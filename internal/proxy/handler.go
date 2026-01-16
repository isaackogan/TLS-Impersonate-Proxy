package proxy

import (
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/elazarl/goproxy"

	"github.com/isaackogan/tls-impersonate-proxy/internal/directive"
	"github.com/isaackogan/tls-impersonate-proxy/internal/impersonate"
)

type identity struct{ browser, os []string }

type tunnel struct {
	mu    sync.Mutex
	picks map[string]identity
}

func (t *tunnel) pick(key string) (identity, bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	id, ok := t.picks[key]
	return id, ok
}

func (t *tunnel) remember(key string, id identity) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.picks[key] = id
}

type state struct {
	started   time.Time
	tunnel    *tunnel
	directive directive.Directive
	spec      directive.Spec
	accept    []string
	original  http.Header
	capture   *impersonate.Capture
	bytesIn   atomic.Int64
	method    string
	host      string
	path      string
	scheme    string
}

func (s *Server) onRequest(req *http.Request, ctx *goproxy.ProxyCtx) (*http.Request, *http.Response) {
	if s.draining.Load() {
		return req, unavailable(req)
	}
	s.active.Add(1)
	t, _ := ctx.UserData.(*tunnel)
	st := &state{started: time.Now(), tunnel: t, method: req.Method, host: req.URL.Hostname(), path: req.URL.Path, scheme: req.URL.Scheme}
	ctx.UserData = st
	s.obs.RequestStarted()
	d, issues := directive.Parse(req.Header, s.policy)
	if len(issues) > 0 {
		for _, issue := range issues {
			s.obs.ValidationFailed(strings.SplitN(issue.Path, ".", 2)[0])
		}
		s.finish(st, http.StatusTeapot, 0)
		return req, teapot(req, issues)
	}
	if d.Profile != "" {
		p, ok := impersonate.Lookup(d.Profile)
		if !ok {
			s.obs.ValidationFailed("Profile")
			s.finish(st, http.StatusTeapot, 0)
			resp := teapot(req, directive.Issues{{Path: "Profile", Message: "unknown, fetch /profiles again"}})
			resp.Header.Set("X-Tip-Profiles-Revision", impersonate.Profiles().Revision)
			return req, resp
		}
		d.Browser, d.Os = []string{p.Family()}, []string{p.Platform()}
	}
	if d.Match && !d.FromRequest("browser") {
		if inferred := impersonate.Infer(req.Header.Get("User-Agent")); inferred.Browser != "" {
			d.Browser = []string{inferred.Browser}
			if inferred.Os != "" && !d.FromRequest("os") {
				d.Os = []string{inferred.Os}
			}
		}
	}
	if d.ForceHttp == "" && isWebSocketUpgrade(req.Header) {
		d.ForceHttp = "1"
	}
	resolved, ok := s.resolve(t, d)
	if !ok {
		s.obs.ValidationFailed("Os")
		s.finish(st, http.StatusTeapot, 0)
		return req, teapot(req, directive.Issues{{Path: "Os", Message: fmt.Sprintf("%s is not available for %s", strings.Join(d.Os, ","), strings.Join(d.Browser, ","))}})
	}
	st.directive = resolved
	st.spec = st.directive.Spec()
	st.accept = acceptEncodings(req.Header.Values("Accept-Encoding"))
	if len(d.Keep) > 0 {
		st.original = req.Header.Clone()
	}
	directive.Strip(req.Header)
	if d.Scheme == "https" {
		upgrade(req)
		st.scheme = "https"
	}
	client, err := s.clients.Get(st.spec)
	if err != nil {
		s.obs.ValidationFailed("Build")
		s.finish(st, http.StatusTeapot, 0)
		return req, teapot(req, directive.Issues{{Message: err.Error()}})
	}
	ctx.RoundTripper = &roundTripper{server: s, client: client, state: st}
	return req, nil
}

func (s *Server) resolve(t *tunnel, d directive.Directive) (directive.Directive, bool) {
	key := strings.Join(d.Browser, ",") + ":" + strings.Join(d.Os, ",")
	if t != nil {
		if id, ok := t.pick(key); ok {
			d.Browser, d.Os = id.browser, id.os
			return d, true
		}
	}
	resolved, ok := d.Resolve(impersonate.Families(), impersonate.OSes, s.pick)
	if !ok {
		return d, false
	}
	if t != nil && len(resolved.Browser) > 0 {
		t.remember(key, identity{resolved.Browser, resolved.Os})
	}
	return resolved, true
}

func isWebSocketUpgrade(h http.Header) bool {
	return strings.EqualFold(h.Get("Upgrade"), "websocket")
}

func upgrade(req *http.Request) {
	req.URL.Scheme = "https"
	if req.URL.Port() == "80" {
		host := req.URL.Hostname()
		if strings.Contains(host, ":") {
			host = "[" + host + "]"
		}
		req.URL.Host = host
		if h, p, err := net.SplitHostPort(req.Host); err == nil && p == "80" {
			req.Host = h
		}
	}
}
