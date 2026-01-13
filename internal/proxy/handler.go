package proxy

import (
	"net"
	"net/http"
	"slices"
	"strings"
	"sync/atomic"
	"time"

	"github.com/elazarl/goproxy"

	"github.com/isaackogan/tls-impersonate-proxy/internal/directive"
	"github.com/isaackogan/tls-impersonate-proxy/internal/impersonate"
)

type tunnel struct {
	picks map[string]string
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
	if d.Match && d.Browser == "" {
		if inferred := impersonate.Infer(req.Header.Get("User-Agent")); inferred.Browser != "" {
			d.Browser = inferred.Browser
			if len(d.Os) == 0 && inferred.Os != "" {
				d.Os = []string{inferred.Os}
			}
		}
	}
	if d.ForceHttp == "" && isWebSocketUpgrade(req.Header) {
		d.ForceHttp = "1"
	}
	st.directive = s.resolve(t, d)
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

func (s *Server) resolve(t *tunnel, d directive.Directive) directive.Directive {
	if len(d.Os) <= 1 && !slices.Contains(d.Os, "random") {
		return d
	}
	key := strings.Join(d.Os, ",")
	if t != nil {
		if os, ok := t.picks[key]; ok {
			d.Os = []string{os}
			return d
		}
	}
	d = d.Resolve(s.pick)
	if t != nil {
		t.picks[key] = d.Os[0]
	}
	return d
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
