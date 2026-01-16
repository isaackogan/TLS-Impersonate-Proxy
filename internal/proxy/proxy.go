package proxy

import (
	"context"
	"crypto/subtle"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"math/rand/v2"
	"net/http"
	"sync/atomic"
	"time"

	"github.com/elazarl/goproxy"
	"github.com/elazarl/goproxy/ext/auth"

	"github.com/isaackogan/tls-impersonate-proxy/internal/directive"
	"github.com/isaackogan/tls-impersonate-proxy/internal/impersonate"
)

type Options struct {
	CA            tls.Certificate
	CertCacheSize int
	ClientHttp2   bool
	Auth          Auth
	Encoding      string
	Timeout       time.Duration
	ServeCa       bool
	ServeProfiles bool
	Redact        func(name, value string) string
}

type Auth struct {
	Realm string
	Users map[string]string
}

type Client interface {
	http.RoundTripper
	Release()
}

type Clients interface {
	Get(directive.Spec) (Client, error)
}

type Server struct {
	proxy   *goproxy.ProxyHttpServer
	opts    Options
	policy  directive.Policy
	clients Clients
	obs     Observer
	log     *slog.Logger
	caPEM    []byte
	profiles []byte
	tlsFor   func(host string, ctx *goproxy.ProxyCtx) (*tls.Config, error)
	pick     func(int) int
	active   atomic.Int64
	draining atomic.Bool
}

type goproxyLogger struct{ *slog.Logger }

func (l goproxyLogger) Printf(format string, v ...any) {
	l.Debug("goproxy", "msg", fmt.Sprintf(format, v...))
}

func New(o Options, policy directive.Policy, clients Clients, obs Observer, log *slog.Logger) (*Server, error) {
	if o.Redact == nil {
		o.Redact = func(_, value string) string { return value }
	}
	if obs == nil {
		obs = NopObserver{}
	}
	s := &Server{
		proxy:   goproxy.NewProxyHttpServer(),
		opts:    o,
		policy:  policy,
		clients: clients,
		obs:     obs,
		log:     log,
		caPEM:   pemOf(o.CA),
		tlsFor:  goproxy.TLSConfigFromCA(&o.CA),
		pick:    rand.IntN,
	}
	s.profiles, _ = json.Marshal(impersonate.Profiles())
	p := s.proxy
	p.Logger = goproxyLogger{log}
	p.Verbose = log.Enabled(context.Background(), slog.LevelDebug)
	p.KeepAcceptEncoding = true
	p.AllowHTTP2 = o.ClientHttp2
	p.CertStore = newCertStore(o.CertCacheSize)
	p.NonproxyHandler = http.HandlerFunc(s.nonProxy)
	if len(o.Auth.Users) > 0 {
		p.OnRequest().HandleConnect(auth.BasicConnect(o.Auth.Realm, s.authenticate))
		p.OnRequest().Do(s.plainAuth(auth.Basic(o.Auth.Realm, s.authenticate)))
	}
	p.OnRequest().HandleConnect(goproxy.FuncHttpsHandler(s.onConnect))
	p.OnRequest().DoFunc(s.onRequest)
	return s, nil
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) { s.proxy.ServeHTTP(w, r) }

func (s *Server) Drain(ctx context.Context) error {
	s.draining.Store(true)
	ticker := time.NewTicker(50 * time.Millisecond)
	defer ticker.Stop()
	for s.active.Load() > 0 {
		select {
		case <-ctx.Done():
			return fmt.Errorf("drain: %d requests still active: %w", s.active.Load(), ctx.Err())
		case <-ticker.C:
		}
	}
	return nil
}

func (s *Server) Active() int64 { return s.active.Load() }

func (s *Server) ProfilesHandler() http.Handler {
	etag := `"` + impersonate.Profiles().Revision + `"`
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("ETag", etag)
		w.Header().Set("Cache-Control", "max-age=300")
		if r.Header.Get("If-None-Match") == etag {
			w.WriteHeader(http.StatusNotModified)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write(s.profiles)
	})
}

func (s *Server) CAHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/x-pem-file")
		w.Write(s.caPEM)
	})
}

func (s *Server) authenticate(user, password string) bool {
	expected, ok := s.opts.Auth.Users[user]
	return ok && subtle.ConstantTimeCompare([]byte(expected), []byte(password)) == 1
}

func (s *Server) plainAuth(basic goproxy.ReqHandler) goproxy.ReqHandler {
	return goproxy.FuncReqHandler(func(req *http.Request, ctx *goproxy.ProxyCtx) (*http.Request, *http.Response) {
		if _, inTunnel := ctx.UserData.(*tunnel); inTunnel {
			return req, nil
		}
		return basic.Handle(req, ctx)
	})
}

func (s *Server) onConnect(host string, ctx *goproxy.ProxyCtx) (*goproxy.ConnectAction, string) {
	ctx.UserData = &tunnel{picks: map[string]identity{}}
	s.obs.TunnelOpened()
	return &goproxy.ConnectAction{Action: goproxy.ConnectMitm, TLSConfig: s.tlsFor}, host
}

func (s *Server) nonProxy(w http.ResponseWriter, r *http.Request) {
	switch {
	case r.URL.Path == "/healthz":
		io.WriteString(w, "ok\n")
	case r.URL.Path == "/ca.pem" && s.opts.ServeCa:
		s.CAHandler().ServeHTTP(w, r)
	case r.URL.Path == "/profiles" && s.opts.ServeProfiles:
		s.ProfilesHandler().ServeHTTP(w, r)
	default:
		http.Error(w, "tip is a proxy; configure it as your HTTP proxy", http.StatusBadRequest)
	}
}
