package proxy

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"log/slog"
	"net/http"
	"strings"
	"sync/atomic"
	"time"

	"github.com/elazarl/goproxy"

	"github.com/isaackogan/tls-impersonate-proxy/internal/impersonate"
)

type roundTripper struct {
	server *Server
	client Client
	state  *state
}

func (rt *roundTripper) RoundTrip(req *http.Request, _ *goproxy.ProxyCtx) (*http.Response, error) {
	s, st := rt.server, rt.state
	ctx, cancel := context.WithCancel(req.Context())
	timeout := s.opts.Timeout
	if t := st.directive.Timeout; t > 0 && (timeout == 0 || t < timeout) {
		timeout = t
	}
	var timer *time.Timer
	if timeout > 0 {
		timer = time.AfterFunc(timeout, cancel)
	}
	st.capture = &impersonate.Capture{}
	ctx = impersonate.WithCapture(ctx, st.capture)
	if st.original != nil {
		ctx = impersonate.WithKeep(ctx, st.original, st.directive.Keep)
	}
	req = req.WithContext(ctx)
	if req.Body != nil {
		body := &replayable{ReadCloser: countReads(req.Body, &st.bytesIn)}
		req.Body = body
		req.GetBody = body.replay
	}
	resp, err := rt.client.RoundTrip(req)
	if timer != nil {
		timer.Stop()
	}
	if err != nil {
		cancel()
		rt.client.Release()
		kind := impersonate.Classify(err)
		if kind == "dial" && st.spec.Proxy != "" {
			kind = "proxy"
		}
		s.obs.UpstreamError(st.host, kind)
		s.log.Warn("upstream failed", "host", st.host, "path", st.path, "kind", kind, "error", err.Error())
		resp = badGateway(req, kind, err)
		s.finish(st, resp.StatusCode, 0)
		return resp, nil
	}
	s.logOutbound(st)
	var out atomic.Int64
	resp.Body = countReads(resp.Body, &out)
	if resp.StatusCode != http.StatusSwitchingProtocols {
		negotiate(s.opts.Encoding, st.accept, resp)
	}
	status := resp.StatusCode
	resp.Body = onClose(resp.Body, func() {
		cancel()
		rt.client.Release()
		s.finish(st, status, out.Load())
	})
	return resp, nil
}

func (s *Server) logOutbound(st *state) {
	if !s.log.Enabled(context.Background(), slog.LevelDebug) || st.capture == nil {
		return
	}
	lines := make([]string, len(st.capture.Headers))
	for i, line := range st.capture.Headers {
		name, value, _ := strings.Cut(line, ": ")
		lines[i] = name + ": " + s.opts.Redact(name, value)
	}
	s.log.Debug("outbound request", "method", st.method, "scheme", st.scheme, "host", st.host, "path", st.path, "headers", lines)
}

func (s *Server) finish(st *state, status int, bytesOut int64) {
	defer s.active.Add(-1)
	route := s.obs.Route(st.host, st.path)
	ev := RequestEvent{
		Host:     st.host,
		Method:   st.method,
		Path:     st.path,
		Browser:  st.directive.Browser,
		Route:    route,
		Status:   status,
		Duration: time.Since(st.started),
		BytesIn:  st.bytesIn.Load(),
		BytesOut: bytesOut,
	}
	s.obs.RequestFinished(ev)
	os := ""
	if len(st.directive.Os) > 0 {
		os = st.directive.Os[0]
	}
	s.log.Info("request",
		"method", ev.Method, "scheme", st.scheme, "host", ev.Host, "path", ev.Path, "status", status,
		"duration_ms", ev.Duration.Milliseconds(), "bytes_in", ev.BytesIn, "bytes_out", bytesOut,
		"browser", ev.Browser, "os", os, "route", route, "client_key", shortKey(st.spec.Key()))
}

func shortKey(key string) string {
	sum := sha256.Sum256([]byte(key))
	return hex.EncodeToString(sum[:6])
}
