package proxy

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"sync/atomic"
	"time"

	"github.com/elazarl/goproxy"

	"github.com/isaackogan/tls-impersonate-proxy/internal/connect"
	"github.com/isaackogan/tls-impersonate-proxy/internal/directive"
	"github.com/isaackogan/tls-impersonate-proxy/internal/impersonate"
	"github.com/isaackogan/tls-impersonate-proxy/internal/logging"
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
	ctx, memo := connect.WithMemo(ctx)
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
		d := diagnose(err, st, memo)
		s.obs.UpstreamError(st.host, d.kind)
		s.log.Warn("upstream failed", d.attrs(st)...)
		resp = upstreamFailure(req, d, err)
		s.finish(st, resp.StatusCode, 0)
		return resp, nil
	}
	directive.Strip(resp.Header)
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
		Browser:  st.spec.Browser,
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

type diagnosis struct {
	kind      string
	message   string
	phase     connect.Phase
	verdict   *connect.Verdict
	connected bool
	nextHop   string
}

// diagnose names the failure. A hop error is the root cause even when surf wrapped it with a fallback attempt.
// A timeout the transport reported as its own is placed by the hop phase the memo saw under way, else by whether
// a connection to the origin had been obtained. The next hop is the upstream proxy when there is one.
func diagnose(err error, st *state, memo *connect.Memo) diagnosis {
	d := diagnosis{kind: impersonate.Classify(err), message: err.Error(), connected: st.capture.Connected.Load(), nextHop: st.host}
	if st.spec.Proxy != "" {
		if u, err := url.Parse(st.spec.Proxy); err == nil {
			d.nextHop = u.Host
		}
		if d.kind == "dial" {
			d.kind = "proxy"
		}
	}
	var hop *connect.Error
	switch {
	case errors.As(err, &hop):
		d.message, d.phase, d.verdict = hop.Error(), hop.Phase, hop.Verdict
	case d.kind != "timeout":
	case memo.Phase() != "":
		d.phase = memo.Phase()
		d.message = string(d.phase) + ": waiting for " + d.nextHop
	case d.connected:
		d.message = "waiting for response headers from " + st.host
	default:
		d.message = "connecting to " + st.host
	}
	d.message = logging.RedactUserinfo(d.message)
	return d
}

func (d diagnosis) attrs(st *state) []any {
	attrs := []any{"host", st.host, "path", st.path, "kind", d.kind, "error", d.message}
	if d.phase != "" {
		attrs = append(attrs, "phase", string(d.phase))
	}
	if d.verdict != nil {
		attrs = append(attrs, "proxy_status", d.verdict.Status)
	}
	return attrs
}

func shortKey(key string) string {
	sum := sha256.Sum256([]byte(key))
	return hex.EncodeToString(sum[:6])
}
