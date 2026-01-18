package testutil

import (
	"compress/gzip"
	"compress/zlib"
	"context"
	"crypto/tls"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/andybalholm/brotli"
	"github.com/coder/websocket"
	"github.com/klauspost/compress/zstd"
)

type Recorded struct {
	Method string
	Path   string
	Proto  string
	Header http.Header
	Body   []byte
}

type Upstream struct {
	*httptest.Server
	mu       sync.Mutex
	requests []Recorded
}

func NewUpstream(t testing.TB) *Upstream {
	t.Helper()
	return newUpstream(t, func(*httptest.Server) {})
}

func NewUpstreamHTTP1(t testing.TB) *Upstream {
	t.Helper()
	return newUpstream(t, func(s *httptest.Server) { s.EnableHTTP2 = false })
}

func NewUpstreamTLS12(t testing.TB) *Upstream {
	t.Helper()
	return newUpstream(t, func(s *httptest.Server) { s.TLS = &tls.Config{MaxVersion: tls.VersionTLS12} })
}

func NewUpstreamIPv6(t testing.TB) *Upstream {
	t.Helper()
	ln, err := net.Listen("tcp6", "[::1]:0")
	if err != nil {
		t.Skipf("no IPv6 loopback: %v", err)
	}
	return newUpstream(t, func(s *httptest.Server) { s.Listener.Close(); s.Listener = ln })
}

func newUpstream(t testing.TB, configure func(*httptest.Server)) *Upstream {
	t.Helper()
	u := &Upstream{}
	u.Server = httptest.NewUnstartedServer(http.HandlerFunc(u.serve))
	u.Server.EnableHTTP2 = true
	configure(u.Server)
	u.Server.StartTLS()
	t.Cleanup(u.Server.Close)
	return u
}

func (u *Upstream) serve(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(r.Body)
	u.mu.Lock()
	u.requests = append(u.requests, Recorded{r.Method, r.URL.Path, r.Proto, r.Header.Clone(), body})
	u.mu.Unlock()
	switch {
	case r.URL.Path == "/ws":
		echoWebSocket(w, r)
		return
	case r.URL.Path == "/xtip":
		w.Header().Set("X-Tip-Error", "from-origin")
		w.Header().Set("X-Tip-Proxy-Status", "999")
		w.Header().Set("X-Origin", "kept")
		w.Header().Set("Proxy-Status", "cdn")
	case r.URL.Path == "/redirect":
		http.Redirect(w, r, "https://example.invalid/landing", http.StatusFound)
		return
	case r.URL.Path == "/cookies":
		http.SetCookie(w, &http.Cookie{Name: "a", Value: "1", Path: "/"})
		http.SetCookie(w, &http.Cookie{Name: "b", Value: "2", Path: "/", HttpOnly: true})
		w.WriteHeader(http.StatusOK)
		return
	case r.URL.Path == "/status":
		if code, err := strconv(r.URL.Query().Get("code")); err == nil {
			if r.Header.Get("X-Upstream-Encoding") != "" {
				w.Header().Set("Content-Encoding", r.Header.Get("X-Upstream-Encoding"))
			}
			w.WriteHeader(code)
			return
		}
	case r.URL.Path == "/sse":
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		io.WriteString(w, "data: first\n\n")
		w.(http.Flusher).Flush()
		time.Sleep(400 * time.Millisecond)
		io.WriteString(w, "data: second\n\n")
		return
	case strings.HasPrefix(r.URL.Path, "/large/"):
		n, _ := strconv(strings.TrimPrefix(r.URL.Path, "/large/"))
		w.Header().Set("Content-Type", "application/octet-stream")
		chunk := make([]byte, 64*1024)
		for written := 0; written < n; written += len(chunk) {
			if remaining := n - written; remaining < len(chunk) {
				chunk = chunk[:remaining]
			}
			w.Write(chunk)
		}
		return
	}
	if d, err := time.ParseDuration(r.Header.Get("X-Upstream-Delay")); err == nil {
		time.Sleep(d)
	}
	payload, _ := json.Marshal(map[string]any{"proto": r.Proto, "headers": r.Header, "path": r.URL.Path, "body": string(body)})
	w.Header().Set("Content-Type", "application/json")
	if encoding := r.Header.Get("X-Upstream-Encoding"); encoding != "" {
		writeEncoded(w, encoding, payload)
		return
	}
	if d, err := time.ParseDuration(r.Header.Get("X-Upstream-Body-Delay")); err == nil {
		w.WriteHeader(http.StatusOK)
		w.(http.Flusher).Flush()
		time.Sleep(d)
	}
	w.Write(payload)
}

func writeEncoded(w http.ResponseWriter, encoding string, payload []byte) {
	switch encoding {
	case "gzip":
		w.Header().Set("Content-Encoding", "gzip")
		zw := gzip.NewWriter(w)
		zw.Write(payload)
		zw.Close()
	case "deflate":
		w.Header().Set("Content-Encoding", "deflate")
		zw := zlib.NewWriter(w)
		zw.Write(payload)
		zw.Close()
	case "br":
		w.Header().Set("Content-Encoding", "br")
		bw := brotli.NewWriter(w)
		bw.Write(payload)
		bw.Close()
	case "zstd":
		w.Header().Set("Content-Encoding", "zstd")
		zw, _ := zstd.NewWriter(w)
		zw.Write(payload)
		zw.Close()
	case "bogus-gzip":
		w.Header().Set("Content-Encoding", "gzip")
		w.Write(payload)
	case "multi":
		w.Header().Set("Content-Encoding", "gzip, br")
		w.Write(payload)
	default:
		w.Write(payload)
	}
}

func strconv(s string) (int, error) {
	n := 0
	if s == "" {
		return 0, io.ErrUnexpectedEOF
	}
	for _, c := range s {
		if c < '0' || c > '9' {
			return 0, io.ErrUnexpectedEOF
		}
		n = n*10 + int(c-'0')
	}
	return n, nil
}

func echoWebSocket(w http.ResponseWriter, r *http.Request) {
	conn, err := websocket.Accept(w, r, &websocket.AcceptOptions{InsecureSkipVerify: true})
	if err != nil {
		return
	}
	defer conn.CloseNow()
	ctx := context.Background()
	for {
		kind, data, err := conn.Read(ctx)
		if err != nil {
			return
		}
		if err := conn.Write(ctx, kind, data); err != nil {
			return
		}
	}
}

func (u *Upstream) Requests() []Recorded {
	u.mu.Lock()
	defer u.mu.Unlock()
	return append([]Recorded(nil), u.requests...)
}

func (u *Upstream) Last(t testing.TB) Recorded {
	t.Helper()
	rs := u.Requests()
	if len(rs) == 0 {
		t.Fatal("upstream saw no requests")
	}
	return rs[len(rs)-1]
}
