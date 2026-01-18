package proxy_test

import (
	"net"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/isaackogan/tls-impersonate-proxy/internal/tests/testutil"
)

func TestProxyStatusNamesWhatFailed(t *testing.T) {
	h := newHarness(t, nil)
	origin, _ := url.Parse(h.upstream.URL)

	resp, _ := h.get(t, h.upstream.URL+"/bad", "X-Tip-Browser", "Safari")
	if resp.StatusCode != 418 || resp.Header.Get("Proxy-Status") != "tip; error=http_request_denied" {
		t.Errorf("418: %d %q", resp.StatusCode, resp.Header.Get("Proxy-Status"))
	}

	hop := testutil.NewHop(t)
	hop.Reply(func(*http.Request) *testutil.HopReply {
		return &testutil.HopReply{Status: 407, Header: http.Header{"Proxy-Status": {"envoy; error=http_request_error"}}, Body: `Auth "failed"` + "\n"}
	})
	resp, _ = h.get(t, h.upstream.URL+"/refused", "X-Tip-Proxy", "http://u:p@"+hop.Addr)
	want := []string{"envoy; error=http_request_error", `tip; error=http_request_error; next-hop="` + hop.Addr + `"; received-status=407; details="Auth \"failed\""`}
	if got := resp.Header.Values("Proxy-Status"); resp.StatusCode != 502 || !slices.Equal(got, want) {
		t.Errorf("refusal: %d %q, want %q", resp.StatusCode, got, want)
	}

	l, _ := net.Listen("tcp", "127.0.0.1:0")
	closed := l.Addr().String()
	l.Close()
	resp, _ = h.get(t, h.upstream.URL+"/closed", "X-Tip-Proxy", "http://"+closed)
	if resp.StatusCode != 502 || resp.Header.Get("Proxy-Status") != `tip; error=connection_refused; next-hop="`+closed+`"` {
		t.Errorf("unreachable hop: %d %q", resp.StatusCode, resp.Header.Get("Proxy-Status"))
	}

	stalled := testutil.NewHop(t)
	stalled.Reply(func(*http.Request) *testutil.HopReply { return &testutil.HopReply{Stall: true} })
	resp, _ = h.get(t, h.upstream.URL+"/stalled", "X-Tip-Proxy", "http://"+stalled.Addr, "X-Tip-Timeout", "300ms")
	if resp.StatusCode != 504 || resp.Header.Get("Proxy-Status") != `tip; error=connection_timeout; next-hop="`+stalled.Addr+`"` || resp.Header.Get("X-Tip-Error") != "timeout: proxy-connect: waiting for "+stalled.Addr {
		t.Errorf("stalled hop: %d %q %q", resp.StatusCode, resp.Header.Get("Proxy-Status"), resp.Header.Get("X-Tip-Error"))
	}

	resp, _ = h.get(t, h.upstream.URL+"/slow", "X-Upstream-Delay", "2s", "X-Tip-Timeout", "300ms")
	if resp.StatusCode != 504 || resp.Header.Get("Proxy-Status") != `tip; error=http_response_timeout; next-hop="`+origin.Hostname()+`"` || resp.Header.Get("X-Tip-Error") != "timeout: waiting for response headers from "+origin.Hostname() {
		t.Errorf("slow origin: %d %q %q", resp.StatusCode, resp.Header.Get("Proxy-Status"), resp.Header.Get("X-Tip-Error"))
	}

	hang, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	var held []net.Conn
	t.Cleanup(func() {
		hang.Close()
		mu.Lock()
		defer mu.Unlock()
		for _, c := range held {
			c.Close()
		}
	})
	go func() {
		for {
			c, err := hang.Accept()
			if err != nil {
				return
			}
			mu.Lock()
			held = append(held, c)
			mu.Unlock()
		}
	}()
	hangHost, _, _ := net.SplitHostPort(hang.Addr().String())
	resp, _ = h.get(t, "https://"+hang.Addr().String()+"/", "X-Tip-Timeout", "300ms")
	if resp.StatusCode != 504 || resp.Header.Get("Proxy-Status") != `tip; error=connection_timeout; next-hop="`+hangHost+`"` || resp.Header.Get("X-Tip-Error") != "timeout: connecting to "+hangHost {
		t.Errorf("tls hang: %d %q %q", resp.StatusCode, resp.Header.Get("Proxy-Status"), resp.Header.Get("X-Tip-Error"))
	}

	resp, _ = h.get(t, h.upstream.URL+"/xtip")
	if resp.StatusCode != 200 || resp.Header.Get("Proxy-Status") != "cdn" {
		t.Errorf("origin Proxy-Status must pass through: %d %q", resp.StatusCode, resp.Header.Get("Proxy-Status"))
	}
	if !strings.Contains(h.logs.String(), `"phase":"proxy-connect"`) {
		t.Errorf("logs lack the phase: %s", h.logs.String())
	}
}
