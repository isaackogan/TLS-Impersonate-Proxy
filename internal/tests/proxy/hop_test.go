package proxy_test

import (
	"encoding/base64"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"

	"github.com/isaackogan/tls-impersonate-proxy/internal/tests/testutil"
)

func TestHopRefusalIsA502CarryingTheVerdict(t *testing.T) {
	h := newHarness(t, nil)
	hop := testutil.NewHop(t)
	hop.Reply(func(*http.Request) *testutil.HopReply {
		return &testutil.HopReply{
			Status: 407,
			Header: http.Header{
				"X-Oxylabs-Error":    {"bad-auth"},
				"Proxy-Authenticate": {`Basic realm="oxy"`},
				"X-Tip-Error":        {"spoofed"},
				"Content-Type":       {"text/plain"},
				"Connection":         {"X-Hop-Private"},
				"X-Hop-Private":      {"secret"},
			},
			Body: "Auth failed: wrong credentials\nsee docs\n",
		}
	})
	resp, _ := h.get(t, h.upstream.URL+"/hop", "X-Tip-Browser", "Chrome", "X-Tip-Proxy", "http://user:pass@"+hop.Addr)
	if resp.StatusCode != 502 {
		t.Fatalf("status %d %v", resp.StatusCode, resp.Header)
	}
	want := map[string]string{
		"X-Tip-Proxy-Status": "407",
		"X-Tip-Proxy-Error":  "Auth failed: wrong credentials",
		"X-Oxylabs-Error":    "bad-auth",
		"Proxy-Authenticate": "",
		"Content-Type":       "",
		"X-Hop-Private":      "",
		"Content-Length":     "0",
	}
	for name, value := range want {
		if got := resp.Header.Get(name); got != value {
			t.Errorf("%s = %q, want %q", name, got, value)
		}
	}
	if errs := resp.Header.Values("X-Tip-Error"); len(errs) != 1 || !strings.HasPrefix(errs[0], "proxy_rejected: CONNECT 407") {
		t.Errorf("X-Tip-Error %v", errs)
	}
	if kind := h.obs.lastUpstreamError(); kind != "proxy_rejected" {
		t.Errorf("kind %q", kind)
	}
	if reqs := hop.Requests(); len(reqs) != 1 || reqs[0].Header.Get("Proxy-Authorization") != "Basic "+base64.StdEncoding.EncodeToString([]byte("user:pass")) {
		t.Errorf("the hop must be asked once, with the credentials: %d requests", len(reqs))
	}
}

func TestHopFailuresNameTheirPhase(t *testing.T) {
	h := newHarness(t, nil)
	l, _ := net.Listen("tcp", "127.0.0.1:0")
	closed := l.Addr().String()
	l.Close()
	resp, _ := h.get(t, h.upstream.URL+"/closed", "X-Tip-Proxy", "http://"+closed)
	if resp.StatusCode != 502 || !strings.HasPrefix(resp.Header.Get("X-Tip-Error"), "proxy: proxy-dial: ") || resp.Header.Get("X-Tip-Proxy-Status") != "" {
		t.Fatalf("status %d headers %v", resp.StatusCode, resp.Header)
	}
	if kind := h.obs.lastUpstreamError(); kind != "proxy" {
		t.Fatalf("kind %q", kind)
	}
	hop := testutil.NewHop(t)
	hop.Reply(func(*http.Request) *testutil.HopReply { return &testutil.HopReply{Stall: true} })
	resp, _ = h.get(t, h.upstream.URL+"/stalled", "X-Tip-Proxy", "http://"+hop.Addr, "X-Tip-Timeout", "300ms")
	if resp.StatusCode != 502 || !strings.HasPrefix(resp.Header.Get("X-Tip-Error"), "timeout: proxy-connect: ") {
		t.Fatalf("status %d headers %v", resp.StatusCode, resp.Header)
	}
	if kind := h.obs.lastUpstreamError(); kind != "timeout" {
		t.Fatalf("kind %q", kind)
	}
}

func TestFailureAfterTheTunnelIsOriginSide(t *testing.T) {
	h := newHarness(t, nil)
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				io.Copy(c, c)
			}()
		}
	}()
	hop := testutil.NewHop(t)
	resp, _ := h.get(t, "https://"+l.Addr().String()+"/", "X-Tip-Browser", "Chrome", "X-Tip-Proxy", "http://"+hop.Addr)
	if resp.StatusCode != 502 || !strings.HasPrefix(resp.Header.Get("X-Tip-Error"), "tls: ") {
		t.Fatalf("status %d headers %v", resp.StatusCode, resp.Header)
	}
	if len(hop.Requests()) == 0 {
		t.Fatal("the hop should have seen the CONNECT")
	}
}

func TestHopServesEveryProtocolPath(t *testing.T) {
	h := newHarness(t, nil)
	hop := testutil.NewHop(t)
	via := "http://" + hop.Addr
	if resp, _ := h.get(t, h.upstream.URL+"/h2", "X-Tip-Browser", "Chrome", "X-Tip-Proxy", via); resp.StatusCode != 200 || h.upstream.Last(t).Proto != "HTTP/2.0" {
		t.Fatalf("h2 through the hop: %d %s", resp.StatusCode, h.upstream.Last(t).Proto)
	}
	h1 := testutil.NewUpstreamHTTP1(t)
	if resp, _ := h.get(t, h1.URL+"/h1", "X-Tip-Browser", "Chrome", "X-Tip-Proxy", via); resp.StatusCode != 200 || h1.Last(t).Proto != "HTTP/1.1" {
		t.Fatalf("http/1.1 fallback through the hop: %d %s", resp.StatusCode, h1.Last(t).Proto)
	}
	if resp, _ := h.get(t, h.upstream.URL+"/plain", "X-Tip-Proxy", via); resp.StatusCode != 200 {
		t.Fatalf("unimpersonated through the hop: %d", resp.StatusCode)
	}
	if n := len(hop.Requests()); n < 3 {
		t.Fatalf("hop saw %d connects", n)
	}
}

func TestOriginXTipHeadersAreStripped(t *testing.T) {
	h := newHarness(t, nil)
	resp, _ := h.get(t, h.upstream.URL+"/xtip")
	if resp.StatusCode != 200 || resp.Header.Get("X-Tip-Error") != "" || resp.Header.Get("X-Tip-Proxy-Status") != "" || resp.Header.Get("X-Origin") != "kept" {
		t.Fatalf("status %d headers %v", resp.StatusCode, resp.Header)
	}
}
