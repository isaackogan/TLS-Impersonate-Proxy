package proxy_test

import (
	"net"
	"net/http"
	"strings"
	"testing"

	"github.com/isaackogan/tls-impersonate-proxy/internal/tests/testutil"
)

func TestCredentialsNeverLeaveTip(t *testing.T) {
	h := newHarness(t, nil)

	resp, _ := h.get(t, h.upstream.URL+"/socks", "X-Tip-Proxy", "socks5://alice-user@127.0.0.1:1")
	if resp.StatusCode != 418 || !strings.Contains(resp.Header.Get("X-Tip-Error"), "password is empty") || strings.Contains(resp.Header.Get("X-Tip-Error"), "alice-user") {
		t.Errorf("socks build failure: %d %q", resp.StatusCode, resp.Header.Get("X-Tip-Error"))
	}

	hop := testutil.NewHop(t)
	hop.Reply(func(*http.Request) *testutil.HopReply {
		return &testutil.HopReply{Status: 407, Body: "bad credentials for http://alice-user:s3cret-pass@proxy.example:8080\n"}
	})
	resp, _ = h.get(t, h.upstream.URL+"/echo", "X-Tip-Proxy", "http://alice-user:s3cret-pass@"+hop.Addr)
	if resp.StatusCode != 502 || resp.Header.Get("X-Tip-Proxy-Error") != "bad credentials for http://***@proxy.example:8080" {
		t.Errorf("hop body: %d %q", resp.StatusCode, resp.Header.Get("X-Tip-Proxy-Error"))
	}
	if ps := resp.Header.Get("Proxy-Status"); strings.Contains(ps, "s3cret-pass") || !strings.Contains(ps, `next-hop="`+hop.Addr+`"`) {
		t.Errorf("proxy-status: %q", ps)
	}

	l, _ := net.Listen("tcp", "127.0.0.1:0")
	closed := l.Addr().String()
	l.Close()
	resp, _ = h.get(t, h.upstream.URL+"/socks-down", "X-Tip-Proxy", "socks5://alice-user:s3cret-pass@"+closed)
	if resp.StatusCode != 502 || !strings.HasPrefix(resp.Header.Get("X-Tip-Error"), "proxy: ") {
		t.Errorf("socks dial failure: %d %q", resp.StatusCode, resp.Header.Get("X-Tip-Error"))
	}

	for _, resp := range []*http.Response{resp} {
		for name, values := range resp.Header {
			if strings.Contains(strings.Join(values, " "), "s3cret-pass") {
				t.Errorf("%s leaks the password: %v", name, values)
			}
		}
	}
	if logs := h.logs.String(); strings.Contains(logs, "s3cret-pass") || strings.Contains(logs, "alice-user") {
		t.Errorf("logs leak credentials: %s", logs)
	}
}
