package proxy_test

import (
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/isaackogan/tls-impersonate-proxy/internal/proxy"
	"github.com/isaackogan/tls-impersonate-proxy/internal/tests/testutil"
)

func TestUpstreamProxyDirectiveRoutesEgress(t *testing.T) {
	h := newHarness(t, nil)
	egress := testutil.NewUpstreamProxy(t)
	resp, echoed := h.get(t, h.upstream.URL+"/via", "X-Tip-Browser", "Chrome", "X-Tip-Proxy", egress.URL)
	if resp.StatusCode != 200 || echoed["path"] != "/via" {
		t.Fatalf("status %d body %v", resp.StatusCode, echoed)
	}
	connects := egress.Connects()
	if len(connects) != 1 || !strings.HasSuffix(connects[0], strings.TrimPrefix(h.upstream.URL, "https://")) {
		t.Fatalf("upstream proxy saw connects %v", connects)
	}
	if ua := echoedHeader(echoed, "User-Agent"); !strings.Contains(ua, "Chrome/152") {
		t.Fatalf("profile lost through the upstream proxy: %q", ua)
	}
}

func TestDeadUpstreamProxyIsAProxyError(t *testing.T) {
	h := newHarness(t, nil)
	resp, _ := h.get(t, h.upstream.URL+"/via-dead", "X-Tip-Browser", "Chrome", "X-Tip-Proxy", "http://127.0.0.1:1")
	if resp.StatusCode != 502 || !strings.HasPrefix(resp.Header.Get("X-Tip-Error"), "proxy:") {
		t.Fatalf("status %d headers %v", resp.StatusCode, resp.Header)
	}
}

func TestRedirectsAreReturnedNotFollowed(t *testing.T) {
	h := newHarness(t, nil)
	resp, _ := h.get(t, h.upstream.URL+"/redirect", "X-Tip-Browser", "Chrome")
	if resp.StatusCode != 302 || resp.Header.Get("Location") != "https://example.invalid/landing" {
		t.Fatalf("status %d location %q", resp.StatusCode, resp.Header.Get("Location"))
	}
	if n := len(h.upstream.Requests()); n != 1 {
		t.Fatalf("redirect must not be followed by tip, upstream saw %d requests", n)
	}
}

func TestSetCookieHeadersArriveSeparately(t *testing.T) {
	h := newHarness(t, nil)
	resp, _ := h.get(t, h.upstream.URL+"/cookies", "X-Tip-Browser", "Firefox")
	cookies := resp.Header.Values("Set-Cookie")
	if len(cookies) != 2 || !strings.HasPrefix(cookies[0], "a=1") || !strings.Contains(cookies[1], "HttpOnly") {
		t.Fatalf("set-cookie %v", cookies)
	}
}

func TestEveryDecoder(t *testing.T) {
	for _, encoding := range []string{"gzip", "deflate", "br", "zstd"} {
		t.Run(encoding, func(t *testing.T) {
			h := newHarness(t, nil)
			req, _ := http.NewRequest("GET", h.upstream.URL+"/dec", nil)
			req.Header.Set("X-Tip-Browser", "Chrome")
			req.Header.Set("Accept-Encoding", "identity")
			req.Header.Set("X-Upstream-Encoding", encoding)
			resp, err := h.client.Do(req)
			if err != nil {
				t.Fatal(err)
			}
			body, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			if resp.Header.Get("Content-Encoding") != "" || !json.Valid(body) {
				t.Fatalf("%s: encoding %q body %q", encoding, resp.Header.Get("Content-Encoding"), body)
			}
		})
	}
}

func TestUndecodableBodiesPassThrough(t *testing.T) {
	for _, encoding := range []string{"bogus-gzip", "multi"} {
		t.Run(encoding, func(t *testing.T) {
			h := newHarness(t, nil)
			req, _ := http.NewRequest("GET", h.upstream.URL+"/raw", nil)
			req.Header.Set("X-Tip-Browser", "Chrome")
			req.Header.Set("Accept-Encoding", "identity")
			req.Header.Set("X-Upstream-Encoding", encoding)
			resp, err := h.client.Do(req)
			if err != nil {
				t.Fatal(err)
			}
			body, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			if resp.StatusCode != 200 || resp.Header.Get("Content-Encoding") == "" || !json.Valid(body) {
				t.Fatalf("%s: status %d encoding %q body %q", encoding, resp.StatusCode, resp.Header.Get("Content-Encoding"), body)
			}
		})
	}
}

func TestWrongCredentials(t *testing.T) {
	h := newHarness(t, func(o *proxy.Options) { o.Auth = proxy.Auth{Realm: "tip", Users: map[string]string{"alice": "secret"}} })
	pool := h.client.Transport.(*http.Transport).TLSClientConfig.RootCAs
	for _, creds := range []string{"alice:wrong", "mallory:secret"} {
		client := testutil.ProxyClient(t, strings.Replace(h.proxy.URL, "http://", "http://"+creds+"@", 1), pool)
		req, _ := http.NewRequest("GET", h.upstream.URL+"/auth", nil)
		if _, err := client.Do(req); err == nil || !strings.Contains(err.Error(), "Proxy Authentication Required") {
			t.Fatalf("%s: err %v", creds, err)
		}
		plain := "http" + strings.TrimPrefix(h.upstream.URL, "https")
		req, _ = http.NewRequest("GET", plain+"/auth", nil)
		req.Header.Set("X-Tip-Scheme", "https")
		resp, err := client.Do(req)
		if err != nil || resp.StatusCode != 407 {
			t.Fatalf("%s: plain status %v err %v", creds, resp, err)
		}
	}
	if n := len(h.upstream.Requests()); n != 0 {
		t.Fatalf("upstream must not see unauthenticated requests, saw %d", n)
	}
	good := testutil.ProxyClient(t, strings.Replace(h.proxy.URL, "http://", "http://alice:secret@", 1), pool)
	plain := "http" + strings.TrimPrefix(h.upstream.URL, "https")
	req, _ := http.NewRequest("GET", plain+"/plainauth", nil)
	req.Header.Set("X-Tip-Scheme", "https")
	resp, err := good.Do(req)
	if err != nil || resp.StatusCode != 200 {
		t.Fatalf("status %v err %v", resp, err)
	}
	resp.Body.Close()
	if got := h.upstream.Last(t).Header.Get("Proxy-Authorization"); got != "" {
		t.Fatalf("plain path leaked credentials upstream: %q", got)
	}
}
