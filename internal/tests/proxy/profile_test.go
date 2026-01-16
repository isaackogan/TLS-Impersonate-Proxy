package proxy_test

import (
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/isaackogan/tls-impersonate-proxy/internal/impersonate"
	"github.com/isaackogan/tls-impersonate-proxy/internal/proxy"
)

func TestProfilesEndpoint(t *testing.T) {
	h := newHarness(t, nil)
	resp, err := http.Get(h.proxy.URL + "/profiles")
	if err != nil || resp.StatusCode != 200 || resp.Header.Get("Content-Type") != "application/json" {
		t.Fatalf("resp %v err %v", resp, err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	var c impersonate.Catalogue
	if err := json.Unmarshal(body, &c); err != nil || len(c.Profiles) != 14 || c.Revision == "" {
		t.Fatalf("catalogue %v err %v", string(body), err)
	}
	if etag := resp.Header.Get("ETag"); etag != `"`+c.Revision+`"` {
		t.Fatalf("etag %q", etag)
	}
	req, _ := http.NewRequest("GET", h.proxy.URL+"/profiles", nil)
	req.Header.Set("If-None-Match", resp.Header.Get("ETag"))
	resp, _ = http.DefaultClient.Do(req)
	if resp.StatusCode != 304 {
		t.Fatalf("status %d", resp.StatusCode)
	}
	off := newHarness(t, func(o *proxy.Options) { o.ServeProfiles = false })
	resp, _ = http.Get(off.proxy.URL + "/profiles")
	if resp.StatusCode != 400 {
		t.Fatalf("disabled endpoint status %d", resp.StatusCode)
	}
}

func TestProfileDirectiveResolvesToItsIdentity(t *testing.T) {
	h := newHarness(t, nil)
	for _, p := range impersonate.Profiles().Profiles {
		if p.Fidelity != "high" {
			continue
		}
		resp, echoed := h.get(t, h.upstream.URL+"/profile", "X-Tip-Profile", p.ID)
		if resp.StatusCode != 200 {
			t.Fatalf("%s: status %d %v", p.ID, resp.StatusCode, resp.Header)
		}
		if ua := echoedHeader(echoed, "User-Agent"); ua != p.UserAgent {
			t.Fatalf("%s/%s: ua %q, want %q", p.Browser, p.Os, ua, p.UserAgent)
		}
		if p.SecChUa != "" && echoedHeader(echoed, "Sec-Ch-Ua") != p.SecChUa {
			t.Fatalf("%s/%s: sec-ch-ua %q", p.Browser, p.Os, echoedHeader(echoed, "Sec-Ch-Ua"))
		}
	}
	if ev := h.obs.last(t); ev.Browser == "" {
		t.Fatalf("event should carry the resolved browser: %+v", ev)
	}
}

func TestUnknownProfileIsATeapotWithRevision(t *testing.T) {
	h := newHarness(t, nil)
	resp, _ := h.get(t, h.upstream.URL+"/unknown", "X-Tip-Profile", "000000000000")
	if resp.StatusCode != 418 || !strings.Contains(resp.Header.Get("X-Tip-Error"), "Profile: unknown, fetch /profiles again") {
		t.Fatalf("status %d headers %v", resp.StatusCode, resp.Header)
	}
	if resp.Header.Get("X-Tip-Profiles-Revision") != impersonate.Profiles().Revision {
		t.Fatalf("revision header %q", resp.Header.Get("X-Tip-Profiles-Revision"))
	}
	if len(h.upstream.Requests()) != 0 {
		t.Fatal("unknown profile must not reach upstream")
	}
	resp, _ = h.get(t, h.upstream.URL+"/conflict", "X-Tip-Profile", impersonate.Profiles().Profiles[0].ID, "X-Tip-Browser", "Chrome")
	if resp.StatusCode != 418 || !strings.Contains(resp.Header.Get("X-Tip-Error"), "cannot be combined") {
		t.Fatalf("status %d headers %v", resp.StatusCode, resp.Header)
	}
}

func TestRandomBrowserIsStickyPerTunnel(t *testing.T) {
	h := newHarness(t, nil)
	transport := h.client.Transport.(*http.Transport)
	transport.MaxConnsPerHost = 1
	transport.MaxIdleConnsPerHost = 1
	seen := map[string]bool{}
	for range 6 {
		_, echoed := h.get(t, h.upstream.URL+"/random-browser", "X-Tip-Browser", "Random", "X-Tip-Os", "Windows")
		seen[echoedHeader(echoed, "User-Agent")] = true
	}
	if len(seen) != 1 {
		t.Fatalf("one tunnel should keep one browser, saw %d user agents", len(seen))
	}
	families := map[string]bool{}
	for range 24 {
		transport.CloseIdleConnections()
		_, echoed := h.get(t, h.upstream.URL+"/random-browser", "X-Tip-Browser", "Random", "X-Tip-Os", "IOS")
		ua := echoedHeader(echoed, "User-Agent")
		switch {
		case strings.Contains(ua, "Edg"):
			t.Fatalf("random browser on ios must never be edge: %q", ua)
		case strings.Contains(ua, "CriOS/"):
			families["chrome"] = true
		case strings.Contains(ua, "FxiOS/"):
			families["firefox"] = true
		default:
			t.Fatalf("unexpected user agent %q", ua)
		}
	}
	if len(families) != 2 {
		t.Fatalf("random browser should reach both ios families across tunnels, saw %v", families)
	}
	resp, _ := h.get(t, h.upstream.URL+"/edge-ios", "X-Tip-Browser", "Edge", "X-Tip-Os", "IOS")
	if resp.StatusCode != 418 || !strings.Contains(resp.Header.Get("X-Tip-Error"), "Os: ios is not available for edge") {
		t.Fatalf("status %d headers %v", resp.StatusCode, resp.Header)
	}
}
