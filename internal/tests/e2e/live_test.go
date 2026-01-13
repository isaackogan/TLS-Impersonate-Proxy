package e2e_test

import (
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"

	"github.com/isaackogan/tls-impersonate-proxy/internal/tests/testutil"
)

const (
	liveURL       = "https://tls.peet.ws/api/all"
	chromeAkamai  = "1:65536;2:0;4:6291456;6:262144|15663105|0|m,a,s,p"
	firefoxAkamai = "1:65536;2:0;4:131072;5:16384|12517377|0|m,p,a,s"
	firefoxUA     = "Mozilla/5.0 (X11; Linux x86_64; rv:120.0) Gecko/20100101 Firefox/120.0"
)

type fingerprint struct {
	UserAgent   string `json:"user_agent"`
	HTTPVersion string `json:"http_version"`
	TLS         struct {
		JA4     string `json:"ja4"`
		JA3Hash string `json:"ja3_hash"`
	} `json:"tls"`
	HTTP2 struct {
		Akamai string `json:"akamai_fingerprint"`
	} `json:"http2"`
}

func observe(t *testing.T, client *http.Client, headers ...string) fingerprint {
	t.Helper()
	req, _ := http.NewRequest("GET", liveURL, nil)
	for i := 0; i < len(headers); i += 2 {
		req.Header.Set(headers[i], headers[i+1])
	}
	resp, err := client.Do(req)
	if err != nil {
		var netErr net.Error
		if errors.As(err, &netErr) || strings.Contains(err.Error(), "502") {
			t.Skipf("live fingerprint service unreachable: %v", err)
		}
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode == http.StatusBadGateway {
		t.Skipf("live fingerprint service unreachable through tip: %s", resp.Header.Get("X-Tip-Error"))
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status %d: %v %s", resp.StatusCode, resp.Header.Values("X-Tip-Error"), body)
	}
	var fp fingerprint
	if err := json.Unmarshal(body, &fp); err != nil {
		t.Fatalf("decode: %v\n%s", err, body)
	}
	return fp
}

func TestLiveFingerprints(t *testing.T) {
	if testing.Short() {
		t.Skip("live fingerprint checks are skipped in short mode")
	}
	tp := startTip(t)
	resp, err := http.Get(tp.proxyURL + "/ca.pem")
	if err != nil {
		t.Fatal(err)
	}
	pemBytes, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	client := testutil.ProxyClient(t, tp.proxyURL, testutil.PoolFromPEM(t, pemBytes))

	chrome := observe(t, client, "X-Tip-Browser", "Chrome", "X-Tip-Os", "Windows")
	t.Run("chrome profile reaches the wire", func(t *testing.T) {
		if !strings.Contains(chrome.UserAgent, "Chrome/152") || !strings.Contains(chrome.UserAgent, "Windows") {
			t.Errorf("user agent %q", chrome.UserAgent)
		}
		if chrome.HTTPVersion != "h2" {
			t.Errorf("http version %q", chrome.HTTPVersion)
		}
		if chrome.HTTP2.Akamai != chromeAkamai {
			t.Errorf("akamai %q, want %q", chrome.HTTP2.Akamai, chromeAkamai)
		}
		if !strings.HasPrefix(chrome.TLS.JA4, "t13d") || !strings.Contains(chrome.TLS.JA4, "h2_") {
			t.Errorf("ja4 %q", chrome.TLS.JA4)
		}
	})

	firefox := observe(t, client, "X-Tip-Browser", "Firefox", "X-Tip-Os", "Linux")
	t.Run("firefox profile reaches the wire", func(t *testing.T) {
		if !strings.Contains(firefox.UserAgent, "Firefox/148") {
			t.Errorf("user agent %q", firefox.UserAgent)
		}
		if firefox.HTTP2.Akamai != firefoxAkamai {
			t.Errorf("akamai %q, want %q", firefox.HTTP2.Akamai, firefoxAkamai)
		}
		if firefox.TLS.JA4 == chrome.TLS.JA4 || firefox.TLS.JA3Hash == chrome.TLS.JA3Hash {
			t.Errorf("firefox and chrome share a TLS fingerprint: %q", firefox.TLS.JA4)
		}
	})

	plain := observe(t, client)
	t.Run("no directives means no impersonation", func(t *testing.T) {
		if plain.UserAgent != "Go-http-client/1.1" {
			t.Errorf("user agent %q", plain.UserAgent)
		}
		if plain.TLS.JA4 == chrome.TLS.JA4 || plain.TLS.JA4 == firefox.TLS.JA4 {
			t.Errorf("unimpersonated ja4 %q collides with a profile", plain.TLS.JA4)
		}
		if plain.HTTP2.Akamai == chromeAkamai || plain.HTTP2.Akamai == firefoxAkamai {
			t.Errorf("unimpersonated akamai %q collides with a profile", plain.HTTP2.Akamai)
		}
	})

	matched := observe(t, client, "X-Tip-Match", "true", "X-Tip-Keep", "User-Agent", "User-Agent", firefoxUA)
	t.Run("match infers the family and keep preserves the user agent", func(t *testing.T) {
		if matched.UserAgent != firefoxUA {
			t.Errorf("user agent %q", matched.UserAgent)
		}
		if matched.HTTP2.Akamai != firefoxAkamai {
			t.Errorf("akamai %q, want %q", matched.HTTP2.Akamai, firefoxAkamai)
		}
		if matched.TLS.JA4 != firefox.TLS.JA4 {
			t.Errorf("ja4 %q, want firefox's %q", matched.TLS.JA4, firefox.TLS.JA4)
		}
	})

	tuned := observe(t, client, "X-Tip-Browser", "Chrome", "X-Tip-Http2Settings", "HeaderTableSize=4096; EnablePush=0; InitialWindowSize=65535")
	t.Run("http2 settings directive reaches the wire", func(t *testing.T) {
		if !strings.HasPrefix(tuned.HTTP2.Akamai, "1:4096;2:0;4:65535|") || !strings.HasSuffix(tuned.HTTP2.Akamai, "|m,a,s,p") {
			t.Errorf("akamai %q", tuned.HTTP2.Akamai)
		}
		if tuned.TLS.JA4 != chrome.TLS.JA4 {
			t.Errorf("ja4 %q changed although only HTTP/2 settings were overridden", tuned.TLS.JA4)
		}
	})
}
