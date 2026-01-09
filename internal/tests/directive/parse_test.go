package directive_test

import (
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/isaackogan/tls-impersonate-proxy/internal/directive"
)

func headers(kv ...string) http.Header {
	h := http.Header{}
	for i := 0; i < len(kv); i += 2 {
		h.Add(kv[i], kv[i+1])
	}
	return h
}

func mustPolicy(t *testing.T, defaults, deny []string) directive.Policy {
	t.Helper()
	p, err := directive.NewPolicy(defaults, deny)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func TestParseAcceptsEveryShapeCaseInsensitively(t *testing.T) {
	h := headers(
		"x-tip-browser", "CHROME",
		"X-TIP-OS", "IOS, Android",
		"X-Tip-Ja", "chrome120pq",
		"X-Tip-Http2Settings", "HEADERTABLESIZE=65536; EnablePush=0",
		"X-Tip-Http3Settings", "Grease=true; QpackMaxTableCapacity=65536; MaxFieldSectionSize=\"262144\"",
		"X-Tip-ForceHttp", "2",
		"X-Tip-Proxy", "SOCKS5://User:Pass@Proxy.Example:1080",
		"X-Tip-Timeout", "1m30s",
		"X-Tip-Dns", "1.1.1.1:53",
		"X-Tip-DnsOverTls", "cloudflare",
		"X-Tip-InterfaceAddr", "en0",
		"X-Tip-SecureTls", "TRUE",
		"X-Tip-DisableKeepAlive", "1",
		"X-Tip-H2c", "false",
		"X-Tip-Scheme", "HTTPS",
		"X-Tip-Keep", "Accept, Accept-Language",
		"X-Tip-Match", "t",
	)
	d, issues := directive.Parse(h, mustPolicy(t, nil, nil))
	if len(issues) > 0 {
		t.Fatalf("unexpected issues: %v", issues)
	}
	if d.Browser != "chrome" || strings.Join(d.Os, ",") != "ios,android" || d.Ja != "chrome120pq" {
		t.Fatalf("browser/os/ja: %+v", d)
	}
	if d.Http2Settings == nil || *d.Http2Settings.HeaderTableSize != 65536 || *d.Http2Settings.EnablePush != 0 || d.Http2Settings.MaxFrameSize != nil {
		t.Fatalf("http2: %+v", d.Http2Settings)
	}
	if d.Http3Settings == nil || !d.Http3Settings.Grease || *d.Http3Settings.MaxFieldSectionSize != 262144 || strings.Join(d.Http3Settings.Order, ",") != "grease,qpackmaxtablecapacity,maxfieldsectionsize" {
		t.Fatalf("http3: %+v", d.Http3Settings)
	}
	if d.ForceHttp != "2" || d.Proxy != "socks5://User:Pass@proxy.example:1080" || d.Timeout != 90*time.Second {
		t.Fatalf("transport: %+v", d)
	}
	if d.Dns != "1.1.1.1:53" || d.DnsOverTls != "cloudflare" || d.InterfaceAddr != "en0" {
		t.Fatalf("dns/iface: %+v", d)
	}
	if !d.SecureTls || !d.DisableKeepAlive || d.H2c || d.Scheme != "https" || !d.Match {
		t.Fatalf("flags: %+v", d)
	}
	if strings.Join(d.Keep, ",") != "accept,accept-language" {
		t.Fatalf("keep: %v", d.Keep)
	}
}

func TestParseNoDirectivesIsEmpty(t *testing.T) {
	d, issues := directive.Parse(headers("User-Agent", "curl"), mustPolicy(t, nil, nil))
	if len(issues) > 0 || d.Browser != "" || d.Os != nil || d.Http2Settings != nil || d.Timeout != 0 {
		t.Fatalf("got %+v %v", d, issues)
	}
}

func TestParseIssues(t *testing.T) {
	cases := []struct {
		name    string
		h       http.Header
		wantMsg string
	}{
		{"unknown directive", headers("X-Tip-Colour", "red"), "X-Tip-Colour: unknown directive"},
		{"bad browser", headers("X-Tip-Browser", "safari"), "Browser: must be one of Chrome, Firefox"},
		{"bad os item", headers("X-Tip-Os", "ios,amiga"), "Os[1]: must be one of Windows, MacOS, Linux, Android, IOS, Random"},
		{"unknown kv key", headers("X-Tip-Http2Settings", "HeaderTableSize=1; Colour=2"), "Http2Settings: unknown key Colour"},
		{"kv without equals", headers("X-Tip-Http3Settings", "Grease"), "Http3Settings: must be Key=Value pairs"},
		{"kv overflow", headers("X-Tip-Http2Settings", "HeaderTableSize=5000000000"), "Http2Settings.HeaderTableSize: must be an unsigned 32-bit integer"},
		{"kv duplicate", headers("X-Tip-Http2Settings", "EnablePush=0; enablepush=1"), "Http2Settings: EnablePush given more than once"},
		{"bad bool", headers("X-Tip-SecureTls", "yes"), "SecureTls: must be true or false"},
		{"bad duration", headers("X-Tip-Timeout", "soon"), "Timeout: must be a duration"},
		{"bad proxy scheme", headers("X-Tip-Proxy", "ftp://x:1"), "Proxy: must be an absolute URL with scheme"},
		{"bad force", headers("X-Tip-ForceHttp", "4"), "ForceHttp: must be 1, 2 or 3"},
		{"bad scheme", headers("X-Tip-Scheme", "http"), "Scheme: must be one of https"},
		{"bad dot", headers("X-Tip-DnsOverTls", "nowhere"), "DnsOverTls: must be one of"},
		{"scalar twice", headers("X-Tip-Browser", "chrome", "X-Tip-Browser", "firefox"), "Browser: sent more than once"},
		{"empty scalar", headers("X-Tip-Browser", ""), "Browser: must not be empty"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, issues := directive.Parse(tc.h, mustPolicy(t, nil, nil))
			if len(issues) == 0 {
				t.Fatal("expected issues")
			}
			if !strings.Contains(issues.Error(), tc.wantMsg) {
				t.Fatalf("got %q, want substring %q", issues.Error(), tc.wantMsg)
			}
		})
	}
}

func TestParseCollectsMultipleIssues(t *testing.T) {
	_, issues := directive.Parse(headers("X-Tip-Browser", "opera", "X-Tip-Timeout", "later"), mustPolicy(t, nil, nil))
	if len(issues) != 2 {
		t.Fatalf("want 2 issues, got %v", issues)
	}
	h := issues.Headers()
	if h.Get("X-Tip-Error-Count") != "2" || len(h.Values("X-Tip-Error")) != 2 {
		t.Fatalf("headers %v", h)
	}
}

func TestRepeatedListLinesJoin(t *testing.T) {
	d, issues := directive.Parse(headers("X-Tip-Os", "ios", "X-Tip-Os", "android", "X-Tip-Http2Settings", "HeaderTableSize=1", "X-Tip-Http2Settings", "EnablePush=0"), mustPolicy(t, nil, nil))
	if len(issues) > 0 {
		t.Fatal(issues)
	}
	if len(d.Os) != 2 || *d.Http2Settings.EnablePush != 0 || *d.Http2Settings.HeaderTableSize != 1 {
		t.Fatalf("%+v", d)
	}
}

func TestDefaultsAndDeny(t *testing.T) {
	p := mustPolicy(t, []string{"Browser: Firefox", "X-Tip-Os: Random"}, []string{"Proxy"})
	d, issues := directive.Parse(headers("X-Tip-Os", "linux"), p)
	if len(issues) > 0 || d.Browser != "firefox" || strings.Join(d.Os, ",") != "linux" {
		t.Fatalf("%+v %v", d, issues)
	}
	_, issues = directive.Parse(headers("X-Tip-Proxy", "http://p:1"), p)
	if len(issues) != 1 || !strings.Contains(issues.Error(), "Proxy: not permitted by this proxy") {
		t.Fatalf("%v", issues)
	}
}

func TestStrip(t *testing.T) {
	h := headers("X-Tip-Browser", "chrome", "x-tip-keep", "Accept", "Accept", "*/*")
	directive.Strip(h)
	if len(h) != 1 || h.Get("Accept") != "*/*" {
		t.Fatalf("%v", h)
	}
}

func TestNamesMatchShape(t *testing.T) {
	names := directive.Names()
	if len(names) != 17 {
		t.Fatalf("got %d names: %v", len(names), names)
	}
	for _, n := range names {
		if _, issues := directive.Parse(headers("X-Tip-"+strings.ToUpper(n), "x"), mustPolicy(t, nil, nil)); len(issues) > 0 && strings.Contains(issues.Error(), "unknown directive") {
			t.Errorf("%s reported unknown", n)
		}
	}
}
