package impersonate_test

import (
	"context"
	"net/http"
	"slices"
	"strings"
	"testing"

	"github.com/isaackogan/tls-impersonate-proxy/internal/directive"
	"github.com/isaackogan/tls-impersonate-proxy/internal/impersonate"
	"github.com/isaackogan/tls-impersonate-proxy/internal/tests/testutil"
)

func spec(t *testing.T, kv ...string) directive.Spec {
	t.Helper()
	h := http.Header{}
	for i := 0; i < len(kv); i += 2 {
		h.Add(kv[i], kv[i+1])
	}
	p, _ := directive.NewPolicy(nil, nil)
	d, issues := directive.Parse(h, p)
	if len(issues) > 0 {
		t.Fatal(issues)
	}
	r, _ := d.Resolve(directive.ConcreteOs(), func(int) int { return 0 })
	return r.Spec()
}

func do(t *testing.T, c *impersonate.Client, req *http.Request) *http.Response {
	t.Helper()
	resp, err := c.RoundTrip(req)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { resp.Body.Close() })
	return resp
}

func TestImpersonationOwnsHeadersAndUsesHTTP2(t *testing.T) {
	up := testutil.NewUpstream(t)
	c, err := impersonate.Build(spec(t, "X-Tip-Browser", "chrome", "X-Tip-Os", "macos"), impersonate.Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	req, _ := http.NewRequest("GET", up.URL+"/p", nil)
	req.Header.Set("User-Agent", "mine/1.0")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Cookie", "a=b")
	resp := do(t, c, req)
	if resp.Proto != "HTTP/2.0" {
		t.Fatalf("proto %s", resp.Proto)
	}
	seen := up.Last(t)
	if !strings.Contains(seen.Header.Get("User-Agent"), "Chrome/152") || !strings.Contains(seen.Header.Get("User-Agent"), "Macintosh") {
		t.Fatalf("ua %q", seen.Header.Get("User-Agent"))
	}
	if seen.Header.Get("Accept") == "application/json" || seen.Header.Get("Cookie") != "a=b" {
		t.Fatalf("headers %v", seen.Header)
	}
	if seen.Header.Get("Accept-Encoding") != "gzip, deflate, br, zstd" {
		t.Fatalf("accept-encoding %q", seen.Header.Get("Accept-Encoding"))
	}
}

func TestKeepRestoresClientValuesAndCaptureLists(t *testing.T) {
	up := testutil.NewUpstream(t)
	c, err := impersonate.Build(spec(t, "X-Tip-Browser", "firefox"), impersonate.Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	req, _ := http.NewRequest("GET", up.URL+"/k", nil)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "mine/2.0")
	capture := &impersonate.Capture{}
	ctx := impersonate.WithCapture(impersonate.WithKeep(context.Background(), req.Header.Clone(), []string{"accept", "user-agent"}), capture)
	do(t, c, req.WithContext(ctx))
	seen := up.Last(t)
	if seen.Header.Get("Accept") != "application/json" || seen.Header.Get("User-Agent") != "mine/2.0" {
		t.Fatalf("keep failed: %v", seen.Header)
	}
	if !slices.Contains(capture.Headers, "user-agent: mine/2.0") {
		t.Fatalf("capture %v", capture.Headers)
	}
	if len(capture.Headers) == 0 || strings.HasPrefix(capture.Headers[0], ":") {
		t.Fatalf("capture should list real headers in order: %v", capture.Headers)
	}
}

func TestNoBrowserMeansNoImpersonation(t *testing.T) {
	up := testutil.NewUpstream(t)
	c, err := impersonate.Build(spec(t), impersonate.Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	req, _ := http.NewRequest("GET", up.URL+"/plain", nil)
	req.Header.Set("User-Agent", "mine/3.0")
	do(t, c, req)
	if ua := up.Last(t).Header.Get("User-Agent"); ua != "mine/3.0" {
		t.Fatalf("ua %q", ua)
	}
}

func TestBuildRejectsBadProxyDialer(t *testing.T) {
	if _, err := impersonate.Build(spec(t, "X-Tip-Proxy", "socks5://user@host:1"), impersonate.Options{}); err == nil {
		t.Fatal("expected password-less socks5 URL to fail at build")
	}
}

func TestJaPresetsMatchDirective(t *testing.T) {
	want := directive.JaPresets()
	got := impersonate.JaPresets()
	slices.Sort(want)
	slices.Sort(got)
	if !slices.Equal(want, got) {
		t.Fatalf("presets differ:\n%v\n%v", want, got)
	}
}

func TestClassify(t *testing.T) {
	up := testutil.NewUpstream(t)
	up.Close()
	c, _ := impersonate.Build(spec(t, "X-Tip-Browser", "chrome"), impersonate.Options{})
	defer c.Close()
	req, _ := http.NewRequest("GET", up.URL, nil)
	_, err := c.RoundTrip(req)
	if err == nil {
		t.Fatal("expected error")
	}
	if kind := impersonate.Classify(err); kind != "dial" {
		t.Fatalf("kind %q for %v", kind, err)
	}
}
