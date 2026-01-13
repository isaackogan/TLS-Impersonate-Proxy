package impersonate_test

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/isaackogan/tls-impersonate-proxy/internal/impersonate"
	"github.com/isaackogan/tls-impersonate-proxy/internal/tests/testutil"
)

func TestEveryBrowserAndOsBuildsAndClaimsItsPlatform(t *testing.T) {
	up := testutil.NewUpstream(t)
	platforms := map[string]string{"windows": "Windows", "macos": "Macintosh", "linux": "Linux", "android": "Android", "ios": "iP"}
	for _, browser := range []string{"chrome", "firefox"} {
		for os, token := range platforms {
			t.Run(browser+"/"+os, func(t *testing.T) {
				c, err := impersonate.Build(spec(t, "X-Tip-Browser", browser, "X-Tip-Os", os), impersonate.Options{})
				if err != nil {
					t.Fatal(err)
				}
				defer c.Close()
				req, _ := http.NewRequest("GET", up.URL+"/"+browser+"/"+os, nil)
				do(t, c, req)
				ua := up.Last(t).Header.Get("User-Agent")
				if !strings.Contains(ua, token) {
					t.Fatalf("ua %q lacks %q", ua, token)
				}
				if browser == "chrome" && up.Last(t).Header.Get("Sec-Ch-Ua") == "" {
					t.Fatalf("chrome without client hints: %v", up.Last(t).Header)
				}
			})
		}
	}
}

func TestJaPresetAloneKeepsClientHeaders(t *testing.T) {
	up := testutil.NewUpstream(t)
	c, err := impersonate.Build(spec(t, "X-Tip-Ja", "safari"), impersonate.Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	req, _ := http.NewRequest("GET", up.URL+"/ja", nil)
	req.Header.Set("User-Agent", "mine/4.0")
	req.Header.Set("Accept", "text/plain")
	do(t, c, req)
	seen := up.Last(t)
	if seen.Header.Get("User-Agent") != "mine/4.0" || seen.Header.Get("Accept") != "text/plain" {
		t.Fatalf("headers changed without a profile: %v", seen.Header)
	}
}

func TestForceHttpVersions(t *testing.T) {
	up := testutil.NewUpstream(t)
	for version, proto := range map[string]string{"1": "HTTP/1.1", "2": "HTTP/2.0"} {
		c, err := impersonate.Build(spec(t, "X-Tip-Browser", "chrome", "X-Tip-ForceHttp", version), impersonate.Options{})
		if err != nil {
			t.Fatal(err)
		}
		req, _ := http.NewRequest("GET", up.URL+"/force"+version, nil)
		resp := do(t, c, req)
		if resp.Proto != proto {
			t.Errorf("ForceHttp %s: proto %s", version, resp.Proto)
		}
		c.Close()
	}
}

func TestDisableKeepAliveStillServes(t *testing.T) {
	up := testutil.NewUpstream(t)
	c, err := impersonate.Build(spec(t, "X-Tip-Browser", "firefox", "X-Tip-DisableKeepAlive", "true"), impersonate.Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	for range 2 {
		req, _ := http.NewRequest("GET", up.URL+"/ka", nil)
		if resp := do(t, c, req); resp.StatusCode != 200 {
			t.Fatal(resp.Status)
		}
	}
}

func TestKeepOfAbsentHeaderRemovesProfileValue(t *testing.T) {
	up := testutil.NewUpstream(t)
	c, err := impersonate.Build(spec(t, "X-Tip-Browser", "chrome"), impersonate.Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	req, _ := http.NewRequest("GET", up.URL+"/absent", nil)
	req.Header.Add("X-Multi", "one")
	req.Header.Add("X-Multi", "two")
	ctx := impersonate.WithKeep(context.Background(), req.Header.Clone(), []string{"accept-language", "x-multi"})
	do(t, c, req.WithContext(ctx))
	seen := up.Last(t)
	if seen.Header.Get("Accept-Language") != "" {
		t.Fatalf("kept-but-absent header should be absent upstream: %v", seen.Header)
	}
	if got := seen.Header.Values("X-Multi"); len(got) != 2 || got[0] != "one" || got[1] != "two" {
		t.Fatalf("multi-valued header not preserved: %v", got)
	}
}

func TestCaptureFollowsProfileOrder(t *testing.T) {
	up := testutil.NewUpstream(t)
	c, err := impersonate.Build(spec(t, "X-Tip-Browser", "chrome", "X-Tip-Os", "windows"), impersonate.Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	req, _ := http.NewRequest("GET", up.URL+"/order", nil)
	req.Header.Set("Cookie", "a=b")
	capture := &impersonate.Capture{}
	do(t, c, req.WithContext(impersonate.WithCapture(context.Background(), capture)))
	if len(capture.Headers) < 5 || !strings.HasPrefix(capture.Headers[0], "sec-ch-ua:") {
		t.Fatalf("capture order %v", capture.Headers)
	}
	var cookieAt, uaAt int
	for i, line := range capture.Headers {
		switch {
		case strings.HasPrefix(line, "cookie:"):
			cookieAt = i
		case strings.HasPrefix(line, "user-agent:"):
			uaAt = i
		}
	}
	if cookieAt < uaAt {
		t.Fatalf("cookie should follow user-agent in chrome order: %v", capture.Headers)
	}
}

func TestRetiredClientFinishesInFlightThenCloses(t *testing.T) {
	up := testutil.NewUpstream(t)
	obs := &counting{}
	c, _ := newCache(t, 1, time.Hour, obs)
	first, err := c.Get(spec(t, "X-Tip-Browser", "chrome"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Get(spec(t, "X-Tip-Browser", "firefox")); err != nil {
		t.Fatal(err)
	}
	if obs.evictions.Load() != 1 {
		t.Fatalf("evictions %d", obs.evictions.Load())
	}
	req, _ := http.NewRequest("GET", up.URL+"/retired", nil)
	if resp := do(t, first, req); resp.StatusCode != 200 {
		t.Fatal("retired client must still serve its in-flight holder")
	}
	first.Release()
	req, _ = http.NewRequest("GET", up.URL+"/closed", nil)
	if _, err := first.RoundTrip(req); !errors.Is(err, impersonate.ErrClosed) {
		t.Fatalf("released retired client should be closed, got %v", err)
	}
}

func TestSweepSkipsInFlightClients(t *testing.T) {
	obs := &counting{}
	c, _ := newCache(t, 10, time.Minute, obs)
	client, _ := c.Get(spec(t, "X-Tip-Browser", "chrome"))
	if n := c.Sweep(time.Now().Add(time.Hour)); n != 0 {
		t.Fatalf("swept %d in-flight clients", n)
	}
	client.Release()
	if n := c.Sweep(time.Now().Add(time.Hour)); n != 1 {
		t.Fatalf("swept %d after release", n)
	}
}

func TestClassifyTimeout(t *testing.T) {
	up := testutil.NewUpstream(t)
	c, _ := impersonate.Build(spec(t, "X-Tip-Browser", "chrome"), impersonate.Options{})
	defer c.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, "GET", up.URL+"/slow", nil)
	req.Header.Set("X-Upstream-Delay", "1s")
	_, err := c.RoundTrip(req)
	if err == nil {
		t.Fatal("expected timeout")
	}
	if kind := impersonate.Classify(err); kind != "timeout" {
		t.Fatalf("kind %q for %v", kind, err)
	}
}

func TestInferExactProfileUserAgents(t *testing.T) {
	up := testutil.NewUpstream(t)
	for _, browser := range []string{"chrome", "firefox"} {
		for _, os := range []string{"windows", "macos", "linux", "android", "ios"} {
			c, _ := impersonate.Build(spec(t, "X-Tip-Browser", browser, "X-Tip-Os", os), impersonate.Options{})
			req, _ := http.NewRequest("GET", up.URL+"/ua", nil)
			do(t, c, req)
			ua := up.Last(t).Header.Get("User-Agent")
			c.Close()
			if got := impersonate.Infer(ua); got.Browser != browser || got.Os != os {
				t.Errorf("%s/%s: %q inferred as %+v", browser, os, ua, got)
			}
		}
	}
}
