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

func TestFamiliesAndOses(t *testing.T) {
	if got := impersonate.Families(); !slices.Equal(got, []string{"chrome", "edge", "firefox"}) {
		t.Fatalf("families %v", got)
	}
	if got := impersonate.OSes("edge"); slices.Contains(got, "ios") || len(got) != 4 {
		t.Fatalf("edge oses %v", got)
	}
	if got := impersonate.OSes("chrome"); len(got) != 5 {
		t.Fatalf("chrome oses %v", got)
	}
	want := directive.Browsers()
	for i := range want {
		want[i] = strings.ToLower(want[i])
	}
	slices.Sort(want)
	if got := impersonate.Families(); !slices.Equal(got, want) {
		t.Fatalf("directive browsers %v differ from families %v", want, got)
	}
}

func TestEdgeProfileIsChromeWithEdgeIdentity(t *testing.T) {
	up := testutil.NewUpstream(t)
	suffix := map[string]string{"windows": " Edg/152.0.0.0", "macos": " Edg/152.0.0.0", "linux": " Edg/152.0.0.0", "android": " EdgA/152.0.0.0"}
	for os, want := range suffix {
		t.Run(os, func(t *testing.T) {
			c, err := impersonate.Build(spec(t, "X-Tip-Browser", "Edge", "X-Tip-Os", os), impersonate.Options{})
			if err != nil {
				t.Fatal(err)
			}
			defer c.Close()
			req, _ := http.NewRequest("GET", up.URL+"/edge/"+os, nil)
			capture := &impersonate.Capture{}
			do(t, c, req.WithContext(impersonate.WithCapture(context.Background(), capture)))
			seen := up.Last(t)
			ua := seen.Header.Get("User-Agent")
			if !strings.HasSuffix(ua, want) || !strings.Contains(ua, "Chrome/152.0.0.0") {
				t.Fatalf("ua %q", ua)
			}
			brands := seen.Header.Get("Sec-Ch-Ua")
			if !strings.Contains(brands, `"Microsoft Edge";v="152"`) || strings.Contains(brands, "Google Chrome") || !strings.Contains(brands, `"Chromium";v="152"`) {
				t.Fatalf("sec-ch-ua %q", brands)
			}
			if !strings.HasPrefix(capture.Headers[0], "sec-ch-ua:") {
				t.Fatalf("header order should be chrome's: %v", capture.Headers)
			}
			expected, _ := impersonate.UserAgent("edge", os)
			if ua != expected {
				t.Fatalf("registry ua %q differs from wire %q", expected, ua)
			}
		})
	}
}

func TestEdgeIsNotAvailableOnIOS(t *testing.T) {
	if _, err := impersonate.Build(directive.Spec{Browser: "edge", Os: "ios"}, impersonate.Options{}); err == nil || !strings.Contains(err.Error(), "not available") {
		t.Fatalf("err %v", err)
	}
	if _, ok := impersonate.UserAgent("edge", "ios"); ok {
		t.Fatal("registry must not claim edge on ios")
	}
}

func TestInferRecognisesEdge(t *testing.T) {
	cases := []struct {
		ua          string
		browser, os string
	}{
		{"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36 Edg/131.0.0.0", "edge", "windows"},
		{"Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Mobile Safari/537.36 EdgA/131.0.0.0", "edge", "android"},
		{"Mozilla/5.0 (iPhone; CPU iPhone OS 17_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 EdgiOS/125.0.2535.60 Mobile/15E148 Safari/605.1.15", "chrome", "ios"},
		{"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36 OPR/116.0.0.0", "chrome", "windows"},
	}
	for _, tc := range cases {
		if got := impersonate.Infer(tc.ua); got.Browser != tc.browser || got.Os != tc.os {
			t.Errorf("%q: got %+v, want %s/%s", tc.ua, got, tc.browser, tc.os)
		}
	}
	for _, os := range impersonate.OSes("edge") {
		ua, _ := impersonate.UserAgent("edge", os)
		if got := impersonate.Infer(ua); got.Browser != "edge" || got.Os != os {
			t.Errorf("exact edge ua for %s inferred as %+v", os, got)
		}
	}
}
