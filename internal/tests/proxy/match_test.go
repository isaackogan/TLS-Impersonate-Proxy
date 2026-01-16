package proxy_test

import (
	"strings"
	"testing"

	"github.com/isaackogan/tls-impersonate-proxy/internal/directive"
	"github.com/isaackogan/tls-impersonate-proxy/internal/impersonate"
)

func TestMatchPrecedenceIsRequestThenInferredThenDefault(t *testing.T) {
	policy, err := directive.NewPolicy(map[string]string{"Browser": "Chrome", "Match": "true"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	h := newHarnessWithPolicy(t, policy)
	firefox := "Mozilla/5.0 (X11; Linux x86_64; rv:130.0) Gecko/20100101 Firefox/130.0"
	safari := "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Safari/605.1.15"
	cases := []struct {
		name  string
		ua    string
		extra []string
		want  []string
	}{
		{"inferred beats the default", firefox, nil, []string{"Firefox/148", "Linux"}},
		{"unplaceable falls back to the default", safari, nil, []string{"Chrome/152"}},
		{"request beats inferred", firefox, []string{"X-Tip-Browser", "Edge"}, []string{"Edg/152"}},
		{"request os survives inference", firefox, []string{"X-Tip-Os", "Android"}, []string{"Firefox/148", "Android"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, echoed := h.get(t, h.upstream.URL+"/precedence", append([]string{"User-Agent", tc.ua}, tc.extra...)...)
			ua := echoedHeader(echoed, "User-Agent")
			for _, want := range tc.want {
				if !strings.Contains(ua, want) {
					t.Fatalf("ua %q lacks %q", ua, want)
				}
			}
		})
	}
	var pinned impersonate.Profile
	for _, p := range impersonate.Profiles().Profiles {
		if p.Browser == "Firefox" && p.Os == "MacOS" {
			pinned = p
		}
	}
	resp, echoed := h.get(t, h.upstream.URL+"/profile-over-defaults", "X-Tip-Profile", pinned.ID, "User-Agent", safari)
	if resp.StatusCode != 200 || echoedHeader(echoed, "User-Agent") != pinned.UserAgent {
		t.Fatalf("a request profile must displace default browser and match: %d %q", resp.StatusCode, echoedHeader(echoed, "User-Agent"))
	}
}
