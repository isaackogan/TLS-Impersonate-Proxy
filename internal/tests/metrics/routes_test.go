package metrics_test

import (
	"testing"

	"github.com/isaackogan/tls-impersonate-proxy/internal/metrics"
)

func TestMatcher(t *testing.T) {
	m, err := metrics.NewMatcher([]metrics.Route{
		{Name: "room", Host: "www.tiktok.com", Path: "/room/:room_id/*", Capture: []string{"room_id"}},
		{Name: "profile", Host: "*.tiktok.com", Path: "/@:handle"},
		{Name: "api", Host: "api.example", Path: "/v1/*", Capture: nil},
	})
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		host, path, wantName, wantRoom string
	}{
		{"www.tiktok.com", "/room/7421/live", "room", "7421"},
		{"WWW.TIKTOK.COM", "/room/7421", "room", "7421"},
		{"m.tiktok.com", "/@scout", "profile", ""},
		{"m.tiktok.com", "/@scout/video", "", ""},
		{"tiktok.com", "/@scout", "", ""},
		{"api.example", "/v1", "api", ""},
		{"api.example", "/v1/a/b", "api", ""},
		{"api.example", "/v2/a", "", ""},
		{"www.tiktok.com", "/room//live", "", ""},
	}
	for _, tc := range cases {
		name, labels := m.Match(tc.host, tc.path)
		if name != tc.wantName || labels["room_id"] != tc.wantRoom {
			t.Errorf("%s%s: got %q %v", tc.host, tc.path, name, labels)
		}
	}
	if got := m.Captures(); len(got) != 1 || got[0] != "room_id" {
		t.Fatalf("captures %v", got)
	}
}

func TestMatcherRejectsBadRoutes(t *testing.T) {
	bad := [][]metrics.Route{
		{{Name: "a", Host: "h", Path: "/x/*/y"}},
		{{Name: "a", Host: "h", Path: "/x/:id", Capture: []string{"other"}}},
	}
	for _, routes := range bad {
		if _, err := metrics.NewMatcher(routes); err == nil {
			t.Errorf("expected error for %+v", routes)
		}
	}
}
