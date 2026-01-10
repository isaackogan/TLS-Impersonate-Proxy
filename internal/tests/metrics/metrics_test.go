package metrics_test

import (
	"io"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/isaackogan/tls-impersonate-proxy/internal/metrics"
)

func scrape(t *testing.T, m *metrics.Metrics) string {
	t.Helper()
	rec := httptest.NewRecorder()
	m.Handler().ServeHTTP(rec, httptest.NewRequest("GET", "/metrics", nil))
	body, _ := io.ReadAll(rec.Body)
	return string(body)
}

func TestCollectorsAndLabels(t *testing.T) {
	m, err := metrics.New(metrics.Options{
		Collectors: metrics.Collectors{Requests: true, Latency: false, Bandwidth: true, UpstreamErrors: true, ValidationErrors: true, Clients: true, Tunnels: true},
		Routes:     []metrics.Route{{Name: "room", Host: "www.tiktok.com", Path: "/room/:room_id/*", Capture: []string{"room_id"}}},
	})
	if err != nil {
		t.Fatal(err)
	}
	m.RequestStarted()
	m.RequestFinished(metrics.Request{Host: "www.tiktok.com", Method: "GET", Path: "/room/7/live", Browser: "chrome", Status: 200, Duration: 20 * time.Millisecond, BytesIn: 10, BytesOut: 300})
	m.RequestFinished(metrics.Request{Host: "other.example", Method: "POST", Status: 418})
	m.ValidationFailed("Browser")
	m.UpstreamError("other.example", "dial")
	m.TunnelOpened()
	m.CacheMiss()
	m.ClientBuilt("chrome", "windows")
	m.CacheHit()
	m.ClientEvicted()
	out := scrape(t, m)
	for _, want := range []string{
		`tip_requests_total{browser="chrome",host="www.tiktok.com",method="GET",room_id="7",route="room",status="200"} 1`,
		`tip_requests_total{browser="",host="other.example",method="POST",room_id="",route="",status="418"} 1`,
		`tip_bandwidth_bytes_total{direction="out",host="www.tiktok.com",room_id="7",route="room"} 300`,
		`tip_validation_errors_total{directive="Browser"} 1`,
		`tip_upstream_errors_total{host="other.example",kind="dial"} 1`,
		`tip_tunnels_total 1`,
		`tip_client_builds_total{browser="chrome",os="windows"} 1`,
		`tip_client_cache_hits_total 1`,
		`tip_client_evictions_total 1`,
		`tip_clients_active 0`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in:\n%s", want, out)
		}
	}
	if strings.Contains(out, "tip_request_duration_seconds") {
		t.Error("latency collector should be disabled")
	}
	if got := m.Route("www.tiktok.com", "/room/1/x"); got != "room" {
		t.Errorf("route %q", got)
	}
}
