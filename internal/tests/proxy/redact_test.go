package proxy_test

import (
	"strings"
	"testing"

	"github.com/isaackogan/tls-impersonate-proxy/internal/logging"
	"github.com/isaackogan/tls-impersonate-proxy/internal/proxy"
)

func TestDebugLogRedactsOutboundHeaders(t *testing.T) {
	h := newHarness(t, func(o *proxy.Options) { o.Redact = logging.NewRedactor([]string{"Cookie", "Authorization"}).Value })
	h.get(t, h.upstream.URL+"/redact", "X-Tip-Browser", "Chrome", "Cookie", "session=topsecret", "Authorization", "Bearer hunter2")
	logs := h.logs.String()
	if strings.Contains(logs, "topsecret") || strings.Contains(logs, "hunter2") {
		t.Fatalf("secrets leaked into logs:\n%s", logs)
	}
	if !strings.Contains(logs, "cookie: [redacted]") || !strings.Contains(logs, "authorization: [redacted]") {
		t.Fatalf("redaction marker missing:\n%s", logs)
	}
	if seen := h.upstream.Last(t); seen.Header.Get("Cookie") != "session=topsecret" || seen.Header.Get("Authorization") != "Bearer hunter2" {
		t.Fatalf("redaction must not touch the wire: %v", seen.Header)
	}
}
