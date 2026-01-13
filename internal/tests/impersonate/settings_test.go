package impersonate_test

import (
	"net/http"
	"testing"

	"github.com/isaackogan/tls-impersonate-proxy/internal/impersonate"
	"github.com/isaackogan/tls-impersonate-proxy/internal/tests/testutil"
)

func TestBrowserWithHttp2SettingsOverride(t *testing.T) {
	up := testutil.NewUpstream(t)
	c, err := impersonate.Build(spec(t, "X-Tip-Browser", "chrome", "X-Tip-Http2Settings", "HeaderTableSize=4096; EnablePush=0; InitialWindowSize=65535"), impersonate.Options{})
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	defer c.Close()
	req, _ := http.NewRequest("GET", up.URL+"/s", nil)
	resp := do(t, c, req)
	if resp.Proto != "HTTP/2.0" {
		t.Fatalf("proto %s", resp.Proto)
	}
}
