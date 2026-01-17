package impersonate_test

import (
	"strings"
	"testing"

	"github.com/isaackogan/tls-impersonate-proxy/internal/impersonate"
)

func TestProxyOverHttp3IsRefused(t *testing.T) {
	for _, proxy := range []string{"http://127.0.0.1:1", "socks5://127.0.0.1:1"} {
		_, err := impersonate.Build(spec(t, "X-Tip-ForceHttp", "3", "X-Tip-Proxy", proxy), impersonate.Options{})
		if err == nil || !strings.Contains(err.Error(), "HTTP/3") {
			t.Fatalf("%s: err %v", proxy, err)
		}
	}
}
