package impersonate_test

import (
	"testing"

	"github.com/isaackogan/tls-impersonate-proxy/internal/impersonate"
)

func TestInfer(t *testing.T) {
	cases := []struct {
		ua          string
		browser, os string
	}{
		{"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/152.0.0.0 Safari/537.36", "chrome", "windows"},
		{"Mozilla/5.0 (Android 16; Mobile; rv:148.0) Gecko/148.0 Firefox/148.0", "firefox", "android"},
		{"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36 Edg/131.0.0.0", "chrome", "windows"},
		{"Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:120.0) Gecko/20100101 Firefox/120.0", "firefox", "linux"},
		{"Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) CriOS/120.0.0.0 Mobile/15E148 Safari/604.1", "chrome", "ios"},
		{"Mozilla/5.0 (Macintosh; Intel Mac OS X 14_0) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15", "", ""},
		{"curl/8.4.0", "", ""},
		{"", "", ""},
	}
	for _, tc := range cases {
		got := impersonate.Infer(tc.ua)
		if got.Browser != tc.browser || got.Os != tc.os {
			t.Errorf("%q: got %+v, want %s/%s", tc.ua, got, tc.browser, tc.os)
		}
	}
}
