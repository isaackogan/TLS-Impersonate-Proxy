package logging_test

import (
	"testing"

	"github.com/isaackogan/tls-impersonate-proxy/internal/logging"
)

func TestRedactUserinfo(t *testing.T) {
	cases := map[string]string{
		"http://alice:s3cret@proxy.example:8080/path":         "http://***@proxy.example:8080/path",
		"socks5h://alice:s3cret@10.0.0.1:1080":                "socks5h://***@10.0.0.1:1080",
		"HTTPS://alice@proxy.example":                         "HTTPS://***@proxy.example",
		"http://alice:p@ss@proxy.example/":                    "http://***@proxy.example/",
		"http://proxy.example:8080/no/creds":                  "http://proxy.example:8080/no/creds",
		`parse "http://alice:s3cret@h:1": first path segment`: `parse "http://***@h:1": first path segment`,
		"a http://u:p@h1 and socks5://u2:p2@h2 too":           "a http://***@h1 and socks5://***@h2 too",
		"nothing here":                                        "nothing here",
	}
	for in, want := range cases {
		if got := logging.RedactUserinfo(in); got != want {
			t.Errorf("%q -> %q, want %q", in, got, want)
		}
	}
}
