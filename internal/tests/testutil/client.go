package testutil

import (
	"crypto/tls"
	"crypto/x509"
	"net/http"
	"net/url"
	"testing"
)

func ProxyClient(t testing.TB, proxyURL string, pool *x509.CertPool) *http.Client {
	t.Helper()
	u, err := url.Parse(proxyURL)
	if err != nil {
		t.Fatal(err)
	}
	return &http.Client{
		Transport: &http.Transport{
			Proxy:           http.ProxyURL(u),
			TLSClientConfig: &tls.Config{RootCAs: pool},
		},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
}
