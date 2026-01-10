package testutil

import (
	"crypto/tls"
	"crypto/x509"
	"path/filepath"
	"testing"

	"github.com/isaackogan/tls-impersonate-proxy/internal/proxy"
)

func TempCA(t testing.TB) (tls.Certificate, *x509.CertPool) {
	t.Helper()
	dir := t.TempDir()
	ca, _, err := proxy.LoadOrCreateCA(filepath.Join(dir, "ca.pem"), filepath.Join(dir, "ca.key"))
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(ca.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(leaf)
	return ca, pool
}

func PoolFromPEM(t testing.TB, pemBytes []byte) *x509.CertPool {
	t.Helper()
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pemBytes) {
		t.Fatal("no certificate in PEM")
	}
	return pool
}
