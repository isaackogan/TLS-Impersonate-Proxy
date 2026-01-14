package proxy_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/isaackogan/tls-impersonate-proxy/internal/proxy"
)

func TestLoadOrCreateCA(t *testing.T) {
	dir := t.TempDir()
	cert, key := filepath.Join(dir, "ca.pem"), filepath.Join(dir, "ca.key")
	ca, created, err := proxy.LoadOrCreateCA(cert, key)
	if err != nil || !created {
		t.Fatalf("created=%v err=%v", created, err)
	}
	info, _ := os.Stat(key)
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("key mode %v", info.Mode().Perm())
	}
	again, created, err := proxy.LoadOrCreateCA(cert, key)
	if err != nil || created || proxy.Fingerprint(again) != proxy.Fingerprint(ca) {
		t.Fatalf("reload created=%v err=%v", created, err)
	}
	if fp := proxy.Fingerprint(ca); len(fp) != 95 || !strings.Contains(fp, ":") {
		t.Fatalf("fingerprint %q", fp)
	}
	os.Chmod(key, 0o644)
	if _, _, err := proxy.LoadOrCreateCA(cert, key); err == nil {
		t.Fatal("expected refusal for a world-readable key")
	}
	os.Chmod(key, 0o440)
	if _, _, err := proxy.LoadOrCreateCA(cert, key); err != nil {
		t.Fatalf("group-readable key from a mounted secret must load: %v", err)
	}
	os.Remove(key)
	if _, _, err := proxy.LoadOrCreateCA(cert, key); err == nil {
		t.Fatal("expected error when only the certificate exists")
	}
}
