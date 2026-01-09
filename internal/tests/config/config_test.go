package config_test

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/isaackogan/tls-impersonate-proxy/internal/config"
)

func fixture(name string) string {
	return filepath.Join("..", "testdata", "config", name)
}

func TestEmptyFileYieldsDefaults(t *testing.T) {
	cfg, err := config.Load(fixture("empty.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	checks := []struct {
		name string
		got  any
		want any
	}{
		{"server.listen", cfg.Server.Listen, ":8080"},
		{"server.read_header_timeout", cfg.Server.ReadHeaderTimeout, 10 * time.Second},
		{"server.serve_ca", cfg.Server.ServeCa, true},
		{"tls.cert_cache_size", cfg.Tls.CertCacheSize, 4096},
		{"upstream.timeout", cfg.Upstream.Timeout, 30 * time.Second},
		{"clients.max", cfg.Clients.Max, 256},
		{"clients.idle_ttl", cfg.Clients.IdleTtl, 10 * time.Minute},
		{"encoding.mode", cfg.Encoding.Mode, "negotiate"},
		{"auth.realm", cfg.Auth.Realm, "tip"},
		{"logging.level", cfg.Logging.Level, "info"},
		{"metrics.enabled", cfg.Metrics.Enabled, true},
		{"metrics.collectors.requests", cfg.Metrics.Collectors.Requests, true},
		{"logging.redact", strings.Join(cfg.Logging.Redact, ","), "Authorization,Proxy-Authorization,Cookie,Set-Cookie"},
	}
	for _, c := range checks {
		if c.got != c.want {
			t.Errorf("%s = %v, want %v", c.name, c.got, c.want)
		}
	}
}

func TestPartialFileKeepsOtherDefaults(t *testing.T) {
	cfg, err := config.Load(fixture("partial.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Server.Listen != ":1234" || cfg.Metrics.Enabled || cfg.Metrics.Listen != ":9090" || cfg.Server.IdleTimeout != 90*time.Second {
		t.Fatalf("unexpected %+v", cfg)
	}
}

func TestFullFile(t *testing.T) {
	cfg, err := config.Load(fixture("full.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Server.MaxConnections != 100 || cfg.Server.ShutdownGrace != 20*time.Second || cfg.Server.ServeCa {
		t.Fatalf("server %+v", cfg.Server)
	}
	if !cfg.Tls.ClientHttp2 || cfg.Tls.CertCacheSize != 10 {
		t.Fatalf("tls %+v", cfg.Tls)
	}
	if len(cfg.Directives.Defaults) != 2 || cfg.Directives.Deny[1] != "InterfaceAddr" {
		t.Fatalf("directives %+v", cfg.Directives)
	}
	if len(cfg.Auth.Users) != 1 || cfg.Auth.Users[0].Password != "secret" {
		t.Fatalf("auth %+v", cfg.Auth)
	}
	if cfg.Metrics.Collectors.Latency || !cfg.Metrics.Collectors.Tunnels {
		t.Fatalf("collectors %+v", cfg.Metrics.Collectors)
	}
	if len(cfg.Metrics.Routes) != 1 || cfg.Metrics.Routes[0].Capture[0] != "room_id" {
		t.Fatalf("routes %+v", cfg.Metrics.Routes)
	}
}

func TestUnknownKeysAreErrorsWithPaths(t *testing.T) {
	_, err := config.Load(fixture("unknown.yaml"))
	if err == nil {
		t.Fatal("expected error")
	}
	for _, want := range []string{"server.lisen", "metrics.routes[0].captures"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q lacks %q", err, want)
		}
	}
}

func TestInvalidValuesReportEveryIssue(t *testing.T) {
	_, err := config.Load(fixture("invalid.yaml"))
	var invalid config.InvalidError
	if !errors.As(err, &invalid) {
		t.Fatalf("expected InvalidError, got %v", err)
	}
	msg := err.Error()
	for _, want := range []string{"server.shutdown_grace", "clients.max", "encoding.mode", "auth.users[0].password", "metrics.routes[0].name", "metrics.routes[0].path"} {
		if !strings.Contains(msg, want) {
			t.Errorf("issues lack %q:\n%s", want, msg)
		}
	}
}

func TestMissingFile(t *testing.T) {
	if _, err := config.Load(fixture("nope.yaml")); err == nil {
		t.Fatal("expected error")
	}
}

func TestPermissive(t *testing.T) {
	dir := t.TempDir()
	open := filepath.Join(dir, "open.yaml")
	closed := filepath.Join(dir, "closed.yaml")
	os.WriteFile(open, nil, 0o644)
	os.WriteFile(closed, nil, 0o600)
	if p, _ := config.Permissive(open); !p {
		t.Error("0644 should be permissive")
	}
	if p, _ := config.Permissive(closed); p {
		t.Error("0600 should not be permissive")
	}
}
