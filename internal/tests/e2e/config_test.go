package e2e_test

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestInvalidConfigFailsFast(t *testing.T) {
	dir := t.TempDir()
	bin := filepath.Join(dir, "tip")
	if out, err := exec.Command("go", "build", "-o", bin, "../../../cmd/tip").CombinedOutput(); err != nil {
		t.Fatalf("build: %v\n%s", err, out)
	}
	cases := []struct {
		name, yaml, want string
	}{
		{"unknown key", "server:\n  lisen: \":1\"\n", "unknown keys: server.lisen"},
		{"bad value", "clients:\n  max: 0\n", "clients.max"},
		{"bad default directive", "directives:\n  defaults: [\"Browser: Safari\"]\n", "defaults: Browser: must be one of"},
		{"bad deny", "directives:\n  deny: [Colour]\n", "deny: unknown directive"},
		{"bad route capture", "metrics:\n  routes:\n    - {name: r, host: h, path: /a/:id, capture: [other]}\n", "capture \"other\" is not a parameter"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := filepath.Join(dir, strings.ReplaceAll(tc.name, " ", "-")+".yaml")
			os.WriteFile(cfg, []byte(tc.yaml), 0o600)
			out, err := exec.Command(bin, "--config", cfg).CombinedOutput()
			if err == nil {
				t.Fatalf("expected non-zero exit, output:\n%s", out)
			}
			if !strings.Contains(string(out), tc.want) {
				t.Fatalf("output lacks %q:\n%s", tc.want, out)
			}
		})
	}
}
