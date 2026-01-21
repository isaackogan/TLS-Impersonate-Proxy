package directive_test

import (
	"strings"
	"testing"

	"github.com/isaackogan/tls-impersonate-proxy/internal/directive"
)

func TestNewPolicyValidates(t *testing.T) {
	cases := []struct {
		name     string
		defaults map[string]string
		deny     []string
		wantErr  bool
	}{
		{"ok", map[string]string{"Browser": "Chrome", "X-Tip-Os": "IOS,Android"}, []string{"Proxy", "x-tip-dns"}, false},
		{"bad default value", map[string]string{"Browser": "Safari"}, nil, true},
		{"unknown default", map[string]string{"Colour": "red"}, nil, true},
		{"unknown deny", nil, []string{"Colour"}, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := directive.NewPolicy(tc.defaults, tc.deny)
			if (err != nil) != tc.wantErr {
				t.Fatalf("err = %v, wantErr %v", err, tc.wantErr)
			}
		})
	}
}

func TestProxyHostsAllowlist(t *testing.T) {
	base := mustPolicy(t, nil, nil)
	p, err := base.ProxyHosts([]string{" Egress.Internal:3128 ", "*.svc.cluster.local", "10.0.0.1"})
	if err != nil {
		t.Fatal(err)
	}
	for _, u := range []string{"http://u:p@egress.internal:3128", "socks5://a.b.svc.cluster.local:1080", "http://10.0.0.1", "HTTP://EGRESS.INTERNAL:3128"} {
		if _, issues := directive.Parse(headers("X-Tip-Proxy", u), p); len(issues) > 0 {
			t.Errorf("%s should be allowed: %v", u, issues)
		}
	}
	for _, u := range []string{"http://egress.internal:3129", "http://egress.internal", "http://svc.cluster.local", "http://evil.example:3128", "http://10.0.0.1.evil.example"} {
		_, issues := directive.Parse(headers("X-Tip-Proxy", u), p)
		if len(issues) != 1 || issues[0].Path != "Proxy" || issues.Error() != "Proxy: host must be one of egress.internal:3128, *.svc.cluster.local, 10.0.0.1" {
			t.Errorf("%s should be refused: %v", u, issues)
		}
	}
	if _, issues := directive.Parse(headers("X-Tip-Browser", "Chrome"), p); len(issues) > 0 {
		t.Errorf("no proxy is fine without require_proxy: %v", issues)
	}
	if _, err := base.ProxyHosts([]string{"http://egress"}); err == nil {
		t.Error("a URL is not a host pattern")
	}
	withDefault := mustPolicy(t, map[string]string{"Proxy": "http://other.example:3128"}, nil)
	if _, err := withDefault.ProxyHosts([]string{"egress.internal"}); err == nil || !strings.Contains(err.Error(), "defaults: Proxy: host must be one of") {
		t.Errorf("a default outside the allowlist must fail at startup: %v", err)
	}
}

func TestRequireProxy(t *testing.T) {
	p, err := mustPolicy(t, nil, nil).RequireProxy()
	if err != nil {
		t.Fatal(err)
	}
	_, issues := directive.Parse(headers("X-Tip-Browser", "Chrome"), p)
	if len(issues) != 1 || issues[0].Path != "Proxy" || issues.Error() != "Proxy: required by this proxy" {
		t.Fatalf("%v", issues)
	}
	if _, issues := directive.Parse(headers("X-Tip-Proxy", "http://egress:3128"), p); len(issues) > 0 {
		t.Fatal(issues)
	}
	withDefault, err := mustPolicy(t, map[string]string{"Proxy": "http://egress:3128"}, nil).RequireProxy()
	if err != nil {
		t.Fatal(err)
	}
	if d, issues := directive.Parse(headers(), withDefault); len(issues) > 0 || d.Proxy != "http://egress:3128" {
		t.Fatalf("a default satisfies the requirement: %+v %v", d, issues)
	}
	if _, err := mustPolicy(t, nil, []string{"Proxy"}).RequireProxy(); err == nil || !strings.Contains(err.Error(), "require_proxy") {
		t.Fatalf("denied without a default can never pass: %v", err)
	}
	if _, err := mustPolicy(t, map[string]string{"Proxy": "http://egress:3128"}, []string{"Proxy"}).RequireProxy(); err != nil {
		t.Fatal(err)
	}
}
