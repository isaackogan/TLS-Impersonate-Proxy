package directive_test

import (
	"strings"
	"testing"
	"time"

	"github.com/isaackogan/tls-impersonate-proxy/internal/directive"
)

func TestRequestDirectivesAreMarked(t *testing.T) {
	p := mustPolicy(t, map[string]string{"Browser": "Chrome", "Match": "true", "Os": "Random"}, nil)
	d, issues := directive.Parse(headers(), p)
	if len(issues) > 0 || d.FromRequest("Browser") || d.FromRequest("os") || !d.Match || strings.Join(d.Browser, ",") != "chrome" {
		t.Fatalf("defaults are not request-supplied: %+v %v", d, issues)
	}
	d, _ = directive.Parse(headers("X-Tip-Browser", "Firefox"), p)
	if !d.FromRequest("Browser") || !d.FromRequest("BROWSER") || d.FromRequest("Os") || !d.Match || strings.Join(d.Browser, ",") != "firefox" {
		t.Fatalf("request browser over default: %+v", d)
	}
}

func TestRequestIdentityDisplacesDefaultsOnTheOtherSide(t *testing.T) {
	id := "c1a2f0e9b7d3"
	p := mustPolicy(t, map[string]string{"Browser": "Chrome", "Os": "Random", "Match": "true", "Timeout": "5s"}, nil)
	d, issues := directive.Parse(headers("X-Tip-Profile", id), p)
	if len(issues) > 0 || d.Profile != id || d.Browser != nil || d.Os != nil || d.Match || d.Timeout != 5*time.Second {
		t.Fatalf("request profile must displace default browser, os and match only: %+v %v", d, issues)
	}
	p = mustPolicy(t, map[string]string{"Profile": id, "Timeout": "5s"}, nil)
	d, issues = directive.Parse(headers("X-Tip-Match", "true"), p)
	if len(issues) > 0 || d.Profile != "" || !d.Match || d.Timeout != 5*time.Second {
		t.Fatalf("request match must displace the default profile only: %+v %v", d, issues)
	}
	d, issues = directive.Parse(headers("X-Tip-Os", "Linux"), p)
	if len(issues) > 0 || d.Profile != "" || strings.Join(d.Os, ",") != "linux" {
		t.Fatalf("request os must displace the default profile: %+v %v", d, issues)
	}
	d, issues = directive.Parse(headers(), p)
	if len(issues) > 0 || d.Profile != id {
		t.Fatalf("a default profile applies when the request names no identity: %+v %v", d, issues)
	}
	if _, err := directive.NewPolicy(map[string]string{"Profile": id, "Browser": "Chrome"}, nil); err == nil || !strings.Contains(err.Error(), "Profile: cannot be combined") {
		t.Fatalf("defaults must respect exclusivity among themselves: %v", err)
	}
}
