package directive_test

import (
	"strings"
	"testing"

	"github.com/isaackogan/tls-impersonate-proxy/internal/directive"
)

func TestBrowserChoiceList(t *testing.T) {
	families := []string{"chrome", "edge", "firefox"}
	oses := func(b string) []string {
		if b == "edge" {
			return []string{"windows", "macos", "linux", "android"}
		}
		return []string{"windows", "macos", "linux", "android", "ios"}
	}
	last := func(n int) int { return n - 1 }
	first := func(int) int { return 0 }
	parse := func(kv ...string) directive.Directive {
		d, issues := directive.Parse(headers(kv...), mustPolicy(t, nil, nil))
		if len(issues) > 0 {
			t.Fatal(issues)
		}
		return d
	}
	joined := func(d directive.Directive) string { return strings.Join(d.Browser, ",") + "/" + strings.Join(d.Os, ",") }

	d, ok := parse("X-Tip-Browser", "Random").Resolve(families, oses, last)
	if !ok || joined(d) != "firefox/" {
		t.Fatalf("random browser alone: %s %v", joined(d), ok)
	}
	d, ok = parse("X-Tip-Browser", "Random", "X-Tip-Os", "IOS").Resolve(families, oses, func(n int) int { return min(1, n-1) })
	if !ok || joined(d) != "firefox/ios" {
		t.Fatalf("random browser on ios must skip edge: %s %v", joined(d), ok)
	}
	d, ok = parse("X-Tip-Browser", "chrome, Edge", "X-Tip-Os", "IOS,Windows").Resolve(families, oses, last)
	if !ok || joined(d) != "edge/windows" {
		t.Fatalf("list pairs are narrowed to what the picked browser supports: %s %v", joined(d), ok)
	}
	if _, ok = parse("X-Tip-Browser", "Edge", "X-Tip-Os", "IOS").Resolve(families, oses, first); ok {
		t.Fatal("edge on ios must not resolve")
	}
	d, ok = parse("X-Tip-Os", "Random").Resolve(families, oses, first)
	if !ok || joined(d) != "/random" {
		t.Fatalf("os without a browser is left alone: %s %v", joined(d), ok)
	}
	if d.Spec().Os != "" || d.Spec().Browser != "" {
		t.Fatal("os without a browser must not reach the spec")
	}
	if s := parse("X-Tip-Browser", "Firefox", "X-Tip-Os", "Linux").Spec(); s.Browser != "firefox" || s.Os != "linux" {
		t.Fatalf("spec %+v", s)
	}
	if d := parse("X-Tip-Browser", "Chrome", "X-Tip-Browser", "Edge"); strings.Join(d.Browser, ",") != "chrome,edge" {
		t.Fatalf("repeated lines join into one list: %v", d.Browser)
	}
	_, issues := directive.Parse(headers("X-Tip-Browser", "Safari"), mustPolicy(t, nil, nil))
	if len(issues) == 0 || !strings.Contains(issues.Error(), "must be one of Chrome, Firefox, Edge, Random") {
		t.Fatalf("issues %v", issues)
	}
}
