package directive_test

import (
	"testing"
	"time"

	"github.com/isaackogan/tls-impersonate-proxy/internal/directive"
)

func TestResolveIsDeterministicGivenPick(t *testing.T) {
	families := []string{"chrome", "edge", "firefox"}
	all := func(string) []string { return directive.ConcreteOs() }
	third := func(n int) int { return min(2, n-1) }
	d, _ := directive.Parse(headers("X-Tip-Browser", "chrome", "X-Tip-Os", "ios,android"), mustPolicy(t, nil, nil))
	r, ok := d.Resolve(families, all, func(n int) int { return n - 1 })
	if !ok || len(r.Os) != 1 || r.Os[0] != "android" {
		t.Fatalf("%v %v", r.Os, ok)
	}
	d, _ = directive.Parse(headers("X-Tip-Browser", "chrome", "X-Tip-Os", "random"), mustPolicy(t, nil, nil))
	r, _ = d.Resolve(families, all, third)
	if r.Os[0] != "linux" {
		t.Fatalf("%v", r.Os)
	}
	desktop := func(string) []string { return []string{"windows", "macos", "linux"} }
	r, ok = d.Resolve(families, desktop, third)
	if !ok || r.Os[0] != "linux" {
		t.Fatalf("random within a subset: %v %v", r.Os, ok)
	}
	d, _ = directive.Parse(headers("X-Tip-Browser", "chrome", "X-Tip-Os", "ios"), mustPolicy(t, nil, nil))
	if _, ok := d.Resolve(families, desktop, func(int) int { return 0 }); ok {
		t.Fatal("an unavailable os must not resolve")
	}
}

func TestSpecKeyExcludesPerRequestDirectives(t *testing.T) {
	a, _ := directive.Parse(headers("X-Tip-Browser", "chrome", "X-Tip-Os", "windows"), mustPolicy(t, nil, nil))
	b, _ := directive.Parse(headers("X-Tip-Browser", "chrome", "X-Tip-Os", "windows", "X-Tip-Timeout", "7300ms", "X-Tip-Keep", "Accept", "X-Tip-Scheme", "https", "X-Tip-Match", "true"), mustPolicy(t, nil, nil))
	if a.Spec().Key() != b.Spec().Key() {
		t.Fatalf("keys differ:\n%s\n%s", a.Spec().Key(), b.Spec().Key())
	}
	if b.Timeout != 7300*time.Millisecond {
		t.Fatal("timeout lost")
	}
}

func TestSpecKeyOrdersH2AndPreservesH3(t *testing.T) {
	a, _ := directive.Parse(headers("X-Tip-Http2Settings", "EnablePush=0; HeaderTableSize=1"), mustPolicy(t, nil, nil))
	b, _ := directive.Parse(headers("X-Tip-Http2Settings", "HeaderTableSize=1; EnablePush=0"), mustPolicy(t, nil, nil))
	if a.Spec().Key() != b.Spec().Key() {
		t.Fatal("h2 key order should not matter")
	}
	c, _ := directive.Parse(headers("X-Tip-Http3Settings", "Grease=true; H3Datagram=1"), mustPolicy(t, nil, nil))
	d, _ := directive.Parse(headers("X-Tip-Http3Settings", "H3Datagram=1; Grease=true"), mustPolicy(t, nil, nil))
	if c.Spec().Key() == d.Spec().Key() {
		t.Fatal("h3 key order must matter")
	}
}

func TestSpecKeyIsStableAcrossValueCasing(t *testing.T) {
	a, _ := directive.Parse(headers("X-Tip-Browser", "Chrome", "X-Tip-Proxy", "HTTP://Proxy.Example:8080"), mustPolicy(t, nil, nil))
	b, _ := directive.Parse(headers("X-Tip-Browser", "chrome", "X-Tip-Proxy", "http://proxy.example:8080"), mustPolicy(t, nil, nil))
	if a.Spec().Key() != b.Spec().Key() {
		t.Fatal("keys differ")
	}
}
