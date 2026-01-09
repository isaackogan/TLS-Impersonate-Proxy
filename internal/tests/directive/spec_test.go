package directive_test

import (
	"testing"
	"time"

	"github.com/isaackogan/tls-impersonate-proxy/internal/directive"
)

func TestResolveIsDeterministicGivenPick(t *testing.T) {
	d, _ := directive.Parse(headers("X-Tip-Os", "ios,android"), mustPolicy(t, nil, nil))
	r := d.Resolve(func(n int) int { return n - 1 })
	if len(r.Os) != 1 || r.Os[0] != "android" {
		t.Fatalf("%v", r.Os)
	}
	d, _ = directive.Parse(headers("X-Tip-Os", "random"), mustPolicy(t, nil, nil))
	r = d.Resolve(func(int) int { return 2 })
	if r.Os[0] != "linux" {
		t.Fatalf("%v", r.Os)
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
