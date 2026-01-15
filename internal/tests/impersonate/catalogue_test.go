package impersonate_test

import (
	"net/http"
	"regexp"
	"strings"
	"testing"

	"github.com/isaackogan/tls-impersonate-proxy/internal/impersonate"
	"github.com/isaackogan/tls-impersonate-proxy/internal/tests/testutil"
)

var hex12 = regexp.MustCompile(`^[0-9a-f]{12}$`)

func TestCatalogueShape(t *testing.T) {
	c := impersonate.Profiles()
	if len(c.Profiles) != 14 || !hex12.MatchString(c.Revision) {
		t.Fatalf("profiles %d revision %q", len(c.Profiles), c.Revision)
	}
	seen := map[string]bool{}
	for _, p := range c.Profiles {
		if !hex12.MatchString(p.ID) || seen[p.ID] {
			t.Fatalf("bad or duplicate id %q", p.ID)
		}
		seen[p.ID] = true
		if p.Browser == "" || p.Os == "" || p.UserAgent == "" {
			t.Fatalf("incomplete profile %+v", p)
		}
		if (p.Os == "IOS") != (p.Fidelity == "low") {
			t.Fatalf("fidelity for %s/%s is %q", p.Browser, p.Os, p.Fidelity)
		}
		if (p.Os == "Android" || p.Os == "IOS") != p.Mobile {
			t.Fatalf("mobile flag for %s/%s is %v", p.Browser, p.Os, p.Mobile)
		}
		switch p.Browser {
		case "Firefox":
			if p.SecChUa != "" || p.SecChUaPlatform != "" {
				t.Fatalf("firefox has no client hints: %+v", p)
			}
		case "Edge":
			if !strings.Contains(p.SecChUa, `"Microsoft Edge"`) || !strings.Contains(p.UserAgent, "Edg") {
				t.Fatalf("edge identity %+v", p)
			}
		case "Chrome":
			if !strings.Contains(p.SecChUa, `"Google Chrome"`) || p.SecChUaPlatform == "" || p.SecChUaMobile == "" {
				t.Fatalf("chrome hints %+v", p)
			}
		}
		got, ok := impersonate.Lookup(strings.ToUpper(p.ID))
		if !ok || got.UserAgent != p.UserAgent {
			t.Fatalf("lookup of %s failed", p.ID)
		}
	}
	if impersonate.Profiles().Revision != c.Revision {
		t.Fatal("revision must be stable")
	}
	if _, ok := impersonate.Lookup("000000000000"); ok {
		t.Fatal("unknown id must not resolve")
	}
}

func TestProfileYieldsItsExactUserAgent(t *testing.T) {
	up := testutil.NewUpstream(t)
	for _, p := range impersonate.Profiles().Profiles {
		c, err := impersonate.Build(spec(t, "X-Tip-Browser", p.Browser, "X-Tip-Os", p.Os), impersonate.Options{})
		if err != nil {
			t.Fatal(err)
		}
		req, _ := http.NewRequest("GET", up.URL+"/catalogue", nil)
		do(t, c, req)
		seen := up.Last(t)
		c.Close()
		if seen.Header.Get("User-Agent") != p.UserAgent {
			t.Fatalf("%s/%s: wire ua %q, catalogue %q", p.Browser, p.Os, seen.Header.Get("User-Agent"), p.UserAgent)
		}
		if p.SecChUa != "" && seen.Header.Get("Sec-Ch-Ua") != p.SecChUa {
			t.Fatalf("%s/%s: wire sec-ch-ua %q, catalogue %q", p.Browser, p.Os, seen.Header.Get("Sec-Ch-Ua"), p.SecChUa)
		}
	}
}
