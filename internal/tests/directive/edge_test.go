package directive_test

import (
	"strings"
	"testing"

	"github.com/isaackogan/tls-impersonate-proxy/internal/directive"
)

func TestParseReportsShapeAndValueIssuesTogether(t *testing.T) {
	_, issues := directive.Parse(headers("X-Tip-Colour", "red", "X-Tip-Browser", "opera", "X-Tip-Http2Settings", "Nope=1"), mustPolicy(t, nil, nil))
	if len(issues) != 3 {
		t.Fatalf("want 3 issues, got %v", issues)
	}
	msg := issues.Error()
	for _, want := range []string{"X-Tip-Colour: unknown directive", "Browser: must be one of", "Http2Settings: unknown key Nope"} {
		if !strings.Contains(msg, want) {
			t.Errorf("missing %q in %q", want, msg)
		}
	}
}

func TestParseEdgeValues(t *testing.T) {
	cases := []struct {
		name    string
		kv      []string
		wantMsg string
	}{
		{"empty list item", []string{"X-Tip-Os", "ios,,android"}, "Os[1]: must be one of"},
		{"zero timeout", []string{"X-Tip-Timeout", "0s"}, "Timeout: must be positive"},
		{"negative timeout", []string{"X-Tip-Timeout", "-5s"}, "Timeout: must be positive"},
		{"empty keep item", []string{"X-Tip-Keep", "Accept,,"}, "Keep[1]: header names must not be empty"},
		{"h3 unknown key", []string{"X-Tip-Http3Settings", "Grease=true; Push=1"}, "Http3Settings: unknown key Push"},
		{"h3 overflow", []string{"X-Tip-Http3Settings", "QpackMaxTableCapacity=99999999999999999999"}, "Http3Settings.QpackMaxTableCapacity: must be an unsigned 64-bit integer"},
		{"grease not bool", []string{"X-Tip-Http3Settings", "Grease=maybe"}, "Http3Settings.Grease: must be true or false"},
		{"dns without port", []string{"X-Tip-Dns", "1.1.1.1"}, "Dns: must be host:port"},
		{"dot custom bad addr", []string{"X-Tip-DnsOverTls", "dns.example@dns.example"}, "DnsOverTls: must be one of"},
		{"proxy without host", []string{"X-Tip-Proxy", "socks5://"}, "Proxy: must be an absolute URL"},
		{"match not bool", []string{"X-Tip-Match", "always"}, "Match: must be true or false"},
		{"blank interface", []string{"X-Tip-InterfaceAddr", "   "}, "InterfaceAddr: must not be empty"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, issues := directive.Parse(headers(tc.kv...), mustPolicy(t, nil, nil))
			if len(issues) == 0 || !strings.Contains(issues.Error(), tc.wantMsg) {
				t.Fatalf("got %v, want %q", issues, tc.wantMsg)
			}
		})
	}
}

func TestParseAcceptsEdgeValues(t *testing.T) {
	d, issues := directive.Parse(headers(
		"X-Tip-Http3Settings", "Grease=false; H3Datagram=1",
		"X-Tip-DnsOverTls", "dns.example@ 1.1.1.1:853 , 8.8.8.8:853",
		"X-Tip-Keep", " Accept , user-agent ",
		"X-Tip-Os", "RANDOM",
	), mustPolicy(t, nil, nil))
	if len(issues) > 0 {
		t.Fatal(issues)
	}
	if d.Http3Settings.Grease || strings.Join(d.Http3Settings.Order, ",") != "grease,h3datagram" || *d.Http3Settings.H3Datagram != 1 {
		t.Fatalf("http3 %+v", d.Http3Settings)
	}
	if d.DnsOverTls != "dns.example@ 1.1.1.1:853 , 8.8.8.8:853" {
		t.Fatalf("dot %q", d.DnsOverTls)
	}
	if strings.Join(d.Keep, ",") != "accept,user-agent" || d.Os[0] != "random" {
		t.Fatalf("keep %v os %v", d.Keep, d.Os)
	}
}

func TestDeniedDirectiveStillHasItsDefault(t *testing.T) {
	p := mustPolicy(t, map[string]string{"Proxy": "socks5://user:pw@egress.example:1080"}, []string{"Proxy"})
	d, issues := directive.Parse(headers("X-Tip-Browser", "chrome"), p)
	if len(issues) > 0 || d.Proxy != "socks5://user:pw@egress.example:1080" {
		t.Fatalf("%+v %v", d, issues)
	}
	_, issues = directive.Parse(headers("X-Tip-Proxy", "http://other:1"), p)
	if len(issues) != 1 {
		t.Fatalf("%v", issues)
	}
}

func TestSpecDropsOsWithoutBrowser(t *testing.T) {
	a, _ := directive.Parse(headers("X-Tip-Os", "linux"), mustPolicy(t, nil, nil))
	b, _ := directive.Parse(nil, mustPolicy(t, nil, nil))
	if a.Spec().Key() != b.Spec().Key() {
		t.Fatalf("os without browser must not change the key: %s vs %s", a.Spec().Key(), b.Spec().Key())
	}
	c, _ := directive.Parse(headers("X-Tip-Os", "linux", "X-Tip-Browser", "chrome"), mustPolicy(t, nil, nil))
	if c.Spec().Os != "linux" {
		t.Fatalf("spec %+v", c.Spec())
	}
}

func TestIssueHeadersAreSingleLine(t *testing.T) {
	issues := directive.Issues{{Path: "Browser", Message: "bad\r\nX-Injected: 1"}}
	for _, v := range issues.Headers().Values("X-Tip-Error") {
		if strings.ContainsAny(v, "\r\n") {
			t.Fatalf("header value contains a line break: %q", v)
		}
	}
}
