package impersonate

import (
	"fmt"
	"math"
	"slices"
	"strings"
	"time"

	"github.com/enetx/g"
	ehttp "github.com/enetx/http"
	"github.com/enetx/surf"

	"github.com/isaackogan/tls-impersonate-proxy/internal/directive"
)

type Options struct {
	VerifyCertificates    bool
	ResponseHeaderTimeout time.Duration
}

var jaPresets = map[string]func(*surf.JA) *surf.Builder{
	"android": (*surf.JA).Android, "chrome": (*surf.JA).Chrome, "chrome58": (*surf.JA).Chrome58, "chrome62": (*surf.JA).Chrome62,
	"chrome70": (*surf.JA).Chrome70, "chrome72": (*surf.JA).Chrome72, "chrome83": (*surf.JA).Chrome83, "chrome87": (*surf.JA).Chrome87,
	"chrome96": (*surf.JA).Chrome96, "chrome100": (*surf.JA).Chrome100, "chrome102": (*surf.JA).Chrome102, "chrome106": (*surf.JA).Chrome106,
	"chrome120": (*surf.JA).Chrome120, "chrome120pq": (*surf.JA).Chrome120PQ, "chrome152": (*surf.JA).Chrome152,
	"edge": (*surf.JA).Edge, "edge85": (*surf.JA).Edge85, "edge106": (*surf.JA).Edge106,
	"firefox": (*surf.JA).Firefox, "firefox55": (*surf.JA).Firefox55, "firefox56": (*surf.JA).Firefox56, "firefox63": (*surf.JA).Firefox63,
	"firefox65": (*surf.JA).Firefox65, "firefox99": (*surf.JA).Firefox99, "firefox102": (*surf.JA).Firefox102, "firefox105": (*surf.JA).Firefox105,
	"firefox120": (*surf.JA).Firefox120, "firefox148": (*surf.JA).Firefox148,
	"ios": (*surf.JA).IOS, "ios11": (*surf.JA).IOS11, "ios12": (*surf.JA).IOS12, "ios13": (*surf.JA).IOS13, "ios14": (*surf.JA).IOS14,
	"randomized": (*surf.JA).Randomized, "randomizedalpn": (*surf.JA).RandomizedALPN, "randomizednoalpn": (*surf.JA).RandomizedNoALPN,
	"safari": (*surf.JA).Safari,
}

var dotProviders = map[string]func(*surf.DNSOverTLS) *surf.Builder{
	"adguard": (*surf.DNSOverTLS).AdGuard, "google": (*surf.DNSOverTLS).Google, "cloudflare": (*surf.DNSOverTLS).Cloudflare,
	"quad9": (*surf.DNSOverTLS).Quad9, "switch": (*surf.DNSOverTLS).Switch, "cirashield": (*surf.DNSOverTLS).CIRAShield,
	"ali": (*surf.DNSOverTLS).Ali, "quad101": (*surf.DNSOverTLS).Quad101, "sb": (*surf.DNSOverTLS).SB,
	"forge": (*surf.DNSOverTLS).Forge, "libredns": (*surf.DNSOverTLS).LibreDNS,
}

func JaPresets() []string {
	names := make([]string, 0, len(jaPresets))
	for name := range jaPresets {
		names = append(names, name)
	}
	slices.Sort(names)
	return names
}

func Build(s directive.Spec, o Options) (*Client, error) {
	b := surf.NewClient().Builder()
	if s.Browser != "" {
		f, ok := families[s.Browser]
		if !ok {
			return nil, fmt.Errorf("unknown browser %q", s.Browser)
		}
		if s.Os != "" && !slices.Contains(f.oses, s.Os) {
			return nil, fmt.Errorf("%s is not available on %s", s.Browser, s.Os)
		}
		b = f.base(impersonateOs(b.Impersonate(), s.Os))
		if f.headers != nil {
			overrides := f.headers(s.Os)
			b = b.With(func(req *surf.Request) error {
				for name, value := range overrides {
					req.GetRequest().Header.Set(name, value)
				}
				return nil
			}, 1)
		}
	}
	if s.Ja != "" {
		preset, ok := jaPresets[s.Ja]
		if !ok {
			return nil, fmt.Errorf("unknown ja preset %q", s.Ja)
		}
		b = preset(b.JA())
	}
	if s.Http2Settings != nil {
		h := b.HTTP2Settings()
		applyHttp2(h, s.Http2Settings)
		if s.Browser == "" {
			b = h.Set()
		}
	}
	if s.Http3Settings != nil {
		b = http3Settings(b.HTTP3Settings(), s.Http3Settings)
	}
	b = b.Proxy(g.String(s.Proxy))
	if s.Dns != "" {
		b = b.DNS(g.String(s.Dns))
	}
	if s.DnsOverTls != "" {
		b = dnsOverTls(b.DNSOverTLS(), s.DnsOverTls)
	}
	if s.InterfaceAddr != "" {
		b = b.InterfaceAddr(g.String(s.InterfaceAddr))
	}
	if s.SecureTls || o.VerifyCertificates {
		b = b.SecureTLS()
	}
	if s.DisableKeepAlive {
		b = b.DisableKeepAlive()
	}
	if s.H2c {
		b = b.H2C()
	}
	switch s.ForceHttp {
	case "1":
		b = b.ForceHTTP1()
	case "2":
		b = b.ForceHTTP2()
	case "3":
		b = b.ForceHTTP3()
	}
	b = b.DisableCompression().
		With(func(c *surf.Client) error { return headerTimeout(c, o.ResponseHeaderTimeout) }, 1).
		With(finalize, math.MaxInt)
	built := b.Build()
	if built.IsErr() {
		return nil, fmt.Errorf("build client: %w", built.Err())
	}
	cli := built.Ok()
	return &Client{Key: s.Key(), transport: cli.Std().Transport, closer: cli}, nil
}

func impersonateOs(im *surf.Impersonate, os string) *surf.Impersonate {
	switch os {
	case "windows":
		return im.Windows()
	case "macos":
		return im.MacOS()
	case "linux":
		return im.Linux()
	case "android":
		return im.Android()
	case "ios":
		return im.IOS()
	}
	return im
}

func applyHttp2(h *surf.HTTP2Settings, s *directive.Http2) {
	set := func(v *uint32, apply func(uint32) *surf.HTTP2Settings) {
		if v != nil {
			apply(*v)
		}
	}
	set(s.HeaderTableSize, h.HeaderTableSize)
	set(s.EnablePush, h.EnablePush)
	set(s.MaxConcurrentStreams, h.MaxConcurrentStreams)
	set(s.InitialWindowSize, h.InitialWindowSize)
	set(s.MaxFrameSize, h.MaxFrameSize)
	set(s.MaxHeaderListSize, h.MaxHeaderListSize)
	set(s.NoRFC7540Priorities, h.NoRFC7540Priorities)
	set(s.ConnectionFlow, h.ConnectionFlow)
	set(s.InitialStreamID, h.InitialStreamID)
}

func http3Settings(h *surf.HTTP3Settings, s *directive.Http3) *surf.Builder {
	for _, key := range s.Order {
		switch key {
		case "qpackmaxtablecapacity":
			h.QpackMaxTableCapacity(*s.QpackMaxTableCapacity)
		case "maxfieldsectionsize":
			h.MaxFieldSectionSize(*s.MaxFieldSectionSize)
		case "qpackblockedstreams":
			h.QpackBlockedStreams(*s.QpackBlockedStreams)
		case "enableconnectprotocol":
			h.EnableConnectProtocol(*s.EnableConnectProtocol)
		case "settingsh3datagram":
			h.SettingsH3Datagram(*s.SettingsH3Datagram)
		case "h3datagram":
			h.H3Datagram(*s.H3Datagram)
		case "enablewebtransport":
			h.EnableWebtransport(*s.EnableWebtransport)
		case "grease":
			if s.Grease {
				h.Grease()
			}
		}
	}
	return h.Set()
}

func dnsOverTls(d *surf.DNSOverTLS, value string) *surf.Builder {
	name, addrs, custom := strings.Cut(value, "@")
	if !custom {
		return dotProviders[strings.ToLower(name)](d)
	}
	parts := strings.Split(addrs, ",")
	servers := make([]g.String, len(parts))
	for i, part := range parts {
		servers[i] = g.String(strings.TrimSpace(part))
	}
	return d.AddProvider(g.String(name), servers...)
}

func headerTimeout(c *surf.Client, d time.Duration) error {
	if t, ok := c.GetTransport().(*ehttp.Transport); ok && d > 0 {
		t.ResponseHeaderTimeout = d
	}
	return nil
}
