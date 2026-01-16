package directive

import (
	"errors"
	"net"
	"net/url"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	z "github.com/Oudwins/zog"
)

type enum struct {
	official []string
	lower    []string
}

func newEnum(official ...string) enum {
	e := enum{official: official, lower: make([]string, len(official))}
	for i, v := range official {
		e.lower[i] = strings.ToLower(v)
	}
	return e
}

func (e enum) message() string { return "must be one of " + strings.Join(e.official, ", ") }

func (e enum) schema() *z.StringSchema[string] {
	return z.String().Transform(lowercase).OneOf(e.lower, z.Message(e.message()))
}

func lowercase(s *string, _ z.Ctx) error {
	*s = strings.ToLower(strings.TrimSpace(*s))
	return nil
}

var (
	browsers     = newEnum("Chrome", "Firefox", "Edge", "Random")
	oses         = newEnum("Windows", "MacOS", "Linux", "Android", "IOS", "Random")
	concreteOs   = oses.lower[:5]
	jaPresets    = newEnum("Android", "Chrome", "Chrome58", "Chrome62", "Chrome70", "Chrome72", "Chrome83", "Chrome87", "Chrome96", "Chrome100", "Chrome102", "Chrome106", "Chrome120", "Chrome120PQ", "Chrome152", "Edge", "Edge85", "Edge106", "Firefox", "Firefox55", "Firefox56", "Firefox63", "Firefox65", "Firefox99", "Firefox102", "Firefox105", "Firefox120", "Firefox148", "IOS", "IOS11", "IOS12", "IOS13", "IOS14", "Randomized", "RandomizedALPN", "RandomizedNoALPN", "Safari")
	dotProviders = newEnum("AdGuard", "Google", "Cloudflare", "Quad9", "Switch", "CIRAShield", "Ali", "Quad101", "SB", "Forge", "LibreDNS")
	proxySchemes = []string{"http", "https", "socks4", "socks4a", "socks5", "socks5h"}
	profileID    = regexp.MustCompile(`^[0-9a-f]{12}$`)
)

func JaPresets() []string { return slices.Clone(jaPresets.lower) }

func uint32s() *z.NumberSchema[uint32] {
	return z.UintLike[uint32](z.WithCoercer(func(v any) (any, error) {
		s, _ := v.(string)
		n, err := strconv.ParseUint(strings.TrimSpace(s), 10, 32)
		if err != nil {
			return nil, errors.New("must be an unsigned 32-bit integer")
		}
		return uint32(n), nil
	}))
}

func uint64s() *z.NumberSchema[uint64] {
	return z.UintLike[uint64](z.WithCoercer(func(v any) (any, error) {
		s, _ := v.(string)
		n, err := strconv.ParseUint(strings.TrimSpace(s), 10, 64)
		if err != nil {
			return nil, errors.New("must be an unsigned 64-bit integer")
		}
		return n, nil
	}))
}

func boolean() *z.BoolSchema[bool] {
	return z.Bool(z.WithCoercer(func(v any) (any, error) {
		s, _ := v.(string)
		b, err := strconv.ParseBool(strings.TrimSpace(s))
		if err != nil {
			return nil, errors.New("must be true or false")
		}
		return b, nil
	}))
}

func duration() *z.NumberSchema[time.Duration] {
	return z.IntLike[time.Duration](z.WithCoercer(func(v any) (any, error) {
		s, _ := v.(string)
		d, err := time.ParseDuration(strings.TrimSpace(s))
		if err != nil {
			return nil, errors.New("must be a duration such as 15s or 500ms")
		}
		return d, nil
	}))
}

func hostPort() *z.StringSchema[string] {
	return z.String().Trim().TestFunc(func(s *string, _ z.Ctx) bool {
		_, _, err := net.SplitHostPort(*s)
		return err == nil
	}, z.Message("must be host:port"))
}

func proxyURL() *z.StringSchema[string] {
	return z.String().Trim().TestFunc(func(s *string, _ z.Ctx) bool {
		u, err := url.Parse(*s)
		return err == nil && u.Host != "" && slices.Contains(proxySchemes, strings.ToLower(u.Scheme))
	}, z.Message("must be an absolute URL with scheme "+strings.Join(proxySchemes, ", "))).Transform(func(s *string, _ z.Ctx) error {
		u, err := url.Parse(*s)
		if err != nil {
			return nil
		}
		u.Scheme = strings.ToLower(u.Scheme)
		u.Host = strings.ToLower(u.Host)
		*s = u.String()
		return nil
	})
}

func dnsOverTls() *z.StringSchema[string] {
	return z.String().Trim().TestFunc(func(s *string, _ z.Ctx) bool {
		name, addrs, custom := strings.Cut(*s, "@")
		if !custom {
			return slices.Contains(dotProviders.lower, strings.ToLower(name))
		}
		if name == "" {
			return false
		}
		for _, addr := range strings.Split(addrs, ",") {
			if _, _, err := net.SplitHostPort(strings.TrimSpace(addr)); err != nil {
				return false
			}
		}
		return true
	}, z.Message(dotProviders.message()+" or servername@host:port,host:port"))
}

var h2Shape = z.Shape{
	"headerTableSize":      z.Ptr(uint32s()),
	"enablePush":           z.Ptr(uint32s()),
	"maxConcurrentStreams": z.Ptr(uint32s()),
	"initialWindowSize":    z.Ptr(uint32s()),
	"maxFrameSize":         z.Ptr(uint32s()),
	"maxHeaderListSize":    z.Ptr(uint32s()),
	"noRFC7540Priorities":  z.Ptr(uint32s()),
	"connectionFlow":       z.Ptr(uint32s()),
	"initialStreamID":      z.Ptr(uint32s()),
}

var h3Shape = z.Shape{
	"qpackMaxTableCapacity": z.Ptr(uint64s()),
	"maxFieldSectionSize":   z.Ptr(uint64s()),
	"qpackBlockedStreams":   z.Ptr(uint64s()),
	"enableConnectProtocol": z.Ptr(uint64s()),
	"settingsH3Datagram":    z.Ptr(uint64s()),
	"h3Datagram":            z.Ptr(uint64s()),
	"enableWebtransport":    z.Ptr(uint64s()),
	"grease":                boolean(),
	"order":                 z.Slice(z.String()),
}

var shape = z.Shape{
	"browser":          z.Slice(browsers.schema()),
	"os":               z.Slice(oses.schema()),
	"ja":               jaPresets.schema(),
	"http2Settings":    z.Ptr(z.Struct(h2Shape)),
	"http3Settings":    z.Ptr(z.Struct(h3Shape)),
	"forceHttp":        z.String().Trim().OneOf([]string{"1", "2", "3"}, z.Message("must be 1, 2 or 3")),
	"proxy":            proxyURL(),
	"timeout":          duration().GT(0, z.Message("must be positive")),
	"dns":              hostPort(),
	"dnsOverTls":       dnsOverTls(),
	"interfaceAddr":    z.String().Trim().Min(1),
	"secureTls":        boolean(),
	"disableKeepAlive": boolean(),
	"h2c":              boolean(),
	"scheme":           newEnum("https").schema(),
	"keep":             z.Slice(z.String().Trim().Transform(lowercase).Min(1, z.Message("header names must not be empty"))),
	"match":            boolean(),
	"profile":          z.String().Trim().Transform(lowercase).Match(profileID, z.Message("must be a 12-character hex id from /profiles")),
}

var schema = z.Struct(shape).TestFunc(func(v any, _ z.Ctx) bool {
	d := v.(*Directive)
	return d.Profile == "" || (len(d.Browser) == 0 && len(d.Os) == 0 && !d.Match)
}, z.Message("cannot be combined with Browser, Os or Match"), z.IssuePath([]string{"profile"}))

var (
	official = map[string]string{}
	known    map[string]struct{}
	kvKeys   = map[string]map[string]struct{}{}
)

func init() {
	known = register("Browser", "Os", "Ja", "Http2Settings", "Http3Settings", "ForceHttp", "Proxy", "Timeout", "Dns", "DnsOverTls", "InterfaceAddr", "SecureTls", "DisableKeepAlive", "H2c", "Scheme", "Keep", "Match", "Profile")
	kvKeys["http2settings"] = register("HeaderTableSize", "EnablePush", "MaxConcurrentStreams", "InitialWindowSize", "MaxFrameSize", "MaxHeaderListSize", "NoRFC7540Priorities", "ConnectionFlow", "InitialStreamID")
	kvKeys["http3settings"] = register("QpackMaxTableCapacity", "MaxFieldSectionSize", "QpackBlockedStreams", "EnableConnectProtocol", "SettingsH3Datagram", "H3Datagram", "EnableWebtransport", "Grease")
}

func register(names ...string) map[string]struct{} {
	set := make(map[string]struct{}, len(names))
	for _, name := range names {
		key := strings.ToLower(name)
		official[key] = name
		set[key] = struct{}{}
	}
	return set
}

func Names() []string {
	names := make([]string, 0, len(known))
	for key := range known {
		names = append(names, official[key])
	}
	slices.Sort(names)
	return names
}

func isKnown(key string) bool {
	_, ok := known[key]
	return ok
}

func officialName(key string) string {
	if name, ok := official[key]; ok {
		return name
	}
	return key
}
