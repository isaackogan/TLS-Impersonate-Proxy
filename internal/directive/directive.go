package directive

import (
	"slices"
	"time"
)

const Prefix = "X-Tip-"

type Directive struct {
	Browser          string        `zog:"browser"`
	Os               []string      `zog:"os"`
	Ja               string        `zog:"ja"`
	Http2Settings    *Http2        `zog:"http2settings"`
	Http3Settings    *Http3        `zog:"http3settings"`
	ForceHttp        string        `zog:"forcehttp"`
	Proxy            string        `zog:"proxy"`
	Timeout          time.Duration `zog:"timeout"`
	Dns              string        `zog:"dns"`
	DnsOverTls       string        `zog:"dnsovertls"`
	InterfaceAddr    string        `zog:"interfaceaddr"`
	SecureTls        bool          `zog:"securetls"`
	DisableKeepAlive bool          `zog:"disablekeepalive"`
	H2c              bool          `zog:"h2c"`
	Scheme           string        `zog:"scheme"`
	Keep             []string      `zog:"keep"`
	Match            bool          `zog:"match"`
}

type Http2 struct {
	HeaderTableSize      *uint32 `zog:"headertablesize" json:"headertablesize,omitempty"`
	EnablePush           *uint32 `zog:"enablepush" json:"enablepush,omitempty"`
	MaxConcurrentStreams *uint32 `zog:"maxconcurrentstreams" json:"maxconcurrentstreams,omitempty"`
	InitialWindowSize    *uint32 `zog:"initialwindowsize" json:"initialwindowsize,omitempty"`
	MaxFrameSize         *uint32 `zog:"maxframesize" json:"maxframesize,omitempty"`
	MaxHeaderListSize    *uint32 `zog:"maxheaderlistsize" json:"maxheaderlistsize,omitempty"`
	NoRFC7540Priorities  *uint32 `zog:"norfc7540priorities" json:"norfc7540priorities,omitempty"`
	ConnectionFlow       *uint32 `zog:"connectionflow" json:"connectionflow,omitempty"`
	InitialStreamID      *uint32 `zog:"initialstreamid" json:"initialstreamid,omitempty"`
}

type Http3 struct {
	QpackMaxTableCapacity *uint64  `zog:"qpackmaxtablecapacity" json:"qpackmaxtablecapacity,omitempty"`
	MaxFieldSectionSize   *uint64  `zog:"maxfieldsectionsize" json:"maxfieldsectionsize,omitempty"`
	QpackBlockedStreams   *uint64  `zog:"qpackblockedstreams" json:"qpackblockedstreams,omitempty"`
	EnableConnectProtocol *uint64  `zog:"enableconnectprotocol" json:"enableconnectprotocol,omitempty"`
	SettingsH3Datagram    *uint64  `zog:"settingsh3datagram" json:"settingsh3datagram,omitempty"`
	H3Datagram            *uint64  `zog:"h3datagram" json:"h3datagram,omitempty"`
	EnableWebtransport    *uint64  `zog:"enablewebtransport" json:"enablewebtransport,omitempty"`
	Grease                bool     `zog:"grease" json:"grease,omitempty"`
	Order                 []string `zog:"order" json:"order,omitempty"`
}

func (d Directive) Resolve(pick func(n int) int) Directive {
	if len(d.Os) == 0 {
		return d
	}
	pool := d.Os
	if slices.Contains(pool, "random") {
		pool = concreteOs
	}
	d.Os = []string{pool[pick(len(pool))]}
	return d
}

func (d Directive) Spec() Spec {
	s := Spec{
		Browser:          d.Browser,
		Ja:               d.Ja,
		Http2Settings:    d.Http2Settings,
		Http3Settings:    d.Http3Settings,
		ForceHttp:        d.ForceHttp,
		Proxy:            d.Proxy,
		Dns:              d.Dns,
		DnsOverTls:       d.DnsOverTls,
		InterfaceAddr:    d.InterfaceAddr,
		SecureTls:        d.SecureTls,
		DisableKeepAlive: d.DisableKeepAlive,
		H2c:              d.H2c,
	}
	if len(d.Os) > 0 {
		s.Os = d.Os[0]
	}
	return s
}
