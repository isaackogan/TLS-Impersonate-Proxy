package directive

import "encoding/json"

type Spec struct {
	Browser          string `json:"browser,omitempty"`
	Os               string `json:"os,omitempty"`
	Ja               string `json:"ja,omitempty"`
	Http2Settings    *Http2 `json:"http2settings,omitempty"`
	Http3Settings    *Http3 `json:"http3settings,omitempty"`
	ForceHttp        string `json:"forcehttp,omitempty"`
	Proxy            string `json:"proxy,omitempty"`
	Dns              string `json:"dns,omitempty"`
	DnsOverTls       string `json:"dnsovertls,omitempty"`
	InterfaceAddr    string `json:"interfaceaddr,omitempty"`
	SecureTls        bool   `json:"securetls,omitempty"`
	DisableKeepAlive bool   `json:"disablekeepalive,omitempty"`
	H2c              bool   `json:"h2c,omitempty"`
}

func (s Spec) Key() string {
	encoded, _ := json.Marshal(s)
	return string(encoded)
}
