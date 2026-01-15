package config

import "time"

type Config struct {
	Server     Server     `zog:"server"`
	Tls        Tls        `zog:"tls"`
	Upstream   Upstream   `zog:"upstream"`
	Directives Directives `zog:"directives"`
	Clients    Clients    `zog:"clients"`
	Encoding   Encoding   `zog:"encoding"`
	Auth       Auth       `zog:"auth"`
	Logging    Logging    `zog:"logging"`
	Metrics    Metrics    `zog:"metrics"`
}

type Server struct {
	Listen            string        `zog:"listen"`
	MaxConnections    int           `zog:"max_connections"`
	ReadHeaderTimeout time.Duration `zog:"read_header_timeout"`
	IdleTimeout       time.Duration `zog:"idle_timeout"`
	MaxHeaderBytes    int           `zog:"max_header_bytes"`
	ShutdownGrace     time.Duration `zog:"shutdown_grace"`
	ServeCa           bool          `zog:"serve_ca"`
	ServeProfiles     bool          `zog:"serve_profiles"`
}

type Tls struct {
	CaCert        string `zog:"ca_cert"`
	CaKey         string `zog:"ca_key"`
	CertCacheSize int    `zog:"cert_cache_size"`
	ClientHttp2   bool   `zog:"client_http2"`
}

type Upstream struct {
	VerifyCertificates bool          `zog:"verify_certificates"`
	Timeout            time.Duration `zog:"timeout"`
}

type Directives struct {
	Defaults map[string]string `zog:"defaults"`
	Deny     []string          `zog:"deny"`
}

type Clients struct {
	Max     int           `zog:"max"`
	IdleTtl time.Duration `zog:"idle_ttl"`
}

type Encoding struct {
	Mode string `zog:"mode"`
}

type Auth struct {
	Realm string            `zog:"realm"`
	Users map[string]string `zog:"users"`
}

type Logging struct {
	Level  string   `zog:"level"`
	Format string   `zog:"format"`
	Redact []string `zog:"redact"`
}

type Metrics struct {
	Enabled    bool       `zog:"enabled"`
	Listen     string     `zog:"listen"`
	Path       string     `zog:"path"`
	Collectors Collectors `zog:"collectors"`
	Routes     []Route    `zog:"routes"`
}

type Collectors struct {
	Requests         bool `zog:"requests"`
	Latency          bool `zog:"latency"`
	Bandwidth        bool `zog:"bandwidth"`
	UpstreamErrors   bool `zog:"upstream_errors"`
	ValidationErrors bool `zog:"validation_errors"`
	Clients          bool `zog:"clients"`
	Tunnels          bool `zog:"tunnels"`
}

type Route struct {
	Name    string   `zog:"name"`
	Host    string   `zog:"host"`
	Path    string   `zog:"path"`
	Capture []string `zog:"capture"`
}
