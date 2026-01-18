package config

import (
	"errors"
	"net"
	"regexp"
	"time"

	z "github.com/Oudwins/zog"
)

var (
	routeName = regexp.MustCompile(`^[a-z][a-z0-9_]*$`)
	labelName = regexp.MustCompile(`^[a-zA-Z_][a-zA-Z0-9_]*$`)
)

var defaultRedact = []string{"Authorization", "Proxy-Authorization", "Cookie", "Set-Cookie"}

func duration() *z.NumberSchema[time.Duration] {
	return z.IntLike[time.Duration](z.WithCoercer(func(v any) (any, error) {
		s, ok := v.(string)
		if !ok {
			return nil, errors.New("must be a duration with a unit, such as 30s or 1m")
		}
		return time.ParseDuration(s)
	}))
}

func listenAddr() *z.StringSchema[string] {
	return z.String().TestFunc(func(s *string, _ z.Ctx) bool {
		_, _, err := net.SplitHostPort(*s)
		return err == nil
	}, z.Message("must be host:port"))
}

func flag(def bool) *z.BoolSchema[bool] { return z.Bool().Default(def) }

func stringMap() *z.MapSchema[string, string] {
	return z.EXPERIMENTAL_MAP[string, string](z.String().Min(1), z.String().Min(1))
}

var schema = z.Struct(z.Shape{
	"server": z.Struct(z.Shape{
		"listen":            listenAddr().Default(":8080"),
		"maxConnections":    z.Int().GTE(0),
		"readHeaderTimeout": duration().Default(10 * time.Second).GT(0),
		"idleTimeout":       duration().Default(90 * time.Second).GT(0),
		"maxHeaderBytes":    z.Int().Default(1 << 20).GT(0),
		"shutdownGrace":     duration().Default(15 * time.Second).GT(0),
		"serveCa":           flag(true),
		"serveProfiles":     flag(true),
	}),
	"tls": z.Struct(z.Shape{
		"caCert":        z.String().Default("./ca.pem").Min(1),
		"caKey":         z.String().Default("./ca.key").Min(1),
		"certCacheSize": z.Int().Default(4096).GT(0),
		"clientHttp2":   flag(false),
	}),
	"upstream": z.Struct(z.Shape{
		"verifyCertificates": flag(false),
		"timeout":            duration().Default(30 * time.Second).GT(0),
	}),
	"directives": z.Struct(z.Shape{
		"defaults": stringMap(),
		"deny":     z.Slice(z.String().Min(1)),
	}),
	"clients": z.Struct(z.Shape{
		"max":     z.Int().Default(4096).GT(0),
		"idleTtl": duration().Default(10 * time.Minute).GT(0),
	}),
	"encoding": z.Struct(z.Shape{
		"mode": z.String().Default("negotiate").OneOf([]string{"negotiate", "decode", "passthrough"}),
	}),
	"auth": z.Struct(z.Shape{
		"realm": z.String().Default("tip").Min(1),
		"users": stringMap(),
	}),
	"logging": z.Struct(z.Shape{
		"level":  z.String().Default("info").OneOf([]string{"debug", "info", "warn", "error"}),
		"format": z.String().Default("json").OneOf([]string{"json", "text"}),
		"redact": z.Slice(z.String().Min(1)),
	}),
	"metrics": z.Struct(z.Shape{
		"enabled": flag(true),
		"listen":  listenAddr().Default(":9090"),
		"path":    z.String().Default("/metrics").HasPrefix("/"),
		"collectors": z.Struct(z.Shape{
			"requests":         flag(true),
			"latency":          flag(true),
			"bandwidth":        flag(true),
			"upstreamErrors":   flag(true),
			"validationErrors": flag(true),
			"clients":          flag(true),
			"tunnels":          flag(true),
		}),
		"routes": z.Slice(z.Struct(z.Shape{
			"name":    z.String().Required().Match(routeName, z.Message("must match ^[a-z][a-z0-9_]*$")),
			"host":    z.String().Required().Min(1),
			"path":    z.String().Required().HasPrefix("/"),
			"capture": z.Slice(z.String().Match(labelName, z.Message("must be a valid label name"))),
		})),
	}),
})
