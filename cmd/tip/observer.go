package main

import (
	"github.com/isaackogan/tls-impersonate-proxy/internal/directive"
	"github.com/isaackogan/tls-impersonate-proxy/internal/impersonate"
	"github.com/isaackogan/tls-impersonate-proxy/internal/metrics"
	"github.com/isaackogan/tls-impersonate-proxy/internal/proxy"
)

type observer struct{ m *metrics.Metrics }

func (o observer) RequestStarted() {
	if o.m != nil {
		o.m.RequestStarted()
	}
}

func (o observer) RequestFinished(e proxy.RequestEvent) {
	if o.m != nil {
		o.m.RequestFinished(metrics.Request{Host: e.Host, Method: e.Method, Path: e.Path, Browser: e.Browser, Status: e.Status, Duration: e.Duration, BytesIn: e.BytesIn, BytesOut: e.BytesOut})
	}
}

func (o observer) ValidationFailed(d string) {
	if o.m != nil {
		o.m.ValidationFailed(d)
	}
}

func (o observer) UpstreamError(host, kind string) {
	if o.m != nil {
		o.m.UpstreamError(host, kind)
	}
}

func (o observer) TunnelOpened() {
	if o.m != nil {
		o.m.TunnelOpened()
	}
}

func (o observer) Route(host, path string) string {
	if o.m != nil {
		return o.m.Route(host, path)
	}
	return ""
}

func (o observer) CacheHit() {
	if o.m != nil {
		o.m.CacheHit()
	}
}

func (o observer) CacheMiss() {
	if o.m != nil {
		o.m.CacheMiss()
	}
}

func (o observer) ClientBuilt(s directive.Spec) {
	if o.m != nil {
		o.m.ClientBuilt(s.Browser, s.Os)
	}
}

func (o observer) ClientEvicted() {
	if o.m != nil {
		o.m.ClientEvicted()
	}
}

type clientSource struct{ cache *impersonate.Cache }

func (c clientSource) Get(s directive.Spec) (proxy.Client, error) { return c.cache.Get(s) }
