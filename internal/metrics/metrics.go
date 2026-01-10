package metrics

import (
	"net/http"
	"strconv"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

type Options struct {
	Collectors Collectors
	Routes     []Route
}

type Collectors struct {
	Requests         bool
	Latency          bool
	Bandwidth        bool
	UpstreamErrors   bool
	ValidationErrors bool
	Clients          bool
	Tunnels          bool
}

type Request struct {
	Host     string
	Method   string
	Path     string
	Browser  string
	Status   int
	Duration time.Duration
	BytesIn  int64
	BytesOut int64
}

type Metrics struct {
	registry         *prometheus.Registry
	matcher          *Matcher
	captures         []string
	requests         *prometheus.CounterVec
	inflight         prometheus.Gauge
	latency          *prometheus.HistogramVec
	bandwidth        *prometheus.CounterVec
	upstreamErrors   *prometheus.CounterVec
	validationErrors *prometheus.CounterVec
	clientsActive    prometheus.Gauge
	clientBuilds     *prometheus.CounterVec
	clientEvictions  prometheus.Counter
	cacheHits        prometheus.Counter
	cacheMisses      prometheus.Counter
	tunnels          prometheus.Counter
}

func New(o Options) (*Metrics, error) {
	matcher, err := NewMatcher(o.Routes)
	if err != nil {
		return nil, err
	}
	m := &Metrics{registry: prometheus.NewRegistry(), matcher: matcher, captures: matcher.Captures()}
	f := promauto.With(m.registry)
	c := o.Collectors
	if c.Requests {
		m.requests = f.NewCounterVec(prometheus.CounterOpts{Name: "tip_requests_total", Help: "Requests handled."}, m.labels("host", "method", "status", "browser", "route"))
		m.inflight = f.NewGauge(prometheus.GaugeOpts{Name: "tip_requests_inflight", Help: "Requests being handled."})
	}
	if c.Latency {
		m.latency = f.NewHistogramVec(prometheus.HistogramOpts{Name: "tip_request_duration_seconds", Help: "Time from request parsed to body closed.", Buckets: prometheus.DefBuckets}, m.labels("host", "route"))
	}
	if c.Bandwidth {
		m.bandwidth = f.NewCounterVec(prometheus.CounterOpts{Name: "tip_bandwidth_bytes_total", Help: "Body bytes by direction."}, m.labels("host", "route", "direction"))
	}
	if c.UpstreamErrors {
		m.upstreamErrors = f.NewCounterVec(prometheus.CounterOpts{Name: "tip_upstream_errors_total", Help: "Upstream failures by kind."}, []string{"host", "kind"})
	}
	if c.ValidationErrors {
		m.validationErrors = f.NewCounterVec(prometheus.CounterOpts{Name: "tip_validation_errors_total", Help: "Directive validation failures."}, []string{"directive"})
	}
	if c.Clients {
		m.clientsActive = f.NewGauge(prometheus.GaugeOpts{Name: "tip_clients_active", Help: "Cached surf clients."})
		m.clientBuilds = f.NewCounterVec(prometheus.CounterOpts{Name: "tip_client_builds_total", Help: "Surf clients built."}, []string{"browser", "os"})
		m.clientEvictions = f.NewCounter(prometheus.CounterOpts{Name: "tip_client_evictions_total", Help: "Surf clients evicted."})
		m.cacheHits = f.NewCounter(prometheus.CounterOpts{Name: "tip_client_cache_hits_total", Help: "Client cache hits."})
		m.cacheMisses = f.NewCounter(prometheus.CounterOpts{Name: "tip_client_cache_misses_total", Help: "Client cache misses."})
	}
	if c.Tunnels {
		m.tunnels = f.NewCounter(prometheus.CounterOpts{Name: "tip_tunnels_total", Help: "CONNECT tunnels opened."})
	}
	return m, nil
}

func (m *Metrics) labels(fixed ...string) []string { return append(fixed, m.captures...) }

func (m *Metrics) Handler() http.Handler {
	return promhttp.HandlerFor(m.registry, promhttp.HandlerOpts{})
}

func (m *Metrics) Route(host, path string) string {
	name, _ := m.matcher.Match(host, path)
	return name
}

func (m *Metrics) RequestStarted() {
	if m.inflight != nil {
		m.inflight.Inc()
	}
}

func (m *Metrics) RequestFinished(r Request) {
	route, captured := m.matcher.Match(r.Host, r.Path)
	values := func(fixed ...string) []string {
		for _, name := range m.captures {
			fixed = append(fixed, captured[name])
		}
		return fixed
	}
	if m.requests != nil {
		m.requests.WithLabelValues(values(r.Host, r.Method, strconv.Itoa(r.Status), r.Browser, route)...).Inc()
		m.inflight.Dec()
	}
	if m.latency != nil {
		m.latency.WithLabelValues(values(r.Host, route)...).Observe(r.Duration.Seconds())
	}
	if m.bandwidth != nil {
		m.bandwidth.WithLabelValues(values(r.Host, route, "in")...).Add(float64(r.BytesIn))
		m.bandwidth.WithLabelValues(values(r.Host, route, "out")...).Add(float64(r.BytesOut))
	}
}

func (m *Metrics) ValidationFailed(directive string) {
	if m.validationErrors != nil {
		m.validationErrors.WithLabelValues(directive).Inc()
	}
}

func (m *Metrics) UpstreamError(host, kind string) {
	if m.upstreamErrors != nil {
		m.upstreamErrors.WithLabelValues(host, kind).Inc()
	}
}

func (m *Metrics) TunnelOpened() {
	if m.tunnels != nil {
		m.tunnels.Inc()
	}
}

func (m *Metrics) CacheHit() {
	if m.cacheHits != nil {
		m.cacheHits.Inc()
	}
}

func (m *Metrics) CacheMiss() {
	if m.cacheMisses != nil {
		m.cacheMisses.Inc()
	}
}

func (m *Metrics) ClientBuilt(browser, os string) {
	if m.clientBuilds != nil {
		m.clientBuilds.WithLabelValues(browser, os).Inc()
		m.clientsActive.Inc()
	}
}

func (m *Metrics) ClientEvicted() {
	if m.clientEvictions != nil {
		m.clientEvictions.Inc()
		m.clientsActive.Dec()
	}
}
