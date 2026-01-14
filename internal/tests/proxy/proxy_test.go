package proxy_test

import (
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/isaackogan/tls-impersonate-proxy/internal/directive"
	"github.com/isaackogan/tls-impersonate-proxy/internal/impersonate"
	"github.com/isaackogan/tls-impersonate-proxy/internal/proxy"
	"github.com/isaackogan/tls-impersonate-proxy/internal/tests/testutil"
)

type recording struct {
	mu       sync.Mutex
	events   []proxy.RequestEvent
	failures []string
	tunnels  int
}

func (r *recording) RequestStarted() {}
func (r *recording) RequestFinished(e proxy.RequestEvent) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.events = append(r.events, e)
}
func (r *recording) ValidationFailed(d string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.failures = append(r.failures, d)
}
func (r *recording) UpstreamError(string, string) {}
func (r *recording) TunnelOpened() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.tunnels++
}
func (r *recording) Route(string, string) string { return "" }

func (r *recording) last(t *testing.T) proxy.RequestEvent {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		r.mu.Lock()
		n := len(r.events)
		if n > 0 {
			ev := r.events[n-1]
			r.mu.Unlock()
			return ev
		}
		r.mu.Unlock()
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("no request event")
	return proxy.RequestEvent{}
}

func (r *recording) tunnelCount() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.tunnels
}

type cacheSource struct{ *impersonate.Cache }

func (c cacheSource) Get(s directive.Spec) (proxy.Client, error) { return c.Cache.Get(s) }

type harness struct {
	upstream *testutil.Upstream
	proxy    *httptest.Server
	server   *proxy.Server
	client   *http.Client
	obs      *recording
	logs     *testutil.SyncBuffer
}

func newHarness(t *testing.T, mutate func(*proxy.Options)) *harness {
	t.Helper()
	policy, _ := directive.NewPolicy(nil, nil)
	return build(t, policy, mutate)
}

func newHarnessWithPolicy(t *testing.T, policy directive.Policy) *harness {
	t.Helper()
	return build(t, policy, nil)
}

func build(t *testing.T, policy directive.Policy, mutate func(*proxy.Options)) *harness {
	t.Helper()
	ca, pool := testutil.TempCA(t)
	logs := &testutil.SyncBuffer{}
	log := slog.New(slog.NewJSONHandler(logs, &slog.HandlerOptions{Level: slog.LevelDebug}))
	cache := impersonate.NewCache(impersonate.CacheOptions{Max: 8, IdleTtl: time.Hour}, func(s directive.Spec) (*impersonate.Client, error) {
		return impersonate.Build(s, impersonate.Options{ResponseHeaderTimeout: 5 * time.Second})
	}, nil)
	t.Cleanup(cache.Close)
	opts := proxy.Options{CA: ca, CertCacheSize: 16, Encoding: "negotiate", Timeout: 5 * time.Second, ServeCa: true}
	if mutate != nil {
		mutate(&opts)
	}
	obs := &recording{}
	srv, err := proxy.New(opts, policy, cacheSource{cache}, obs, log)
	if err != nil {
		t.Fatal(err)
	}
	ps := httptest.NewServer(srv)
	t.Cleanup(ps.Close)
	return &harness{upstream: testutil.NewUpstream(t), proxy: ps, server: srv, client: testutil.ProxyClient(t, ps.URL, pool), obs: obs, logs: logs}
}

func (h *harness) get(t *testing.T, url string, headers ...string) (*http.Response, map[string]any) {
	t.Helper()
	req, _ := http.NewRequest("GET", url, nil)
	for i := 0; i < len(headers); i += 2 {
		req.Header.Set(headers[i], headers[i+1])
	}
	resp, err := h.client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	var echoed map[string]any
	json.Unmarshal(body, &echoed)
	return resp, echoed
}

func echoedHeader(echoed map[string]any, name string) string {
	headers, _ := echoed["headers"].(map[string]any)
	values, _ := headers[name].([]any)
	if len(values) == 0 {
		return ""
	}
	s, _ := values[0].(string)
	return s
}

func TestMITMImpersonatesAndStrips(t *testing.T) {
	h := newHarness(t, nil)
	resp, echoed := h.get(t, h.upstream.URL+"/a", "X-Tip-Browser", "Chrome", "X-Tip-Os", "Linux", "Accept", "application/json", "X-Tip-Keep", "Accept")
	if resp.StatusCode != 200 {
		t.Fatalf("status %d", resp.StatusCode)
	}
	if ua := echoedHeader(echoed, "User-Agent"); !strings.Contains(ua, "Chrome/152") || !strings.Contains(ua, "Linux") {
		t.Fatalf("ua %q", ua)
	}
	if echoedHeader(echoed, "Accept") != "application/json" {
		t.Fatalf("keep failed: %v", echoed)
	}
	if echoed["proto"] != "HTTP/2.0" {
		t.Fatalf("proto %v", echoed["proto"])
	}
	for name := range echoed["headers"].(map[string]any) {
		if strings.HasPrefix(strings.ToLower(name), "x-tip-") {
			t.Fatalf("leaked %s", name)
		}
	}
	if h.obs.tunnelCount() != 1 {
		t.Fatalf("tunnels %d", h.obs.tunnelCount())
	}
	ev := h.obs.last(t)
	if ev.Status != 200 || ev.Browser != "chrome" || ev.BytesOut == 0 || ev.Method != "GET" {
		t.Fatalf("event %+v", ev)
	}
	if !strings.Contains(h.logs.String(), `"outbound request"`) || !strings.Contains(h.logs.String(), "user-agent: Mozilla") {
		t.Fatalf("debug log lacks outbound headers:\n%s", h.logs.String())
	}
}

func TestPlainModeSchemeUpgrade(t *testing.T) {
	h := newHarness(t, nil)
	plain := "http" + strings.TrimPrefix(h.upstream.URL, "https")
	resp, echoed := h.get(t, plain+"/b", "X-Tip-Scheme", "https", "X-Tip-Browser", "Firefox")
	if resp.StatusCode != 200 || !strings.Contains(echoedHeader(echoed, "User-Agent"), "Firefox/148") {
		t.Fatalf("status %d ua %q", resp.StatusCode, echoedHeader(echoed, "User-Agent"))
	}
	if h.obs.tunnelCount() != 0 {
		t.Fatal("plain mode must not open a tunnel")
	}
}

func TestMatchInfersFromUserAgent(t *testing.T) {
	h := newHarness(t, nil)
	_, echoed := h.get(t, h.upstream.URL+"/m", "X-Tip-Match", "true", "User-Agent", "Mozilla/5.0 (X11; Linux x86_64; rv:120.0) Gecko/20100101 Firefox/120.0")
	if ua := echoedHeader(echoed, "User-Agent"); !strings.Contains(ua, "Firefox/148") || !strings.Contains(ua, "Linux") {
		t.Fatalf("ua %q", ua)
	}
	_, echoed = h.get(t, h.upstream.URL+"/m2", "X-Tip-Match", "true", "User-Agent", "curl/8.4.0")
	if ua := echoedHeader(echoed, "User-Agent"); ua != "curl/8.4.0" {
		t.Fatalf("ua %q", ua)
	}
}

func TestTeapot(t *testing.T) {
	h := newHarness(t, nil)
	resp, _ := h.get(t, h.upstream.URL+"/t", "X-Tip-Browser", "Safari", "X-Tip-Timeout", "never")
	if resp.StatusCode != 418 || resp.ContentLength != 0 || resp.Header.Get("X-Tip-Error-Count") != "2" {
		t.Fatalf("status %d len %d headers %v", resp.StatusCode, resp.ContentLength, resp.Header)
	}
	if len(h.upstream.Requests()) != 0 {
		t.Fatal("teapot must not reach upstream")
	}
	if ev := h.obs.last(t); ev.Status != 418 {
		t.Fatalf("event %+v", ev)
	}
}

func TestBadGateway(t *testing.T) {
	h := newHarness(t, nil)
	dead := testutil.NewUpstream(t)
	dead.Close()
	resp, _ := h.get(t, dead.URL+"/x", "X-Tip-Browser", "Chrome")
	if resp.StatusCode != 502 || !strings.HasPrefix(resp.Header.Get("X-Tip-Error"), "dial:") {
		t.Fatalf("status %d headers %v", resp.StatusCode, resp.Header)
	}
}

func TestEncodingNegotiation(t *testing.T) {
	cases := []struct {
		name, mode, accept, wantEncoding string
	}{
		{"negotiate keeps accepted", "negotiate", "gzip", "gzip"},
		{"negotiate decodes unaccepted", "negotiate", "identity", ""},
		{"decode always", "decode", "gzip", ""},
		{"passthrough always", "passthrough", "identity", "gzip"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := newHarness(t, func(o *proxy.Options) { o.Encoding = tc.mode })
			req, _ := http.NewRequest("GET", h.upstream.URL+"/enc", nil)
			req.Header.Set("Accept-Encoding", tc.accept)
			req.Header.Set("X-Upstream-Encoding", "gzip")
			req.Header.Set("X-Tip-Browser", "Chrome")
			resp, err := h.client.Do(req)
			if err != nil {
				t.Fatal(err)
			}
			body, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			if resp.Header.Get("Content-Encoding") != tc.wantEncoding {
				t.Fatalf("encoding %q, want %q", resp.Header.Get("Content-Encoding"), tc.wantEncoding)
			}
			if tc.wantEncoding == "" && !json.Valid(body) {
				t.Fatalf("expected decoded json, got %q", body)
			}
		})
	}
}

func TestProxyAuth(t *testing.T) {
	h := newHarness(t, func(o *proxy.Options) { o.Auth = proxy.Auth{Realm: "tip", Users: map[string]string{"alice": "secret"}} })
	req, _ := http.NewRequest("GET", h.upstream.URL+"/auth", nil)
	if _, err := h.client.Do(req); err == nil || !strings.Contains(err.Error(), "Proxy Authentication Required") {
		t.Fatalf("CONNECT without credentials: err %v", err)
	}
	plain := "http" + strings.TrimPrefix(h.upstream.URL, "https")
	resp, _ := h.get(t, plain+"/auth", "X-Tip-Scheme", "https")
	if resp.StatusCode != 407 {
		t.Fatalf("plain request without credentials: status %d", resp.StatusCode)
	}
	pool := h.client.Transport.(*http.Transport).TLSClientConfig.RootCAs
	withCreds := testutil.ProxyClient(t, strings.Replace(h.proxy.URL, "http://", "http://alice:secret@", 1), pool)
	req, _ = http.NewRequest("GET", h.upstream.URL+"/auth", nil)
	resp, err := withCreds.Do(req)
	if err != nil || resp.StatusCode != 200 {
		t.Fatalf("CONNECT with credentials: status %v err %v\nlogs:\n%s", resp, err, h.logs.String())
	}
	resp.Body.Close()
	if got := h.upstream.Last(t).Header.Get("Proxy-Authorization"); got != "" {
		t.Fatalf("leaked %q", got)
	}
	req, _ = http.NewRequest("GET", plain+"/auth", nil)
	req.Header.Set("X-Tip-Scheme", "https")
	resp, err = withCreds.Do(req)
	if err != nil || resp.StatusCode != 200 {
		t.Fatalf("plain request with credentials: status %v err %v", resp, err)
	}
	resp.Body.Close()
}

func TestNonProxyEndpoints(t *testing.T) {
	h := newHarness(t, nil)
	resp, err := http.Get(h.proxy.URL + "/ca.pem")
	if err != nil || resp.StatusCode != 200 {
		t.Fatalf("ca %v %v", resp, err)
	}
	body, _ := io.ReadAll(resp.Body)
	if !strings.HasPrefix(string(body), "-----BEGIN CERTIFICATE-----") {
		t.Fatalf("body %q", body)
	}
	resp, _ = http.Get(h.proxy.URL + "/healthz")
	if resp.StatusCode != 200 {
		t.Fatalf("healthz %d", resp.StatusCode)
	}
}
