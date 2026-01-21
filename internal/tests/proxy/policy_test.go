package proxy_test

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/isaackogan/tls-impersonate-proxy/internal/directive"
	"github.com/isaackogan/tls-impersonate-proxy/internal/tests/testutil"
)

func TestRequireProxyAndAllowlistAreEnforced(t *testing.T) {
	policy, err := directive.NewPolicy(nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if policy, err = policy.ProxyHosts([]string{"127.0.0.1"}); err != nil {
		t.Fatal(err)
	}
	if policy, err = policy.RequireProxy(); err != nil {
		t.Fatal(err)
	}
	h := newHarnessWithPolicy(t, policy)
	resp, _ := h.get(t, h.upstream.URL+"/no-proxy", "X-Tip-Browser", "Chrome")
	if resp.StatusCode != 418 || resp.Header.Get("X-Tip-Error") != "Proxy: required by this proxy" {
		t.Errorf("without a proxy: %d %q", resp.StatusCode, resp.Header.Get("X-Tip-Error"))
	}
	resp, _ = h.get(t, h.upstream.URL+"/bad-host", "X-Tip-Proxy", "http://egress.example:3128")
	if resp.StatusCode != 418 || resp.Header.Get("X-Tip-Error") != "Proxy: host must be one of 127.0.0.1" {
		t.Errorf("host outside the allowlist: %d %q", resp.StatusCode, resp.Header.Get("X-Tip-Error"))
	}
	if len(h.upstream.Requests()) != 0 {
		t.Fatal("rejected requests must not reach the upstream")
	}
	hop := testutil.NewHop(t)
	resp, _ = h.get(t, h.upstream.URL+"/allowed", "X-Tip-Proxy", "http://"+hop.Addr)
	if resp.StatusCode != 200 || len(hop.Requests()) != 1 {
		t.Errorf("allowed hop: %d, hop saw %d", resp.StatusCode, len(hop.Requests()))
	}
	h.obs.mu.Lock()
	failures := slices.Clone(h.obs.failures)
	h.obs.mu.Unlock()
	if n := len(slices.DeleteFunc(failures, func(d string) bool { return d != "Proxy" })); n != 2 {
		t.Errorf("validation failures on Proxy: %d in %v", n, failures)
	}
}

func TestReadyzFailsWhileDraining(t *testing.T) {
	h := newHarness(t, nil)
	if resp, err := http.Get(h.proxy.URL + "/readyz"); err != nil || resp.StatusCode != 200 {
		t.Fatalf("ready before drain: %v %v", resp, err)
	}
	started := make(chan struct{})
	finished := make(chan int, 1)
	go func() {
		req, _ := http.NewRequest("GET", h.upstream.URL+"/slow", nil)
		req.Header.Set("X-Upstream-Delay", "600ms")
		close(started)
		resp, err := h.client.Do(req)
		if err != nil {
			finished <- 0
			return
		}
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
		finished <- resp.StatusCode
	}()
	<-started
	time.Sleep(150 * time.Millisecond)
	drained := make(chan error, 1)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		drained <- h.server.Drain(ctx)
	}()
	deadline := time.Now().Add(2 * time.Second)
	for {
		resp, err := http.Get(h.proxy.URL + "/readyz")
		if err == nil && resp.StatusCode == 503 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("readyz never turned 503: %v %v", resp, err)
		}
		time.Sleep(20 * time.Millisecond)
	}
	rec := httptest.NewRecorder()
	h.server.ReadyHandler().ServeHTTP(rec, httptest.NewRequest("GET", "/readyz", nil))
	if rec.Code != 503 || !strings.Contains(rec.Body.String(), "draining") {
		t.Fatalf("admin readyz during drain: %d %q", rec.Code, rec.Body.String())
	}
	if status := <-finished; status != 200 {
		t.Fatalf("in-flight request finished with %d", status)
	}
	if err := <-drained; err != nil {
		t.Fatal(err)
	}
}
