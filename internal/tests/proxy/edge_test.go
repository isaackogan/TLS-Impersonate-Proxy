package proxy_test

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/coder/websocket"

	"github.com/isaackogan/tls-impersonate-proxy/internal/directive"
	"github.com/isaackogan/tls-impersonate-proxy/internal/proxy"
)

func TestRandomOsIsStickyPerTunnel(t *testing.T) {
	h := newHarness(t, nil)
	transport := h.client.Transport.(*http.Transport)
	transport.MaxConnsPerHost = 1
	transport.MaxIdleConnsPerHost = 1
	seen := map[string]bool{}
	for range 6 {
		_, echoed := h.get(t, h.upstream.URL+"/sticky", "X-Tip-Browser", "Chrome", "X-Tip-Os", "IOS,Android")
		seen[echoedHeader(echoed, "User-Agent")] = true
	}
	if len(seen) != 1 {
		t.Fatalf("one tunnel should keep one identity, saw %d user agents", len(seen))
	}
	if h.obs.tunnelCount() != 1 {
		t.Fatalf("expected one tunnel, got %d", h.obs.tunnelCount())
	}
}

func TestPolicyDefaultsAndDeny(t *testing.T) {
	policy, err := directive.NewPolicy(map[string]string{"Browser": "Firefox", "Os": "Linux"}, []string{"Proxy"})
	if err != nil {
		t.Fatal(err)
	}
	h := newHarnessWithPolicy(t, policy)
	_, echoed := h.get(t, h.upstream.URL+"/defaults")
	if ua := echoedHeader(echoed, "User-Agent"); !strings.Contains(ua, "Firefox/148") || !strings.Contains(ua, "Linux") {
		t.Fatalf("defaults not applied: %q", ua)
	}
	_, echoed = h.get(t, h.upstream.URL+"/override", "X-Tip-Browser", "Chrome")
	if ua := echoedHeader(echoed, "User-Agent"); !strings.Contains(ua, "Chrome/152") {
		t.Fatalf("request should override default: %q", ua)
	}
	resp, _ := h.get(t, h.upstream.URL+"/denied", "X-Tip-Proxy", "http://p:1")
	if resp.StatusCode != 418 || !strings.Contains(resp.Header.Get("X-Tip-Error"), "not permitted") {
		t.Fatalf("status %d headers %v", resp.StatusCode, resp.Header)
	}
}

func TestPostBodyStreamsAndIsCounted(t *testing.T) {
	h := newHarness(t, nil)
	payload := bytes.Repeat([]byte("x"), 200000)
	req, _ := http.NewRequest("POST", h.upstream.URL+"/post", bytes.NewReader(payload))
	req.Header.Set("X-Tip-Browser", "Chrome")
	req.Header.Set("Content-Type", "text/plain")
	resp, err := h.client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	seen := h.upstream.Last(t)
	if seen.Method != "POST" || len(seen.Body) != len(payload) || seen.Header.Get("Content-Type") != "text/plain" {
		t.Fatalf("upstream saw %s %d bytes %v", seen.Method, len(seen.Body), seen.Header.Get("Content-Type"))
	}
	if ev := h.obs.last(t); ev.BytesIn != int64(len(payload)) || ev.Method != "POST" || ev.BytesOut == 0 {
		t.Fatalf("event %+v", ev)
	}
}

func TestPassthroughKeepsUpstreamFraming(t *testing.T) {
	h := newHarness(t, nil)
	resp, _ := h.get(t, h.upstream.URL+"/framing", "X-Tip-Browser", "Chrome")
	if resp.ContentLength <= 0 || len(resp.TransferEncoding) != 0 {
		t.Fatalf("content-length %d transfer-encoding %v", resp.ContentLength, resp.TransferEncoding)
	}
	req, _ := http.NewRequest("GET", h.upstream.URL+"/decoded", nil)
	req.Header.Set("X-Tip-Browser", "Chrome")
	req.Header.Set("Accept-Encoding", "identity")
	req.Header.Set("X-Upstream-Encoding", "gzip")
	resp, err := h.client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.Header.Get("Content-Length") != "" || !json.Valid(body) {
		t.Fatalf("decoded response should drop content-length and carry plain json: %v %q", resp.Header, body)
	}
}

func TestBadGatewayEmitsEvent(t *testing.T) {
	h := newHarness(t, nil)
	dead := h.upstream
	dead.Close()
	resp, _ := h.get(t, dead.URL+"/gone", "X-Tip-Browser", "Chrome")
	if resp.StatusCode != 502 {
		t.Fatalf("status %d", resp.StatusCode)
	}
	if ev := h.obs.last(t); ev.Status != 502 {
		t.Fatalf("event %+v", ev)
	}
}

func TestDirectiveTimeoutShortensHeadersPhase(t *testing.T) {
	h := newHarness(t, nil)
	resp, _ := h.get(t, h.upstream.URL+"/slow", "X-Tip-Browser", "Chrome", "X-Tip-Timeout", "100ms", "X-Upstream-Delay", "800ms")
	if resp.StatusCode != 502 || !strings.HasPrefix(resp.Header.Get("X-Tip-Error"), "timeout:") {
		t.Fatalf("status %d headers %v", resp.StatusCode, resp.Header)
	}
}

func TestConfiguredTimeoutIsTheCeilingOverHTTP2(t *testing.T) {
	h := newHarness(t, func(o *proxy.Options) { o.Timeout = 150 * time.Millisecond })
	resp, echoed := h.get(t, h.upstream.URL+"/ceiling", "X-Tip-Browser", "Chrome", "X-Tip-Timeout", "10s", "X-Upstream-Delay", "800ms")
	if resp.StatusCode != 502 || !strings.HasPrefix(resp.Header.Get("X-Tip-Error"), "timeout:") {
		t.Fatalf("directive must not extend the ceiling: status %d headers %v echoed %v", resp.StatusCode, resp.Header, echoed)
	}
}

func TestTimeoutDoesNotCutSlowBodies(t *testing.T) {
	h := newHarness(t, func(o *proxy.Options) { o.Timeout = 200 * time.Millisecond })
	resp, echoed := h.get(t, h.upstream.URL+"/slowbody", "X-Tip-Browser", "Chrome", "X-Upstream-Body-Delay", "600ms")
	if resp.StatusCode != 200 || echoed["path"] != "/slowbody" {
		t.Fatalf("status %d body %v", resp.StatusCode, echoed)
	}
}

func TestWebSocketRelayThroughTunnel(t *testing.T) {
	h := newHarness(t, nil)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	wsURL := "wss" + strings.TrimPrefix(h.upstream.URL, "https") + "/ws"
	conn, _, err := websocket.Dial(ctx, wsURL, &websocket.DialOptions{HTTPClient: h.client, HTTPHeader: http.Header{"X-Tip-Browser": {"Chrome"}}})
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.CloseNow()
	if err := conn.Write(ctx, websocket.MessageText, []byte("hello through tip")); err != nil {
		t.Fatal(err)
	}
	_, data, err := conn.Read(ctx)
	if err != nil || string(data) != "hello through tip" {
		t.Fatalf("echo %q err %v", data, err)
	}
	if seen := h.upstream.Last(t); seen.Path != "/ws" || seen.Header.Get("X-Tip-Browser") != "" {
		t.Fatalf("upstream saw %+v", seen)
	}
}

func TestServeCaCanBeDisabled(t *testing.T) {
	h := newHarness(t, func(o *proxy.Options) { o.ServeCa = false })
	resp, _ := http.Get(h.proxy.URL + "/ca.pem")
	if resp.StatusCode != 400 {
		t.Fatalf("status %d", resp.StatusCode)
	}
	if srv := (&http.Client{}); srv != nil {
		resp, _ = http.Get(h.proxy.URL + "/healthz")
		if resp.StatusCode != 200 {
			t.Fatalf("healthz %d", resp.StatusCode)
		}
	}
}

func TestHeadRequest(t *testing.T) {
	h := newHarness(t, nil)
	req, _ := http.NewRequest("HEAD", h.upstream.URL+"/head", nil)
	req.Header.Set("X-Tip-Browser", "Chrome")
	resp, err := h.client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 200 || h.upstream.Last(t).Method != "HEAD" {
		t.Fatalf("status %d method %s", resp.StatusCode, h.upstream.Last(t).Method)
	}
}

func TestConcurrentRequestsShareOneClient(t *testing.T) {
	h := newHarness(t, nil)
	var wg sync.WaitGroup
	errs := make(chan error, 20)
	for range 20 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			req, _ := http.NewRequest("GET", h.upstream.URL+"/parallel", nil)
			req.Header.Set("X-Tip-Browser", "Chrome")
			req.Header.Set("X-Tip-Os", "Windows")
			resp, err := h.client.Do(req)
			if err != nil {
				errs <- err
				return
			}
			io.Copy(io.Discard, resp.Body)
			resp.Body.Close()
			if resp.StatusCode != 200 {
				errs <- io.ErrUnexpectedEOF
			}
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatal(err)
	}
	if n := len(h.upstream.Requests()); n != 20 {
		t.Fatalf("upstream saw %d requests", n)
	}
}
