package proxy_test

import (
	"bufio"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/isaackogan/tls-impersonate-proxy/internal/proxy"
	"github.com/isaackogan/tls-impersonate-proxy/internal/tests/testutil"
)

func TestServerSentEventsStream(t *testing.T) {
	h := newHarness(t, nil)
	req, _ := http.NewRequest("GET", h.upstream.URL+"/sse", nil)
	req.Header.Set("X-Tip-Browser", "Chrome")
	started := time.Now()
	resp, err := h.client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	scanner := bufio.NewScanner(resp.Body)
	if !scanner.Scan() || scanner.Text() != "data: first" {
		t.Fatalf("first event %q", scanner.Text())
	}
	if elapsed := time.Since(started); elapsed > 250*time.Millisecond {
		t.Fatalf("first event arrived after %v; the stream is being buffered", elapsed)
	}
	for scanner.Scan() {
		if scanner.Text() == "data: second" {
			return
		}
	}
	t.Fatal("second event never arrived")
}

func TestLargeBodyStreamsWithExactCount(t *testing.T) {
	h := newHarness(t, nil)
	const size = 8 << 20
	req, _ := http.NewRequest("GET", h.upstream.URL+"/large/8388608", nil)
	req.Header.Set("X-Tip-Browser", "Chrome")
	resp, err := h.client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	n, err := io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	if err != nil || n != size {
		t.Fatalf("read %d bytes err %v", n, err)
	}
	if ev := h.obs.last(t); ev.BytesOut != size {
		t.Fatalf("bytes_out %d", ev.BytesOut)
	}
}

func TestUpstreamVariants(t *testing.T) {
	cases := []struct {
		name      string
		upstream  func(testing.TB) *testutil.Upstream
		wantProto string
	}{
		{"http1 only", testutil.NewUpstreamHTTP1, "HTTP/1.1"},
		{"tls12 only", testutil.NewUpstreamTLS12, "HTTP/2.0"},
		{"ipv6 literal", testutil.NewUpstreamIPv6, "HTTP/2.0"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := newHarness(t, nil)
			up := tc.upstream(t)
			resp, echoed := h.get(t, up.URL+"/variant", "X-Tip-Browser", "Chrome")
			if resp.StatusCode != 200 || echoed["proto"] != tc.wantProto {
				t.Fatalf("status %d proto %v error %q", resp.StatusCode, echoed["proto"], resp.Header.Get("X-Tip-Error"))
			}
			if ua := echoedHeader(echoed, "User-Agent"); !strings.Contains(ua, "Chrome/152") {
				t.Fatalf("ua %q", ua)
			}
		})
	}
}

type endless struct{ remaining int }

func (e *endless) Read(p []byte) (int, error) {
	if e.remaining == 0 {
		return 0, io.EOF
	}
	n := min(len(p), e.remaining)
	for i := range n {
		p[i] = 'z'
	}
	e.remaining -= n
	return n, nil
}

func TestOtherMethodsAndBodies(t *testing.T) {
	h := newHarness(t, nil)
	for _, method := range []string{"PUT", "PATCH", "DELETE", "OPTIONS"} {
		t.Run(method, func(t *testing.T) {
			req, _ := http.NewRequest(method, h.upstream.URL+"/m", strings.NewReader("payload"))
			req.Header.Set("X-Tip-Browser", "Chrome")
			resp, err := h.client.Do(req)
			if err != nil {
				t.Fatal(err)
			}
			io.Copy(io.Discard, resp.Body)
			resp.Body.Close()
			seen := h.upstream.Last(t)
			if resp.StatusCode != 200 || seen.Method != method || string(seen.Body) != "payload" {
				t.Fatalf("status %d method %s body %q", resp.StatusCode, seen.Method, seen.Body)
			}
		})
	}
	t.Run("chunked body with expect", func(t *testing.T) {
		req, _ := http.NewRequest("POST", h.upstream.URL+"/chunked", &endless{remaining: 300000})
		req.Header.Set("X-Tip-Browser", "Chrome")
		req.Header.Set("Expect", "100-continue")
		resp, err := h.client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
		if seen := h.upstream.Last(t); len(seen.Body) != 300000 {
			t.Fatalf("upstream got %d bytes", len(seen.Body))
		}
		if ev := h.obs.last(t); ev.BytesIn != 300000 {
			t.Fatalf("bytes_in %d", ev.BytesIn)
		}
	})
}

func TestEncodingHeadersLeftAloneWithoutBodies(t *testing.T) {
	h := newHarness(t, nil)
	req, _ := http.NewRequest("GET", h.upstream.URL+"/status?code=304", nil)
	req.Header.Set("X-Tip-Browser", "Chrome")
	req.Header.Set("Accept-Encoding", "identity")
	req.Header.Set("X-Upstream-Encoding", "gzip")
	resp, err := h.client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 304 || resp.Header.Get("Content-Encoding") != "gzip" {
		t.Fatalf("status %d encoding %q", resp.StatusCode, resp.Header.Get("Content-Encoding"))
	}
	req, _ = http.NewRequest("HEAD", h.upstream.URL+"/head", nil)
	req.Header.Set("X-Tip-Browser", "Chrome")
	req.Header.Set("Accept-Encoding", "identity")
	req.Header.Set("X-Upstream-Encoding", "gzip")
	resp, err = h.client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 200 || resp.Header.Get("Content-Encoding") != "gzip" {
		t.Fatalf("head status %d encoding %q", resp.StatusCode, resp.Header.Get("Content-Encoding"))
	}
}

func TestKeepAcceptEncodingDrivesNegotiation(t *testing.T) {
	h := newHarness(t, nil)
	req, _ := http.NewRequest("GET", h.upstream.URL+"/keepae", nil)
	req.Header.Set("X-Tip-Browser", "Chrome")
	req.Header.Set("X-Tip-Keep", "Accept-Encoding")
	req.Header.Set("Accept-Encoding", "gzip")
	req.Header.Set("X-Upstream-Encoding", "gzip")
	resp, err := h.client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if got := h.upstream.Last(t).Header.Get("Accept-Encoding"); got != "gzip" {
		t.Fatalf("upstream saw accept-encoding %q", got)
	}
	if resp.Header.Get("Content-Encoding") != "gzip" {
		t.Fatalf("client offered gzip, so gzip must pass through: %v", resp.Header)
	}
}

func TestMatchWithExplicitOs(t *testing.T) {
	h := newHarness(t, nil)
	_, echoed := h.get(t, h.upstream.URL+"/matchos", "X-Tip-Match", "true", "X-Tip-Os", "Windows", "User-Agent", "Mozilla/5.0 (X11; Linux x86_64; rv:120.0) Gecko/20100101 Firefox/120.0")
	if ua := echoedHeader(echoed, "User-Agent"); !strings.Contains(ua, "Firefox/148") || !strings.Contains(ua, "Windows") {
		t.Fatalf("ua %q", ua)
	}
}

func TestBogusInterfaceIsABuildError(t *testing.T) {
	h := newHarness(t, nil)
	resp, _ := h.get(t, h.upstream.URL+"/iface", "X-Tip-Browser", "Chrome", "X-Tip-InterfaceAddr", "nope0")
	if resp.StatusCode != 418 || !strings.Contains(resp.Header.Get("X-Tip-Error"), "build client") {
		t.Fatalf("status %d headers %v", resp.StatusCode, resp.Header)
	}
}

func TestTinyTimeoutIsArmed(t *testing.T) {
	h := newHarness(t, nil)
	resp, _ := h.get(t, h.upstream.URL+"/tiny", "X-Tip-Browser", "Chrome", "X-Tip-Timeout", "1ms", "X-Upstream-Delay", "300ms")
	if resp.StatusCode != 502 || !strings.HasPrefix(resp.Header.Get("X-Tip-Error"), "timeout:") {
		t.Fatalf("status %d headers %v", resp.StatusCode, resp.Header)
	}
}

func TestClientHTTP2InTunnel(t *testing.T) {
	h := newHarness(t, func(o *proxy.Options) { o.ClientHttp2 = true })
	transport := h.client.Transport.(*http.Transport)
	transport.ForceAttemptHTTP2 = true
	done := make(chan error, 8)
	for range 8 {
		go func() {
			req, _ := http.NewRequest("GET", h.upstream.URL+"/h2client", nil)
			req.Header.Set("X-Tip-Browser", "Chrome")
			req.Header.Set("X-Tip-Os", "IOS,Android")
			resp, err := h.client.Do(req)
			if err != nil {
				done <- err
				return
			}
			io.Copy(io.Discard, resp.Body)
			resp.Body.Close()
			if resp.ProtoMajor != 2 {
				done <- io.ErrUnexpectedEOF
				return
			}
			done <- nil
		}()
	}
	for range 8 {
		if err := <-done; err != nil {
			t.Fatalf("client-side h2: %v", err)
		}
	}
}

func TestClientKeyIsStableAndLogged(t *testing.T) {
	h := newHarness(t, nil)
	h.get(t, h.upstream.URL+"/k1", "X-Tip-Browser", "Chrome", "X-Tip-Os", "Windows")
	h.get(t, h.upstream.URL+"/k2", "X-Tip-Browser", "chrome", "X-Tip-Os", "WINDOWS", "X-Tip-Timeout", "3s")
	var keys []string
	for _, line := range strings.Split(strings.TrimSpace(h.logs.String()), "\n") {
		var rec map[string]any
		if json.Unmarshal([]byte(line), &rec) == nil && rec["msg"] == "request" {
			keys = append(keys, rec["client_key"].(string))
		}
	}
	if len(keys) != 2 || keys[0] != keys[1] || keys[0] == "" {
		t.Fatalf("client keys %v", keys)
	}
}

func TestDrainWaitsForActiveRequestsAndRefusesNewOnes(t *testing.T) {
	h := newHarness(t, nil)
	started := make(chan struct{})
	finished := make(chan int, 1)
	go func() {
		req, _ := http.NewRequest("GET", h.upstream.URL+"/draining", nil)
		req.Header.Set("X-Tip-Browser", "Chrome")
		req.Header.Set("X-Upstream-Delay", "500ms")
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
	resp, _ := h.get(t, h.upstream.URL+"/late", "X-Tip-Browser", "Chrome")
	if resp.StatusCode != 503 {
		t.Fatalf("new request during drain: status %d", resp.StatusCode)
	}
	if status := <-finished; status != 200 {
		t.Fatalf("in-flight request finished with %d", status)
	}
	if err := <-drained; err != nil {
		t.Fatal(err)
	}
}
