package e2e_test

import (
	"bufio"
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/isaackogan/tls-impersonate-proxy/internal/tests/testutil"
)

type tip struct {
	proxyURL string
	adminURL string
	logs     *bytes.Buffer
	mu       *sync.Mutex
}

func (tp *tip) output() string {
	tp.mu.Lock()
	defer tp.mu.Unlock()
	return tp.logs.String()
}

func startTip(t *testing.T) *tip {
	t.Helper()
	dir := t.TempDir()
	bin := filepath.Join(dir, "tip")
	build := exec.Command("go", "build", "-o", bin, "../../../cmd/tip")
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build: %v\n%s", err, out)
	}
	raw, _ := os.ReadFile(filepath.Join("..", "testdata", "e2e", "tip.yaml"))
	cfg := filepath.Join(dir, "tip.yaml")
	os.WriteFile(cfg, bytes.ReplaceAll(raw, []byte("CA_DIR"), []byte(dir)), 0o600)
	cmd := exec.Command(bin, "--config", cfg)
	stdout, _ := cmd.StdoutPipe()
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { cmd.Process.Signal(os.Interrupt); cmd.Wait() })
	tp := &tip{logs: &bytes.Buffer{}, mu: &sync.Mutex{}}
	ready := make(chan struct{}, 1)
	go func() {
		scanner := bufio.NewScanner(stdout)
		for scanner.Scan() {
			line := scanner.Bytes()
			tp.mu.Lock()
			tp.logs.Write(append(bytes.Clone(line), '\n'))
			tp.mu.Unlock()
			var rec map[string]any
			if json.Unmarshal(line, &rec) == nil && rec["msg"] == "ready" {
				tp.proxyURL = "http://" + rec["proxy"].(string)
				tp.adminURL = "http://" + rec["admin"].(string)
				ready <- struct{}{}
			}
		}
	}()
	select {
	case <-ready:
		return tp
	case <-time.After(30 * time.Second):
		t.Fatalf("tip did not become ready:\n%s", tp.output())
	}
	return nil
}

func TestEndToEnd(t *testing.T) {
	tp := startTip(t)
	resp, err := http.Get(tp.proxyURL + "/ca.pem")
	if err != nil || resp.StatusCode != 200 {
		t.Fatalf("ca.pem %v %v", resp, err)
	}
	pemBytes, _ := io.ReadAll(resp.Body)
	pool := testutil.PoolFromPEM(t, pemBytes)
	up := testutil.NewUpstream(t)
	client := testutil.ProxyClient(t, tp.proxyURL, pool)
	req, _ := http.NewRequest("GET", up.URL+"/e2e", nil)
	req.Header.Set("X-Tip-Browser", "Chrome")
	req.Header.Set("X-Tip-Os", "IOS,Android")
	resp, err = client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != 200 || !strings.Contains(string(body), `\"Google Chrome\";v=\"152\"`) {
		t.Fatalf("status %d body %s", resp.StatusCode, body)
	}
	metrics, err := http.Get(tp.adminURL + "/metrics")
	if err != nil {
		t.Fatal(err)
	}
	scraped, _ := io.ReadAll(metrics.Body)
	if !strings.Contains(string(scraped), `tip_requests_total{`) {
		t.Fatalf("metrics:\n%s", scraped)
	}
	deadline := time.Now().Add(2 * time.Second)
	for !strings.Contains(tp.output(), `"msg":"request"`) && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	if !strings.Contains(tp.output(), `"msg":"request"`) {
		t.Fatalf("logs:\n%s", tp.output())
	}
}
