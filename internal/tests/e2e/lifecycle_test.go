package e2e_test

import (
	"bufio"
	"bytes"
	"crypto/x509"
	"encoding/json"
	"io"
	"net"
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

type process struct {
	tip
	cmd *exec.Cmd
}

func buildTip(t *testing.T) string {
	t.Helper()
	bin := filepath.Join(t.TempDir(), "tip")
	if out, err := exec.Command("go", "build", "-o", bin, "../../../cmd/tip").CombinedOutput(); err != nil {
		t.Fatalf("build: %v\n%s", err, out)
	}
	return bin
}

func launch(t *testing.T, bin, yaml string, mode os.FileMode) *process {
	t.Helper()
	dir := t.TempDir()
	cfg := filepath.Join(dir, "tip.yaml")
	os.WriteFile(cfg, []byte(strings.ReplaceAll(yaml, "CA_DIR", dir)), mode)
	cmd := exec.Command(bin, "--config", cfg)
	stdout, _ := cmd.StdoutPipe()
	stderr := &bytes.Buffer{}
	cmd.Stderr = stderr
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	p := &process{tip: tip{logs: &bytes.Buffer{}, mu: &sync.Mutex{}}, cmd: cmd}
	ready := make(chan struct{}, 1)
	go func() {
		scanner := bufio.NewScanner(stdout)
		for scanner.Scan() {
			line := scanner.Bytes()
			p.mu.Lock()
			p.logs.Write(append(bytes.Clone(line), '\n'))
			p.mu.Unlock()
			var rec map[string]any
			if json.Unmarshal(line, &rec) == nil && rec["msg"] == "ready" {
				p.proxyURL = "http://" + rec["proxy"].(string)
				p.adminURL = "http://" + rec["admin"].(string)
				ready <- struct{}{}
			}
		}
	}()
	select {
	case <-ready:
	case <-time.After(20 * time.Second):
		cmd.Process.Kill()
		t.Fatalf("not ready:\n%s\n%s", p.output(), stderr.String())
	}
	t.Cleanup(func() {
		if cmd.ProcessState == nil {
			cmd.Process.Kill()
			cmd.Wait()
		}
	})
	return p
}

func (p *process) pool(t *testing.T) *x509.CertPool {
	t.Helper()
	resp, err := http.Get(p.proxyURL + "/ca.pem")
	if err != nil {
		t.Fatal(err)
	}
	pemBytes, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	http.DefaultTransport.(*http.Transport).CloseIdleConnections()
	return testutil.PoolFromPEM(t, pemBytes)
}

func (p *process) client(t *testing.T) *http.Client {
	t.Helper()
	return testutil.ProxyClient(t, p.proxyURL, p.pool(t))
}

const baseYAML = "server:\n  listen: \"127.0.0.1:0\"\n  shutdown_grace: 5s\ntls:\n  ca_cert: CA_DIR/ca.pem\n  ca_key: CA_DIR/ca.key\nmetrics:\n  listen: \"127.0.0.1:0\"\n"

func TestGracefulShutdownFinishesInFlightRequests(t *testing.T) {
	p := launch(t, buildTip(t), baseYAML, 0o600)
	up := testutil.NewUpstream(t)
	client := p.client(t)
	result := make(chan error, 1)
	go func() {
		req, _ := http.NewRequest("GET", up.URL+"/slow", nil)
		req.Header.Set("X-Tip-Browser", "Chrome")
		req.Header.Set("X-Upstream-Delay", "800ms")
		resp, err := client.Do(req)
		if err != nil {
			result <- err
			return
		}
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
		if resp.StatusCode != 200 {
			result <- io.ErrUnexpectedEOF
			return
		}
		result <- nil
	}()
	time.Sleep(200 * time.Millisecond)
	p.cmd.Process.Signal(os.Interrupt)
	if err := <-result; err != nil {
		t.Fatalf("in-flight request failed during shutdown: %v", err)
	}
	if err := p.cmd.Wait(); err != nil {
		t.Fatalf("exit: %v\n%s", err, p.output())
	}
	if !strings.Contains(p.output(), `"msg":"shutting down"`) {
		t.Fatalf("logs:\n%s", p.output())
	}
}

func TestMaxConnectionsBlocksTheNextClient(t *testing.T) {
	p := launch(t, buildTip(t), strings.Replace(baseYAML, "  listen: \"127.0.0.1:0\"\n  shutdown_grace", "  listen: \"127.0.0.1:0\"\n  max_connections: 1\n  shutdown_grace", 1), 0o600)
	up := testutil.NewUpstream(t)
	pool := p.pool(t)
	first := testutil.ProxyClient(t, p.proxyURL, pool)
	req, _ := http.NewRequest("GET", up.URL+"/one", nil)
	req.Header.Set("X-Tip-Browser", "Chrome")
	resp, err := first.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	second := testutil.ProxyClient(t, p.proxyURL, pool)
	done := make(chan error, 1)
	go func() {
		req, _ := http.NewRequest("GET", up.URL+"/two", nil)
		req.Header.Set("X-Tip-Browser", "Chrome")
		resp, err := second.Do(req)
		if err == nil {
			io.Copy(io.Discard, resp.Body)
			resp.Body.Close()
		}
		done <- err
	}()
	select {
	case err := <-done:
		t.Fatalf("second connection should have waited for the first to close (err %v)", err)
	case <-time.After(400 * time.Millisecond):
	}
	first.Transport.(*http.Transport).CloseIdleConnections()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("second connection never got through after the first closed")
	}
}

func TestPermissiveConfigWithCredentialsWarns(t *testing.T) {
	p := launch(t, buildTip(t), baseYAML+"auth:\n  users:\n    alice: secret\n", 0o644)
	if !strings.Contains(p.output(), "readable by other users") {
		t.Fatalf("logs:\n%s", p.output())
	}
}

func TestPortInUseFailsFast(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	bin := buildTip(t)
	dir := t.TempDir()
	cfg := filepath.Join(dir, "tip.yaml")
	os.WriteFile(cfg, []byte(strings.ReplaceAll(strings.Replace(baseYAML, "127.0.0.1:0\"\n  shutdown_grace", ln.Addr().String()+"\"\n  shutdown_grace", 1), "CA_DIR", dir)), 0o600)
	out, err := exec.Command(bin, "--config", cfg).CombinedOutput()
	if err == nil || !strings.Contains(string(out), "address already in use") {
		t.Fatalf("err %v output:\n%s", err, out)
	}
}
