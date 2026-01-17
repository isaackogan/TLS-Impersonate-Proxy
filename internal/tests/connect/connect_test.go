package connect_test

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/isaackogan/tls-impersonate-proxy/internal/connect"
	"github.com/isaackogan/tls-impersonate-proxy/internal/tests/testutil"
)

func echo(t *testing.T) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				io.Copy(c, c)
			}()
		}
	}()
	return l.Addr().String()
}

func dialer(t *testing.T, proxy string) *connect.Dialer {
	t.Helper()
	u, err := url.Parse(proxy)
	if err != nil {
		t.Fatal(err)
	}
	d, err := connect.New(u, &net.Dialer{}, &tls.Config{InsecureSkipVerify: true})
	if err != nil {
		t.Fatal(err)
	}
	return d
}

func exchange(t *testing.T, conn net.Conn, send string, want string) {
	t.Helper()
	conn.SetDeadline(time.Now().Add(2 * time.Second))
	if _, err := io.WriteString(conn, send); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, len(want))
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatal(err)
	}
	if string(buf) != want {
		t.Fatalf("read %q, want %q", buf, want)
	}
}

func hopError(t *testing.T, err error) *connect.Error {
	t.Helper()
	var e *connect.Error
	if !errors.As(err, &e) {
		t.Fatalf("want *connect.Error, got %T: %v", err, err)
	}
	return e
}

func TestTunnelsThroughTheHopWithBasicAuth(t *testing.T) {
	target := echo(t)
	hop := testutil.NewHop(t)
	conn, err := dialer(t, "http://alice:s3cret@"+hop.Addr).DialContext(context.Background(), "tcp", target)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	exchange(t, conn, "ping", "ping")
	req := hop.Requests()[0]
	want := "Basic " + base64.StdEncoding.EncodeToString([]byte("alice:s3cret"))
	if req.Method != "CONNECT" || req.Host != target || req.Header.Get("Proxy-Authorization") != want || req.Header.Get("User-Agent") != "" {
		t.Fatalf("connect request %s %s %v", req.Method, req.Host, req.Header)
	}
}

func TestBytesBehindTheStatusLineReachTheTunnel(t *testing.T) {
	target := echo(t)
	hop := testutil.NewHop(t)
	hop.Reply(func(*http.Request) *testutil.HopReply { return &testutil.HopReply{Status: 200, Banner: "hello "} })
	conn, err := dialer(t, "http://"+hop.Addr).DialContext(context.Background(), "tcp", target)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	exchange(t, conn, "ping", "hello ping")
}

func TestRefusalKeepsStatusHeadersAndBody(t *testing.T) {
	hop := testutil.NewHop(t)
	hop.Reply(func(*http.Request) *testutil.HopReply {
		return &testutil.HopReply{Status: 407, Header: http.Header{"X-Oxylabs-Error": {"bad-auth"}}, Body: "Auth failed\r\nsecond line\n"}
	})
	_, err := dialer(t, "http://"+hop.Addr).DialContext(context.Background(), "tcp", "example.invalid:443")
	e := hopError(t, err)
	if e.Phase != connect.PhaseConnect || e.Verdict == nil || e.Verdict.Status != 407 || e.Verdict.Header.Get("X-Oxylabs-Error") != "bad-auth" {
		t.Fatalf("%+v", e)
	}
	if e.Verdict.Line() != "Auth failed" || string(e.Verdict.Body) != "Auth failed\r\nsecond line\n" {
		t.Fatalf("line %q body %q", e.Verdict.Line(), e.Verdict.Body)
	}
	if e.Error() != "CONNECT 407 Proxy Authentication Required" {
		t.Fatalf("message %q", e.Error())
	}
}

func TestRefusalBodyIsCapped(t *testing.T) {
	hop := testutil.NewHop(t)
	hop.Reply(func(*http.Request) *testutil.HopReply { return &testutil.HopReply{Status: 503, Body: strings.Repeat("x", 10000)} })
	_, err := dialer(t, "http://"+hop.Addr).DialContext(context.Background(), "tcp", "example.invalid:443")
	e := hopError(t, err)
	if len(e.Verdict.Body) != connect.MaxBody || len(e.Verdict.Line()) != connect.MaxLine {
		t.Fatalf("body %d line %d", len(e.Verdict.Body), len(e.Verdict.Line()))
	}
}

func TestUnreachableHopIsTheDialPhase(t *testing.T) {
	l, _ := net.Listen("tcp", "127.0.0.1:0")
	closed := l.Addr().String()
	l.Close()
	_, err := dialer(t, "http://"+closed).DialContext(context.Background(), "tcp", "example.invalid:443")
	e := hopError(t, err)
	if e.Phase != connect.PhaseDial || e.Verdict != nil || e.Err == nil || !strings.HasPrefix(e.Error(), "proxy-dial: ") {
		t.Fatalf("%+v", e)
	}
}

func TestStalledHopHonoursTheContext(t *testing.T) {
	hop := testutil.NewHop(t)
	hop.Reply(func(*http.Request) *testutil.HopReply { return &testutil.HopReply{Stall: true} })
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	ctx, memo := connect.WithMemo(ctx)
	start := time.Now()
	_, err := dialer(t, "http://"+hop.Addr).DialContext(ctx, "tcp", "example.invalid:443")
	e := hopError(t, err)
	if e.Phase != connect.PhaseConnect || !errors.Is(err, context.DeadlineExceeded) || time.Since(start) > 2*time.Second {
		t.Fatalf("%+v after %s", e, time.Since(start))
	}
	if memo.Phase() != connect.PhaseConnect || memo.Verdict() != nil {
		t.Fatalf("memo should hold the phase that timed out: %q %v", memo.Phase(), memo.Verdict())
	}
}

func TestMemoRemembersTheVerdictAndClearsOnATunnel(t *testing.T) {
	hop := testutil.NewHop(t)
	hop.Reply(func(*http.Request) *testutil.HopReply { return &testutil.HopReply{Status: 403, Body: "blocked"} })
	ctx, memo := connect.WithMemo(context.Background())
	d := dialer(t, "http://"+hop.Addr)
	hopError(t, must(d.DialContext(ctx, "tcp", "example.invalid:443")))
	e := hopError(t, must(d.DialContext(ctx, "tcp", "example.invalid:443")))
	if e.Verdict == nil || e.Verdict.Status != 403 || len(hop.Requests()) != 1 {
		t.Fatalf("a second dial must reuse the verdict: %+v, hop saw %d", e, len(hop.Requests()))
	}
	if memo.Verdict() == nil || memo.Phase() != connect.PhaseConnect {
		t.Fatalf("memo %v %q", memo.Verdict(), memo.Phase())
	}
	hop.Reply(nil)
	ctx, memo = connect.WithMemo(context.Background())
	conn, err := d.DialContext(ctx, "tcp", echo(t))
	if err != nil {
		t.Fatal(err)
	}
	conn.Close()
	if memo.Phase() != "" || memo.Verdict() != nil {
		t.Fatalf("a tunnel clears the phase: %q %v", memo.Phase(), memo.Verdict())
	}
}

func must(_ net.Conn, err error) error { return err }

func TestTLSHop(t *testing.T) {
	target := echo(t)
	hop := testutil.NewHopTLS(t)
	conn, err := dialer(t, "https://"+hop.Addr).DialContext(context.Background(), "tcp", target)
	if err != nil {
		t.Fatal(err)
	}
	exchange(t, conn, "ping", "ping")
	conn.Close()
	_, err = dialer(t, "https://"+testutil.NewHop(t).Addr).DialContext(context.Background(), "tcp", target)
	if e := hopError(t, err); e.Phase != connect.PhaseTLS {
		t.Fatalf("plaintext hop behind an https url: %+v", e)
	}
	_, err = dialer(t, "http://"+hop.Addr).DialContext(context.Background(), "tcp", target)
	if e := hopError(t, err); e.Phase != connect.PhaseConnect || e.Verdict != nil {
		t.Fatalf("tls hop behind an http url: %+v", e)
	}
}

func TestOnlyHttpProxies(t *testing.T) {
	for _, raw := range []string{"socks5://127.0.0.1:1080", "http://:8080", "ftp://x:1"} {
		u, _ := url.Parse(raw)
		if _, err := connect.New(u, nil, nil); err == nil {
			t.Fatalf("%s must be refused", raw)
		}
	}
}
