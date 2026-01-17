// Package connect dials through an HTTP CONNECT proxy and keeps the hop's answer when it refuses.
package connect

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

type Phase string

const (
	PhaseDial    Phase = "proxy-dial"
	PhaseTLS     Phase = "proxy-tls"
	PhaseConnect Phase = "proxy-connect"
)

const (
	MaxBody = 4096
	MaxLine = 200
)

// Verdict is a hop's non-2xx answer to CONNECT: its status, its headers and the start of its body.
type Verdict struct {
	Status int
	Header http.Header
	Body   []byte
}

func (v *Verdict) Line() string {
	line, _, _ := strings.Cut(strings.TrimSpace(string(v.Body)), "\n")
	line = strings.TrimSpace(line)
	if len(line) > MaxLine {
		line = strings.ToValidUTF8(line[:MaxLine], "")
	}
	return line
}

type Error struct {
	Phase   Phase
	Verdict *Verdict
	Err     error
}

func (e *Error) Error() string {
	if e.Verdict != nil {
		return fmt.Sprintf("CONNECT %d %s", e.Verdict.Status, http.StatusText(e.Verdict.Status))
	}
	return string(e.Phase) + ": " + e.Err.Error()
}

func (e *Error) Unwrap() error { return e.Err }

type memoKey struct{}

// Memo is per-request state shared between a transport's dial attempts and the caller: the hop phase under way,
// so a timeout the transport reports as its own can say where it struck, and a hop's refusal, so a fallback
// attempt for the same request does not ask the hop again.
type Memo struct {
	mu      sync.Mutex
	phase   Phase
	verdict *Verdict
}

func WithMemo(ctx context.Context) (context.Context, *Memo) {
	m := &Memo{}
	return context.WithValue(ctx, memoKey{}, m), m
}

// Phase is the hop phase under way, or the one that last failed; it is empty once a tunnel is up.
func (m *Memo) Phase() Phase {
	if m == nil {
		return ""
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.phase
}

func (m *Memo) Verdict() *Verdict {
	if m == nil {
		return nil
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.verdict
}

func (m *Memo) set(phase Phase, verdict *Verdict) {
	if m == nil {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.phase = phase
	if verdict != nil {
		m.verdict = verdict
	}
}

type Dialer struct {
	host string
	auth string
	dial func(ctx context.Context, network, addr string) (net.Conn, error)
	tls  *tls.Config
}

// New builds a dialer for an http or https proxy. base reaches the hop, so its resolver and local address apply
// there; the target name travels to the hop as written and is resolved by it.
func New(proxy *url.URL, base *net.Dialer, tlsConfig *tls.Config) (*Dialer, error) {
	if proxy.Scheme != "http" && proxy.Scheme != "https" {
		return nil, fmt.Errorf("connect: %q is not an http or https proxy", proxy.Scheme)
	}
	if proxy.Hostname() == "" {
		return nil, errors.New("connect: proxy URL has no host")
	}
	if base == nil {
		base = &net.Dialer{}
	}
	port := proxy.Port()
	if port == "" {
		port = map[string]string{"http": "80", "https": "443"}[proxy.Scheme]
	}
	d := &Dialer{host: net.JoinHostPort(proxy.Hostname(), port), dial: base.DialContext}
	if u := proxy.User; u != nil {
		password, _ := u.Password()
		d.auth = "Basic " + base64.StdEncoding.EncodeToString([]byte(u.Username()+":"+password))
	}
	if proxy.Scheme == "https" {
		cfg := &tls.Config{}
		if tlsConfig != nil {
			cfg = tlsConfig.Clone()
		}
		if cfg.ServerName == "" {
			cfg.ServerName = proxy.Hostname()
		}
		cfg.NextProtos = []string{"http/1.1"}
		d.tls = cfg
	}
	return d, nil
}

func (d *Dialer) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	memo, _ := ctx.Value(memoKey{}).(*Memo)
	if v := memo.Verdict(); v != nil {
		return nil, &Error{Phase: PhaseConnect, Verdict: v}
	}
	memo.set(PhaseDial, nil)
	conn, err := d.dial(ctx, network, d.host)
	if err != nil {
		return nil, &Error{Phase: PhaseDial, Err: err}
	}
	if d.tls != nil {
		memo.set(PhaseTLS, nil)
		tc := tls.Client(conn, d.tls)
		if err := tc.HandshakeContext(ctx); err != nil {
			conn.Close()
			return nil, &Error{Phase: PhaseTLS, Err: err}
		}
		conn = tc
	}
	memo.set(PhaseConnect, nil)
	tunnel, e := d.connect(ctx, conn, addr)
	if e != nil {
		conn.Close()
		memo.set(PhaseConnect, e.Verdict)
		return nil, e
	}
	memo.set("", nil)
	return tunnel, nil
}

func (d *Dialer) connect(ctx context.Context, conn net.Conn, addr string) (net.Conn, *Error) {
	stop := context.AfterFunc(ctx, func() { conn.SetDeadline(time.Unix(1, 0)) })
	req := &http.Request{Method: http.MethodConnect, URL: &url.URL{Opaque: addr}, Host: addr, Header: http.Header{"User-Agent": {""}}}
	if d.auth != "" {
		req.Header.Set("Proxy-Authorization", d.auth)
	}
	if err := req.Write(conn); err != nil {
		stop()
		return nil, &Error{Phase: PhaseConnect, Err: cause(ctx, err)}
	}
	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, req)
	if err != nil {
		stop()
		return nil, &Error{Phase: PhaseConnect, Err: cause(ctx, err)}
	}
	if resp.StatusCode/100 != 2 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, MaxBody))
		stop()
		return nil, &Error{Phase: PhaseConnect, Verdict: &Verdict{Status: resp.StatusCode, Header: resp.Header, Body: body}}
	}
	if !stop() {
		return nil, &Error{Phase: PhaseConnect, Err: ctx.Err()}
	}
	conn.SetDeadline(time.Time{})
	if n := br.Buffered(); n > 0 {
		return &buffered{Conn: conn, r: io.MultiReader(io.LimitReader(br, int64(n)), conn)}, nil
	}
	return conn, nil
}

func cause(ctx context.Context, err error) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}
	return err
}

// buffered hands bytes the response reader took past the status line to the tunnel before the socket.
type buffered struct {
	net.Conn
	r io.Reader
}

func (b *buffered) Read(p []byte) (int, error) { return b.r.Read(p) }
