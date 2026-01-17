package testutil

import (
	"bufio"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"sync"
	"testing"
)

// Hop is a bare HTTP CONNECT proxy whose answer each test scripts. Without a script it tunnels to the target.
type Hop struct {
	Addr     string
	listener net.Listener
	done     chan struct{}
	mu       sync.Mutex
	requests []*http.Request
	reply    func(*http.Request) *HopReply
}

// HopReply is the hop's answer to a CONNECT. A nil reply or a 2xx status tunnels, with Banner written right
// after the status line before any target bytes; a non-2xx status is sent with Header and Body; Stall never answers.
type HopReply struct {
	Status int
	Header http.Header
	Body   string
	Banner string
	Stall  bool
}

func NewHop(t testing.TB) *Hop { return newHop(t, listen(t)) }

func NewHopTLS(t testing.TB) *Hop {
	cert, _ := TempCA(t)
	return newHop(t, tls.NewListener(listen(t), &tls.Config{Certificates: []tls.Certificate{cert}}))
}

func listen(t testing.TB) net.Listener {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	return l
}

func newHop(t testing.TB, l net.Listener) *Hop {
	h := &Hop{Addr: l.Addr().String(), listener: l, done: make(chan struct{})}
	t.Cleanup(func() {
		close(h.done)
		l.Close()
	})
	go h.accept()
	return h
}

func (h *Hop) Reply(f func(*http.Request) *HopReply) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.reply = f
}

func (h *Hop) Requests() []*http.Request {
	h.mu.Lock()
	defer h.mu.Unlock()
	return append([]*http.Request(nil), h.requests...)
}

func (h *Hop) accept() {
	for {
		conn, err := h.listener.Accept()
		if err != nil {
			return
		}
		go h.handle(conn)
	}
}

func (h *Hop) handle(conn net.Conn) {
	defer conn.Close()
	req, err := http.ReadRequest(bufio.NewReader(conn))
	if err != nil {
		return
	}
	h.mu.Lock()
	h.requests = append(h.requests, req)
	reply := h.reply
	h.mu.Unlock()
	var r *HopReply
	if reply != nil {
		r = reply(req)
	}
	if r != nil && r.Stall {
		<-h.done
		return
	}
	if r != nil && r.Status != 0 && r.Status/100 != 2 {
		fmt.Fprintf(conn, "HTTP/1.1 %d %s\r\n", r.Status, http.StatusText(r.Status))
		r.Header.Write(conn)
		fmt.Fprintf(conn, "Content-Length: %d\r\n\r\n%s", len(r.Body), r.Body)
		return
	}
	target, err := net.Dial("tcp", req.Host)
	if err != nil {
		io.WriteString(conn, "HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n")
		return
	}
	defer target.Close()
	banner := ""
	if r != nil {
		banner = r.Banner
	}
	io.WriteString(conn, "HTTP/1.1 200 Connection established\r\n\r\n"+banner)
	go io.Copy(target, conn)
	io.Copy(conn, target)
}
