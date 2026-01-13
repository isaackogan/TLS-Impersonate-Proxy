package impersonate

import (
	"context"
	"errors"
	"net"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

type Client struct {
	Key       string
	transport http.RoundTripper
	closer    interface {
		Close() error
		CloseIdleConnections()
	}
	inflight  atomic.Int64
	lastUsed  atomic.Int64
	retired   atomic.Bool
	closed    atomic.Bool
	closeOnce sync.Once
}

var ErrClosed = errors.New("impersonate: client is closed")

func (c *Client) RoundTrip(r *http.Request) (*http.Response, error) {
	if c.closed.Load() {
		return nil, ErrClosed
	}
	return c.transport.RoundTrip(r)
}

func (c *Client) Release() {
	if c.inflight.Add(-1) == 0 && c.retired.Load() {
		c.Close()
	}
}

func (c *Client) Close() error {
	c.closeOnce.Do(func() {
		c.closed.Store(true)
		c.closer.Close()
	})
	return nil
}

func (c *Client) acquire(now time.Time) {
	c.inflight.Add(1)
	c.lastUsed.Store(now.UnixNano())
}

func (c *Client) retire() {
	c.retired.Store(true)
	c.closer.CloseIdleConnections()
	if c.inflight.Load() == 0 {
		c.Close()
	}
}

func Classify(err error) string {
	var netErr net.Error
	var opErr *net.OpError
	msg := strings.ToLower(err.Error())
	switch {
	case errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
		return "timeout"
	case errors.As(err, &netErr) && netErr.Timeout():
		return "timeout"
	case strings.Contains(msg, "proxy"):
		return "proxy"
	case strings.Contains(msg, "tls") || strings.Contains(msg, "certificate") || strings.Contains(msg, "handshake"):
		return "tls"
	case errors.As(err, &opErr) && opErr.Op == "dial":
		return "dial"
	case strings.Contains(msg, "dial"):
		return "dial"
	}
	return "read"
}
