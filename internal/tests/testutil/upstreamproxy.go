package testutil

import (
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/elazarl/goproxy"
)

type UpstreamProxy struct {
	*httptest.Server
	mu       sync.Mutex
	connects []string
}

func NewUpstreamProxy(t testing.TB) *UpstreamProxy {
	t.Helper()
	p := &UpstreamProxy{}
	gp := goproxy.NewProxyHttpServer()
	gp.OnRequest().HandleConnectFunc(func(host string, ctx *goproxy.ProxyCtx) (*goproxy.ConnectAction, string) {
		p.mu.Lock()
		p.connects = append(p.connects, host)
		p.mu.Unlock()
		return goproxy.OkConnect, host
	})
	p.Server = httptest.NewServer(gp)
	t.Cleanup(p.Server.Close)
	return p
}

func (p *UpstreamProxy) Connects() []string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]string(nil), p.connects...)
}

var _ http.Handler = (*goproxy.ProxyHttpServer)(nil)
