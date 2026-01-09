package testutil

import (
	"compress/gzip"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
)

type Recorded struct {
	Method string
	Path   string
	Proto  string
	Header http.Header
	Body   []byte
}

type Upstream struct {
	*httptest.Server
	mu       sync.Mutex
	requests []Recorded
}

func NewUpstream(t testing.TB) *Upstream {
	t.Helper()
	u := &Upstream{}
	u.Server = httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		u.mu.Lock()
		u.requests = append(u.requests, Recorded{r.Method, r.URL.Path, r.Proto, r.Header.Clone(), body})
		u.mu.Unlock()
		payload, _ := json.Marshal(map[string]any{"proto": r.Proto, "headers": r.Header, "path": r.URL.Path})
		w.Header().Set("Content-Type", "application/json")
		if r.Header.Get("X-Upstream-Encoding") == "gzip" {
			w.Header().Set("Content-Encoding", "gzip")
			zw := gzip.NewWriter(w)
			zw.Write(payload)
			zw.Close()
			return
		}
		w.Write(payload)
	}))
	u.Server.EnableHTTP2 = true
	u.Server.StartTLS()
	t.Cleanup(u.Server.Close)
	return u
}

func (u *Upstream) Requests() []Recorded {
	u.mu.Lock()
	defer u.mu.Unlock()
	return append([]Recorded(nil), u.requests...)
}

func (u *Upstream) Last(t testing.TB) Recorded {
	t.Helper()
	rs := u.Requests()
	if len(rs) == 0 {
		t.Fatal("upstream saw no requests")
	}
	return rs[len(rs)-1]
}
