package impersonate_test

import (
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/isaackogan/tls-impersonate-proxy/internal/directive"
	"github.com/isaackogan/tls-impersonate-proxy/internal/impersonate"
)

type counting struct{ hits, misses, builds, evictions atomic.Int64 }

func (c *counting) CacheHit()                  { c.hits.Add(1) }
func (c *counting) CacheMiss()                 { c.misses.Add(1) }
func (c *counting) ClientBuilt(directive.Spec) { c.builds.Add(1) }
func (c *counting) ClientEvicted()             { c.evictions.Add(1) }

func newCache(t *testing.T, max int, ttl time.Duration, obs *counting) (*impersonate.Cache, *atomic.Int64) {
	t.Helper()
	var built atomic.Int64
	c := impersonate.NewCache(impersonate.CacheOptions{Max: max, IdleTtl: ttl}, func(s directive.Spec) (*impersonate.Client, error) {
		built.Add(1)
		if s.Proxy == "http://bad:1" {
			return nil, errors.New("bad proxy")
		}
		return impersonate.Build(s, impersonate.Options{})
	}, obs)
	t.Cleanup(c.Close)
	return c, &built
}

func TestCacheHitMissAndSingleFlight(t *testing.T) {
	obs := &counting{}
	c, built := newCache(t, 10, time.Hour, obs)
	s := spec(t, "X-Tip-Browser", "chrome")
	var wg sync.WaitGroup
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			client, err := c.Get(s)
			if err != nil {
				t.Error(err)
				return
			}
			client.Release()
		}()
	}
	wg.Wait()
	if built.Load() != 1 || c.Len() != 1 || obs.builds.Load() != 1 || obs.hits.Load()+obs.misses.Load() != 8 {
		t.Fatalf("built=%d len=%d hits=%d misses=%d", built.Load(), c.Len(), obs.hits.Load(), obs.misses.Load())
	}
}

func TestCacheLRUEviction(t *testing.T) {
	obs := &counting{}
	c, _ := newCache(t, 2, time.Hour, obs)
	first, _ := c.Get(spec(t, "X-Tip-Browser", "chrome"))
	first.Release()
	second, _ := c.Get(spec(t, "X-Tip-Browser", "firefox"))
	second.Release()
	again, _ := c.Get(spec(t, "X-Tip-Browser", "chrome"))
	again.Release()
	third, _ := c.Get(spec(t, "X-Tip-Browser", "chrome", "X-Tip-Os", "linux"))
	third.Release()
	if c.Len() != 2 || obs.evictions.Load() != 1 {
		t.Fatalf("len=%d evictions=%d", c.Len(), obs.evictions.Load())
	}
	if _, err := c.Get(spec(t, "X-Tip-Browser", "chrome")); err != nil || obs.misses.Load() != 3 {
		t.Fatalf("chrome should have survived as most recent; misses=%d", obs.misses.Load())
	}
}

func TestCacheSweepEvictsIdle(t *testing.T) {
	obs := &counting{}
	c, _ := newCache(t, 10, time.Minute, obs)
	client, _ := c.Get(spec(t, "X-Tip-Browser", "chrome"))
	client.Release()
	if n := c.Sweep(time.Now().Add(30 * time.Second)); n != 0 {
		t.Fatalf("swept %d early", n)
	}
	if n := c.Sweep(time.Now().Add(2 * time.Minute)); n != 1 || c.Len() != 0 {
		t.Fatalf("swept %d, len %d", n, c.Len())
	}
}

func TestBuildErrorsAreNotCached(t *testing.T) {
	obs := &counting{}
	c, built := newCache(t, 10, time.Hour, obs)
	s := spec(t, "X-Tip-Proxy", "http://bad:1")
	for range 2 {
		if _, err := c.Get(s); err == nil {
			t.Fatal("expected error")
		}
	}
	if built.Load() != 2 || c.Len() != 0 {
		t.Fatalf("built=%d len=%d", built.Load(), c.Len())
	}
}
