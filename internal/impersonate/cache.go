package impersonate

import (
	"math"
	"sync"
	"time"

	"github.com/isaackogan/tls-impersonate-proxy/internal/directive"
)

type CacheOptions struct {
	Max     int
	IdleTtl time.Duration
}

type CacheObserver interface {
	CacheHit()
	CacheMiss()
	ClientBuilt(spec directive.Spec)
	ClientEvicted()
}

type NopObserver struct{}

func (NopObserver) CacheHit()                  {}
func (NopObserver) CacheMiss()                 {}
func (NopObserver) ClientBuilt(directive.Spec) {}
func (NopObserver) ClientEvicted()             {}

type pending struct {
	done   chan struct{}
	client *Client
	err    error
}

type Cache struct {
	mu      sync.Mutex
	entries map[string]*Client
	pending map[string]*pending
	build   func(directive.Spec) (*Client, error)
	opts    CacheOptions
	obs     CacheObserver
	now     func() time.Time
}

func NewCache(o CacheOptions, build func(directive.Spec) (*Client, error), obs CacheObserver) *Cache {
	if obs == nil {
		obs = NopObserver{}
	}
	return &Cache{entries: map[string]*Client{}, pending: map[string]*pending{}, build: build, opts: o, obs: obs, now: time.Now}
}

func (c *Cache) Get(s directive.Spec) (*Client, error) {
	key := s.Key()
	c.mu.Lock()
	if client, ok := c.entries[key]; ok {
		client.acquire(c.now())
		c.mu.Unlock()
		c.obs.CacheHit()
		return client, nil
	}
	if p, ok := c.pending[key]; ok {
		c.mu.Unlock()
		c.obs.CacheHit()
		<-p.done
		return c.share(p)
	}
	p := &pending{done: make(chan struct{})}
	c.pending[key] = p
	c.mu.Unlock()
	c.obs.CacheMiss()
	p.client, p.err = c.build(s)
	c.mu.Lock()
	delete(c.pending, key)
	evicted := 0
	if p.err == nil {
		evicted = c.insert(key, p.client)
		p.client.acquire(c.now())
	}
	c.mu.Unlock()
	close(p.done)
	if p.err == nil {
		c.obs.ClientBuilt(s)
	}
	for range evicted {
		c.obs.ClientEvicted()
	}
	return p.client, p.err
}

func (c *Cache) share(p *pending) (*Client, error) {
	if p.err != nil {
		return nil, p.err
	}
	c.mu.Lock()
	p.client.acquire(c.now())
	c.mu.Unlock()
	return p.client, nil
}

func (c *Cache) insert(key string, client *Client) int {
	evicted := 0
	for len(c.entries) >= c.opts.Max {
		c.evict(c.leastRecent())
		evicted++
	}
	c.entries[key] = client
	return evicted
}

func (c *Cache) leastRecent() string {
	var oldest string
	var oldestAt int64 = math.MaxInt64
	for key, client := range c.entries {
		if at := client.lastUsed.Load(); at < oldestAt {
			oldest, oldestAt = key, at
		}
	}
	return oldest
}

func (c *Cache) evict(key string) {
	client, ok := c.entries[key]
	if !ok {
		return
	}
	delete(c.entries, key)
	client.retire()
}

func (c *Cache) Sweep(now time.Time) int {
	cutoff := now.Add(-c.opts.IdleTtl).UnixNano()
	c.mu.Lock()
	n := 0
	for key, client := range c.entries {
		if client.lastUsed.Load() < cutoff && client.inflight.Load() == 0 {
			c.evict(key)
			n++
		}
	}
	c.mu.Unlock()
	for range n {
		c.obs.ClientEvicted()
	}
	return n
}

func (c *Cache) Len() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.entries)
}

func (c *Cache) Close() {
	c.mu.Lock()
	defer c.mu.Unlock()
	for key := range c.entries {
		c.evict(key)
	}
}
