package cache

import (
	"errors"
	"sync"
	"time"
)

// ErrDisposed is returned by a cache method called after Dispose.
var ErrDisposed = errors.New("cache: cache has been disposed")

// Loader resolves the fresh value for a cache key (e.g. fetch a JWKS).
type Loader[V any] func(key string) (V, error)

// Options configures a MemoryKeyCache.
type Options[V any] struct {
	// TTL is how long a loaded value stays fresh. Required (> 0).
	TTL time.Duration

	// Loader resolves a fresh value for a key. Invoked at most once per key
	// concurrently (single-flight).
	Loader Loader[V]

	// StaleIfError: if a refresh of an already-cached key fails, keep serving the
	// previous value for up to this long past its TTL instead of erroring. Zero
	// defaults to TTL; a negative value disables it.
	StaleIfError time.Duration

	// RefreshInterval, when > 0, starts a background goroutine that proactively
	// refreshes every live key on this interval. Stop it with Dispose.
	RefreshInterval time.Duration

	// Clock is an injectable clock. Defaults to SystemClock.
	Clock Clock

	// OnError is an optional hook for observability (e.g. a failed background or
	// stale-served refresh).
	OnError func(key string, err error)
}

type entry[V any] struct {
	value     V
	expiresAt time.Time
}

type call[V any] struct {
	wg    sync.WaitGroup
	value V
	err   error
}

// MemoryKeyCache is an in-memory, per-key TTL cache with single-flight load
// deduplication, stale-if-error fallback, and optional background refresh.
//
// Guarantees:
//   - Single-flight: N concurrent Get(key) calls during a miss trigger the
//     loader exactly once; all callers receive the same result.
//   - TTL + lazy eviction: stale entries are reloaded on access.
//   - Stale-if-error: a failed refresh of a previously-good key serves the old
//     value within a grace window rather than failing.
type MemoryKeyCache[V any] struct {
	ttl          time.Duration
	staleIfError time.Duration
	loader       Loader[V]
	clock        Clock
	onError      func(string, error)

	mu       sync.Mutex
	entries  map[string]entry[V]
	inflight map[string]*call[V]
	disposed bool

	stop     chan struct{}
	stopOnce sync.Once
}

// New constructs a MemoryKeyCache. It panics if TTL <= 0.
func New[V any](opts Options[V]) *MemoryKeyCache[V] {
	if opts.TTL <= 0 {
		panic("cache: TTL must be greater than 0")
	}
	stale := opts.StaleIfError
	if stale == 0 {
		stale = opts.TTL
	}
	if stale < 0 {
		stale = 0
	}
	clk := opts.Clock
	if clk == nil {
		clk = SystemClock
	}
	c := &MemoryKeyCache[V]{
		ttl:          opts.TTL,
		staleIfError: stale,
		loader:       opts.Loader,
		clock:        clk,
		onError:      opts.OnError,
		entries:      make(map[string]entry[V]),
		inflight:     make(map[string]*call[V]),
		stop:         make(chan struct{}),
	}
	if opts.RefreshInterval > 0 {
		go c.refreshLoop(opts.RefreshInterval)
	}
	return c
}

// Get resolves the value for key, loading it if absent or stale. Concurrent
// calls for the same key share a single load.
func (c *MemoryKeyCache[V]) Get(key string) (V, error) {
	c.mu.Lock()
	if e, ok := c.entries[key]; ok && !c.isExpired(e) {
		v := e.value
		c.mu.Unlock()
		return v, nil
	}
	c.mu.Unlock()
	return c.load(key, false)
}

// Refresh forces a reload of key, bypassing the freshness check but still
// deduplicating with any in-flight load.
func (c *MemoryKeyCache[V]) Refresh(key string) (V, error) {
	return c.load(key, true)
}

// Peek returns the cached value without loading. ok is false if absent/expired.
func (c *MemoryKeyCache[V]) Peek(key string) (V, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if e, ok := c.entries[key]; ok && !c.isExpired(e) {
		return e.value, true
	}
	var zero V
	return zero, false
}

// Has reports whether a fresh (non-expired) entry exists for key.
func (c *MemoryKeyCache[V]) Has(key string) bool {
	_, ok := c.Peek(key)
	return ok
}

// Delete removes a single key's cached value.
func (c *MemoryKeyCache[V]) Delete(key string) {
	c.mu.Lock()
	delete(c.entries, key)
	c.mu.Unlock()
}

// Size returns the number of entries currently held (including expired-but-not-swept).
func (c *MemoryKeyCache[V]) Size() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.entries)
}

// EvictExpired drops every expired entry and returns the count removed.
func (c *MemoryKeyCache[V]) EvictExpired() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	removed := 0
	for k, e := range c.entries {
		if c.isExpired(e) {
			delete(c.entries, k)
			removed++
		}
	}
	return removed
}

// Dispose stops the background refresh timer and drops all state. Idempotent.
func (c *MemoryKeyCache[V]) Dispose() {
	c.mu.Lock()
	c.disposed = true
	c.entries = make(map[string]entry[V])
	c.mu.Unlock()
	c.stopOnce.Do(func() { close(c.stop) })
}

func (c *MemoryKeyCache[V]) isExpired(e entry[V]) bool {
	return !c.clock.Now().Before(e.expiresAt)
}

// load is the single-flight core.
func (c *MemoryKeyCache[V]) load(key string, force bool) (V, error) {
	c.mu.Lock()
	if c.disposed {
		c.mu.Unlock()
		var zero V
		return zero, ErrDisposed
	}
	// Re-check freshness for non-forced loads: a value may have been populated
	// between the caller's Get check and acquiring the single-flight slot.
	if !force {
		if e, ok := c.entries[key]; ok && !c.isExpired(e) {
			v := e.value
			c.mu.Unlock()
			return v, nil
		}
	}
	if cl, ok := c.inflight[key]; ok {
		c.mu.Unlock()
		cl.wg.Wait()
		return cl.value, cl.err
	}
	cl := &call[V]{}
	cl.wg.Add(1)
	c.inflight[key] = cl
	c.mu.Unlock()

	value, err := c.loader(key)

	c.mu.Lock()
	var onErr func(string, error)
	if err != nil {
		// Stale-if-error: if we still hold a value within the grace window, serve
		// it rather than propagating a transient loader failure.
		if e, ok := c.entries[key]; ok && c.clock.Now().Before(e.expiresAt.Add(c.staleIfError)) {
			cl.value, cl.err = e.value, nil
			onErr = c.onError
		} else {
			cl.err = err
		}
	} else {
		c.entries[key] = entry[V]{value: value, expiresAt: c.clock.Now().Add(c.ttl)}
		cl.value = value
	}
	delete(c.inflight, key)
	c.mu.Unlock()
	cl.wg.Done()

	if onErr != nil {
		onErr(key, err)
	}
	return cl.value, cl.err
}

func (c *MemoryKeyCache[V]) refreshLoop(interval time.Duration) {
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-c.stop:
			return
		case <-t.C:
			c.mu.Lock()
			keys := make([]string, 0, len(c.entries))
			for k := range c.entries {
				keys = append(keys, k)
			}
			c.mu.Unlock()
			for _, k := range keys {
				if _, err := c.Refresh(k); err != nil && c.onError != nil {
					c.onError(k, err)
				}
			}
		}
	}
}
