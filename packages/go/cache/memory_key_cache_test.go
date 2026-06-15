package cache

import (
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type fakeClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *fakeClock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

func newFakeClock() *fakeClock { return &fakeClock{t: time.Unix(1_700_000_000, 0)} }

func TestGetLoadsAndCaches(t *testing.T) {
	var calls int32
	clk := newFakeClock()
	c := New[string](Options[string]{
		TTL:   time.Minute,
		Clock: clk,
		Loader: func(key string) (string, error) {
			atomic.AddInt32(&calls, 1)
			return "v:" + key, nil
		},
	})
	defer c.Dispose()

	for i := 0; i < 3; i++ {
		got, err := c.Get("k")
		if err != nil || got != "v:k" {
			t.Fatalf("Get = %q, %v", got, err)
		}
	}
	if calls != 1 {
		t.Fatalf("loader called %d times, want 1 (cached)", calls)
	}
}

func TestTTLExpiryReloads(t *testing.T) {
	var calls int32
	clk := newFakeClock()
	c := New[int](Options[int]{
		TTL:   time.Minute,
		Clock: clk,
		Loader: func(string) (int, error) {
			return int(atomic.AddInt32(&calls, 1)), nil
		},
	})
	defer c.Dispose()

	if v, _ := c.Get("k"); v != 1 {
		t.Fatalf("first load = %d", v)
	}
	clk.Advance(30 * time.Second)
	if v, _ := c.Get("k"); v != 1 {
		t.Fatalf("within TTL = %d, want cached 1", v)
	}
	clk.Advance(31 * time.Second) // now past TTL
	if v, _ := c.Get("k"); v != 2 {
		t.Fatalf("after TTL = %d, want reloaded 2", v)
	}
}

func TestSingleFlight(t *testing.T) {
	var calls int32
	release := make(chan struct{})
	c := New[string](Options[string]{
		TTL:   time.Minute,
		Clock: newFakeClock(),
		Loader: func(key string) (string, error) {
			atomic.AddInt32(&calls, 1)
			<-release // hold all concurrent callers on a single in-flight load
			return "value", nil
		},
	})
	defer c.Dispose()

	const n = 20
	var wg sync.WaitGroup
	wg.Add(n)
	for i := 0; i < n; i++ {
		go func() {
			defer wg.Done()
			if v, err := c.Get("k"); err != nil || v != "value" {
				t.Errorf("Get = %q, %v", v, err)
			}
		}()
	}
	time.Sleep(20 * time.Millisecond) // let goroutines pile up on the load
	close(release)
	wg.Wait()
	if calls != 1 {
		t.Fatalf("loader called %d times, want 1 (single-flight)", calls)
	}
}

func TestStaleIfError(t *testing.T) {
	var fail atomic.Bool
	clk := newFakeClock()
	c := New[string](Options[string]{
		TTL:          time.Minute,
		StaleIfError: time.Minute,
		Clock:        clk,
		Loader: func(string) (string, error) {
			if fail.Load() {
				return "", errors.New("boom")
			}
			return "fresh", nil
		},
	})
	defer c.Dispose()

	if v, _ := c.Get("k"); v != "fresh" {
		t.Fatalf("seed load = %q", v)
	}
	fail.Store(true)
	clk.Advance(90 * time.Second) // past TTL, within stale window

	v, err := c.Get("k")
	if err != nil || v != "fresh" {
		t.Fatalf("stale-if-error Get = %q, %v; want cached 'fresh'", v, err)
	}

	clk.Advance(time.Hour) // now past the stale window too
	if _, err := c.Get("k"); err == nil {
		t.Fatal("expected error past the stale window")
	}
}

func TestDispose(t *testing.T) {
	c := New[string](Options[string]{
		TTL:    time.Minute,
		Clock:  newFakeClock(),
		Loader: func(string) (string, error) { return "v", nil },
	})
	c.Dispose()
	if _, err := c.Get("k"); !errors.Is(err, ErrDisposed) {
		t.Fatalf("Get after Dispose = %v, want ErrDisposed", err)
	}
}
