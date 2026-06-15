// Package cache provides an in-memory, per-key TTL cache with single-flight load
// deduplication, used to hold JWKS key sets. It is value-generic and knows
// nothing about what it caches, keeping it provider-agnostic.
package cache

import "time"

// Clock is an injectable time source. Production uses SystemClock; tests pass a
// fake clock to make TTL/expiry behavior deterministic without real timers.
type Clock interface {
	Now() time.Time
}

type systemClock struct{}

func (systemClock) Now() time.Time { return time.Now() }

// SystemClock is the default clock, backed by time.Now.
var SystemClock Clock = systemClock{}
