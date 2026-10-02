// Package ratelimit is a small in-memory sliding-window limiter keyed by an
// arbitrary string (client IP, code hint, token). Good enough for a single
// process; counters are reset on restart, which is acceptable here.
package ratelimit

import (
	"sync"
	"time"
)

type Limiter struct {
	mu     sync.Mutex
	limit  int
	window time.Duration
	hits   map[string][]time.Time
	now    func() time.Time
}

func New(limit int, window time.Duration) *Limiter {
	return &Limiter{limit: limit, window: window, hits: map[string][]time.Time{}, now: time.Now}
}

// Allow records an attempt for key and reports whether it is within limits.
func (l *Limiter) Allow(key string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	cut := now.Add(-l.window)
	kept := l.hits[key][:0]
	for _, t := range l.hits[key] {
		if t.After(cut) {
			kept = append(kept, t)
		}
	}
	if len(kept) >= l.limit {
		l.hits[key] = kept
		return false
	}
	l.hits[key] = append(kept, now)
	if len(l.hits) > 50000 { // crude memory bound
		l.hits = map[string][]time.Time{}
	}
	return true
}

// SetClock is for tests.
func (l *Limiter) SetClock(f func() time.Time) { l.now = f }
