package httpapi

import (
	"sync"
	"time"

	"golang.org/x/time/rate"
)

// limiter throttles login attempts per key.
type limiter struct {
	mu      sync.Mutex
	every   time.Duration
	burst   int
	buckets map[string]*bucket
	sweep   time.Time
}

type bucket struct {
	lim  *rate.Limiter
	seen time.Time
}

func newLimiter(every time.Duration, burst int) *limiter {
	if every <= 0 {
		every = 6 * time.Second
	}
	if burst <= 0 {
		burst = 10
	}
	return &limiter{every: every, burst: burst, buckets: map[string]*bucket{}}
}

// allow reports whether every key still has budget, and spends it.
func (l *limiter) allow(keys ...string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := time.Now()
	if now.Sub(l.sweep) > time.Minute {
		for k, b := range l.buckets {
			if now.Sub(b.seen) > time.Duration(l.burst)*l.every {
				delete(l.buckets, k)
			}
		}
		l.sweep = now
	}
	ok := true
	for _, k := range keys {
		b := l.buckets[k]
		if b == nil {
			b = &bucket{lim: rate.NewLimiter(rate.Every(l.every), l.burst)}
			l.buckets[k] = b
		}
		b.seen = now
		if !b.lim.AllowN(now, 1) {
			ok = false
		}
	}
	return ok
}
