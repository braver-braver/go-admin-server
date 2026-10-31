package httpapi

import (
	"encoding/json"
	"io"
	"math"
	"net/http"
	"strconv"
	"sync"
	"time"

	"golang.org/x/time/rate"

	"github.com/braver-braver/go-admin-server/internal/apierr"
)

// writeData sends `{ "data": v }`.
func writeData(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]any{"data": v})
}

// writeError sends `{ "error": { "code", "message" } }`.
func writeError(w http.ResponseWriter, e *apierr.Error) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(e.Status)
	_ = json.NewEncoder(w).Encode(map[string]any{"error": map[string]string{"code": e.Code, "message": e.Message}})
}

const maxJSONBody = 1 << 20

// readJSON reads a JSON body. It returns nil for an empty or invalid body;
// callers decide whether that is an error.
func readJSON(w http.ResponseWriter, r *http.Request) []byte {
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxJSONBody))
	if err != nil || !json.Valid(body) {
		return nil
	}
	return body
}

// positiveInt parses a positive integer query value, else returns fallback
// (users and audit lists).
func positiveInt(v string, fallback int) int {
	f, err := strconv.ParseFloat(v, 64)
	if err != nil || math.IsNaN(f) || math.IsInf(f, 0) || f <= 0 {
		return fallback
	}
	if f >= math.MaxInt32 {
		return math.MaxInt32
	}
	return int(math.Floor(f))
}

// pageSizeOf clamps pageSize to [1, 100] (decision D3).
func pageSizeOf(v string) int { return min(100, positiveInt(v, 10)) }

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
