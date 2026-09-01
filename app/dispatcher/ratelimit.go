package dispatcher

import (
	"context"
	"sync"

	"golang.org/x/time/rate"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
)

// limiterBurst is how much a user may send in one go before the cap starts
// pacing them. One second of their own allowance, so a cap never turns a bulk
// transfer into a stream of tiny writes.
const limiterBurst = 1

// userLimiters hands out one pair of limiters per user, keyed by email.
//
// Keeping them per user rather than per connection is the whole point: a cap
// that resets with every new connection is no cap at all.
type userLimiters struct {
	mu   sync.Mutex
	up   map[string]*rate.Limiter
	down map[string]*rate.Limiter
}

func newUserLimiters() *userLimiters {
	return &userLimiters{
		up:   map[string]*rate.Limiter{},
		down: map[string]*rate.Limiter{},
	}
}

func (l *userLimiters) forUser(table map[string]*rate.Limiter, email string, bps uint64) *rate.Limiter {
	if bps == 0 || email == "" {
		return nil
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	limiter, ok := table[email]
	if !ok {
		limiter = rate.NewLimiter(rate.Limit(bps), int(bps)*limiterBurst)
		table[email] = limiter
	}
	return limiter
}

// Uplink and Downlink return the limiters for one user, or nil when uncapped
func (l *userLimiters) Uplink(email string, bps uint64) *rate.Limiter {
	return l.forUser(l.up, email, bps)
}

func (l *userLimiters) Downlink(email string, bps uint64) *rate.Limiter {
	return l.forUser(l.down, email, bps)
}

// Forget drops a user's limiters, so a profile taken off an inbound stops
// costing memory
func (l *userLimiters) Forget(email string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	delete(l.up, email)
	delete(l.down, email)
}

// rateLimitWriter paces one user's traffic to the cap their policy level sets.
//
// The limiter is shared across every connection the user has: a cap applied per
// connection is no cap at all, since opening a second connection would double it.
type rateLimitWriter struct {
	writer  buf.Writer
	limiter *rate.Limiter
}

func newRateLimitWriter(writer buf.Writer, limiter *rate.Limiter) buf.Writer {
	if limiter == nil {
		return writer
	}
	return &rateLimitWriter{writer: writer, limiter: limiter}
}

// WriteMultiBuffer waits out the debt before passing the buffer on.
//
// A burst larger than the bucket can never be granted in one call, so it is
// paid for in bucket-sized instalments instead of failing the connection.
func (w *rateLimitWriter) WriteMultiBuffer(mb buf.MultiBuffer) error {
	size := int(mb.Len())
	for size > 0 {
		chunk := size
		if burst := w.limiter.Burst(); burst > 0 && chunk > burst {
			chunk = burst
		}
		if err := w.limiter.WaitN(context.Background(), chunk); err != nil {
			break
		}
		size -= chunk
	}
	return w.writer.WriteMultiBuffer(mb)
}

func (w *rateLimitWriter) Close() error {
	return common.Close(w.writer)
}

func (w *rateLimitWriter) Interrupt() {
	common.Interrupt(w.writer)
}
