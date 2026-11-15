package authevent

import (
	"context"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"
)

type sink interface {
	write(context.Context, Event) error
	cleanup(context.Context) (time.Duration, error)
}
type limits struct {
	capacity, attempts                       int
	timeout, maxAge, retryDelay, maintenance time.Duration
}

func defaults() limits {
	return limits{256, 3, 2 * time.Second, 30 * time.Second, 100 * time.Millisecond, time.Minute}
}

type pending struct {
	event     Event
	offeredAt time.Time
}

type Recorder struct {
	sink                                                            sink
	limits                                                          limits
	queue                                                           chan pending
	mu                                                              sync.RWMutex
	closed                                                          bool
	done                                                            chan struct{}
	cancel                                                          context.CancelFunc
	closeSink                                                       func()
	closeOnce                                                       sync.Once
	written, failures, exhausted, dropped, expired, cleanupFailures atomic.Uint64
	healthy                                                         atomic.Bool
	cleanupLag                                                      atomic.Int64
	lastCleanup                                                     atomic.Int64
}

type Stats struct {
	QueueDepth        int    `json:"queueDepth"`
	Written           uint64 `json:"written"`
	WriteFailures     uint64 `json:"writeFailures"`
	RetryExhausted    uint64 `json:"retryExhausted"`
	Dropped           uint64 `json:"dropped"`
	Expired           uint64 `json:"expired"`
	WriterHealthy     bool   `json:"writerHealthy"`
	CleanupFailures   uint64 `json:"cleanupFailures"`
	CleanupLagSeconds int64  `json:"cleanupLagSeconds"`
	LastCleanupUnix   int64  `json:"lastCleanupUnix"`
}

func newRecorder(sink sink, bounds limits) *Recorder {
	ctx, cancel := context.WithCancel(context.Background())
	recorder := &Recorder{sink: sink, limits: bounds, queue: make(chan pending, bounds.capacity), done: make(chan struct{}), cancel: cancel}
	recorder.healthy.Store(true)
	go recorder.run(ctx)
	return recorder
}

// Offer never waits for persistence or capacity. The value contains only scalars.
// A nil recorder is an unavailable writer, not a reason to fail the operation.
func (recorder *Recorder) Offer(event Event) bool {
	if recorder == nil {
		return false
	}
	if event.EventID == "" {
		event.EventID = NewID()
	}
	if event.OccurredAt.IsZero() {
		event.OccurredAt = time.Now().UTC()
	}
	event.RecordedAt = time.Time{}
	if !event.valid() {
		recorder.dropped.Add(1)
		return false
	}
	recorder.mu.RLock()
	defer recorder.mu.RUnlock()
	if !recorder.closed {
		select {
		case recorder.queue <- pending{event, time.Now()}:
			return true
		default:
		}
	}
	recorder.dropped.Add(1)
	return false
}

func (recorder *Recorder) Stats() Stats {
	return Stats{len(recorder.queue), recorder.written.Load(), recorder.failures.Load(), recorder.exhausted.Load(), recorder.dropped.Load(), recorder.expired.Load(), recorder.healthy.Load(), recorder.cleanupFailures.Load(), recorder.cleanupLag.Load(), recorder.lastCleanup.Load()}
}

// Drop accounts for events omitted by a bounded bulk producer after its business
// transaction. It never changes that transaction or attempts audit persistence.
func (recorder *Recorder) Drop(count uint64) {
	if recorder != nil {
		recorder.dropped.Add(count)
	}
}

// Close permits a bounded drain independent of canceled HTTP/server contexts.
func (recorder *Recorder) Close(timeout time.Duration) {
	if recorder == nil {
		return
	}
	recorder.closeOnce.Do(func() {
		recorder.mu.Lock()
		recorder.closed = true
		close(recorder.queue)
		recorder.mu.Unlock()
		timer := time.NewTimer(timeout)
		defer timer.Stop()
		select {
		case <-recorder.done:
		case <-timer.C:
			recorder.cancel()
			<-recorder.done
		}
		recorder.cancel()
		recorder.report()
		if recorder.closeSink != nil {
			recorder.closeSink()
		}
	})
}

func (recorder *Recorder) run(ctx context.Context) {
	defer close(recorder.done)
	var maintenance <-chan time.Time
	if recorder.limits.maintenance > 0 {
		ticker := time.NewTicker(recorder.limits.maintenance)
		defer ticker.Stop()
		maintenance = ticker.C
	}
	for {
		select {
		case <-ctx.Done():
			for range recorder.queue {
				recorder.dropped.Add(1)
			}
			return
		case item, ok := <-recorder.queue:
			if !ok {
				return
			}
			recorder.deliver(ctx, item)
		case <-maintenance:
			timeout, cancel := context.WithTimeout(ctx, recorder.limits.timeout)
			lag, err := recorder.sink.cleanup(timeout)
			cancel()
			if err != nil {
				recorder.cleanupFailures.Add(1)
			} else {
				recorder.cleanupLag.Store(int64(lag.Seconds()))
				recorder.lastCleanup.Store(time.Now().Unix())
			}
			recorder.report()
		}
	}
}

func (recorder *Recorder) deliver(ctx context.Context, item pending) {
	for attempt := 0; attempt < recorder.limits.attempts; attempt++ {
		if ctx.Err() != nil {
			recorder.dropped.Add(1)
			return
		}
		if time.Since(item.offeredAt) > recorder.limits.maxAge {
			recorder.expired.Add(1)
			recorder.dropped.Add(1)
			return
		}
		timeout, cancel := context.WithTimeout(ctx, recorder.limits.timeout)
		err := recorder.sink.write(timeout, item.event)
		cancel()
		recorder.healthy.Store(err == nil)
		if err == nil {
			recorder.written.Add(1)
			return
		}
		recorder.failures.Add(1)
		if attempt+1 < recorder.limits.attempts {
			timer := time.NewTimer(recorder.limits.retryDelay * time.Duration(attempt+1))
			select {
			case <-ctx.Done():
				timer.Stop()
				recorder.dropped.Add(1)
				return
			case <-timer.C:
			}
		}
	}
	recorder.exhausted.Add(1)
	recorder.dropped.Add(1)
}

// One summary per minute (and shutdown), never raw errors or event payloads.
func (recorder *Recorder) report() {
	stats := recorder.Stats()
	level := slog.LevelInfo
	if !stats.WriterHealthy || stats.Dropped > 0 || stats.CleanupFailures > 0 || stats.CleanupLagSeconds > 0 {
		level = slog.LevelWarn
	}
	slog.Log(context.Background(), level, "Authentication event delivery status", "status", stats)
}
