package authevent

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"
)

type testSink struct {
	mu      sync.Mutex
	events  []Event
	fail    bool
	started chan struct{}
	block   bool
}

func (sink *testSink) write(ctx context.Context, event Event) error {
	sink.mu.Lock()
	sink.events = append(sink.events, event)
	sink.mu.Unlock()
	if sink.started != nil {
		select {
		case sink.started <- struct{}{}:
		default:
		}
	}
	if sink.block {
		<-ctx.Done()
		return ctx.Err()
	}
	if sink.fail {
		return errors.New("synthetic failure containing private provider data")
	}
	return nil
}
func (*testSink) cleanup(context.Context) (time.Duration, error) { return 0, nil }
func testLimits() limits {
	return limits{2, 3, 20 * time.Millisecond, time.Second, time.Millisecond, time.Hour}
}
func sampleEvent() Event { return Event{Type: "sms.send", Outcome: "succeeded", Purpose: "login"} }

func TestRetryKeepsIdentityAndIsBounded(t *testing.T) {
	sink := &testSink{fail: true}
	recorder := newRecorder(sink, testLimits())
	if !recorder.Offer(sampleEvent()) {
		t.Fatal("event refused")
	}
	recorder.Close(time.Second)
	if len(sink.events) != 3 || sink.events[0].EventID == "" || sink.events[0] != sink.events[1] || sink.events[1] != sink.events[2] {
		t.Fatal("retry changed the captured event")
	}
	stats := recorder.Stats()
	if stats.WriteFailures != 3 || stats.RetryExhausted != 1 || stats.Dropped != 1 || stats.WriterHealthy {
		t.Fatal(stats)
	}
}

func TestFullQueueAndBoundedShutdown(t *testing.T) {
	sink := &testSink{block: true, started: make(chan struct{}, 1)}
	bounds := testLimits()
	bounds.timeout = time.Hour
	recorder := newRecorder(sink, bounds)
	recorder.Offer(sampleEvent())
	<-sink.started
	for range bounds.capacity {
		if !recorder.Offer(sampleEvent()) {
			t.Fatal("queue refused capacity")
		}
	}
	start := time.Now()
	if recorder.Offer(sampleEvent()) || time.Since(start) > 100*time.Millisecond {
		t.Fatal("full queue waited")
	}
	recorder.Close(10 * time.Millisecond)
	if time.Since(start) > time.Second || recorder.Stats().Dropped != 4 {
		t.Fatal("shutdown did not bound or account for loss", recorder.Stats())
	}
	if recorder.Offer(sampleEvent()) {
		t.Fatal("closed writer accepted event")
	}
}

func TestCaptureAndValidation(t *testing.T) {
	sink := &testSink{}
	recorder := newRecorder(sink, testLimits())
	original := sampleEvent()
	original.Actor = Actor{Kind: "client", ID: "example-web"}
	recorder.Offer(original)
	original.Actor.ID = "changed"
	for _, event := range []Event{
		{Type: "sms.send", Outcome: "succeeded", ReasonCode: "raw provider error"},
		{Type: "sms.send", Outcome: "detected"},
		{Type: "sms.send", Outcome: "succeeded", ClientID: "line\ncontrol"},
		{Type: "sms.send", Outcome: "succeeded", Actor: Actor{ID: "unverified"}},
	} {
		if recorder.Offer(event) {
			t.Fatal("unbounded context accepted")
		}
	}
	recorder.Close(time.Second)
	if len(sink.events) != 1 || sink.events[0].Actor.ID != "example-web" || recorder.Stats().Dropped != 4 {
		t.Fatal("event changed", recorder.Stats())
	}
}

func TestQueuedEventsHaveMaximumAge(t *testing.T) {
	sink := &testSink{}
	recorder := newRecorder(sink, testLimits())
	event := sampleEvent()
	event.EventID = NewID()
	event.OccurredAt = time.Now()
	recorder.queue <- pending{event, time.Now().Add(-time.Minute)}
	recorder.Close(time.Second)
	if len(sink.events) != 0 || recorder.Stats().Expired != 1 {
		t.Fatal(recorder.Stats())
	}
}
