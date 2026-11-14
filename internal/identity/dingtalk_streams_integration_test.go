//go:build integration

package identity

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/euyuil/memberid/internal/dingtalk"
)

type streamInvocation struct {
	secret       string
	consume      func(context.Context, dingtalk.DirectoryEvent) error
	disconnected chan struct{}
	stopped      chan struct{}
}

type fakeStreamProvider struct {
	DingTalkDirectoryProvider
	calls     chan streamInvocation
	connected bool
}

func (provider *fakeStreamProvider) Stream(ctx context.Context, _, secret string, connected func(), consume func(context.Context, dingtalk.DirectoryEvent) error) error {
	call := streamInvocation{secret, consume, make(chan struct{}), make(chan struct{})}
	defer close(call.stopped)
	select {
	case provider.calls <- call:
	case <-ctx.Done():
		return ctx.Err()
	}
	if provider.connected {
		connected()
	}
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-call.disconnected:
		return dingtalk.ErrUnavailable
	}
}

func nextStream(t *testing.T, calls <-chan streamInvocation) streamInvocation {
	t.Helper()
	select {
	case call := <-calls:
		return call
	case <-time.After(10 * time.Second):
		t.Fatal("stream did not connect")
		return streamInvocation{}
	}
}

func eventuallyStream(t *testing.T, condition func() bool) {
	t.Helper()
	timeout := time.NewTimer(10 * time.Second)
	defer timeout.Stop()
	ticker := time.NewTicker(5 * time.Millisecond)
	defer ticker.Stop()
	for {
		if condition() {
			return
		}
		select {
		case <-timeout.C:
			t.Fatal("stream state did not converge")
		case <-ticker.C:
		}
	}
}

func TestStreamSupervisorTracksConfigurationAndOrganizationLifecycle(t *testing.T) {
	store, apps, directory, _, app, _ := reconciliationFixture(t)
	provider := &fakeStreamProvider{DingTalkDirectoryProvider: directory.provider, calls: make(chan streamInvocation, 10)}
	directory.provider = provider
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan struct{})
	go func() {
		defer close(done)
		directory.superviseStreams(ctx, synchronizationTiming{time.Hour, 20 * time.Millisecond, 20 * time.Millisecond}, nil)
	}()
	t.Cleanup(func() { cancel(); waitWorker(t, done) })
	first := nextStream(t, provider.calls)
	for range 3 {
		if _, err := apps.SynchronizeAuthorization(t.Context(), app.OrganizationID); err != nil {
			t.Fatal(err)
		}
	}
	select {
	case <-provider.calls:
		t.Fatal("routine observation restarted stream")
	case <-time.After(80 * time.Millisecond):
	}
	rotated, err := apps.Configure(t.Context(), OperatorPrincipal(), app.OrganizationID, DingTalkApplicationInput{CorpID: app.CorpID, ClientID: app.ClientID, ClientSecret: "rotated-synthetic-secret", ExpectedRevision: app.Revision})
	if err != nil {
		t.Fatal(err)
	}
	waitWorker(t, first.stopped)
	second := nextStream(t, provider.calls)
	if first.secret == second.secret || second.secret != "rotated-synthetic-secret" {
		t.Fatal("stream retained obsolete credentials")
	}
	event := directoryEvent(app, "stale", "user_leave_org", time.Now().UnixMilli())
	if err := first.consume(t.Context(), event); !errors.Is(err, ErrConflict) {
		t.Fatal("old stream changed state", err)
	}
	disabled := "disabled"
	if _, err := store.UpdateOrganization(t.Context(), OperatorPrincipal(), app.OrganizationID, OrganizationChange{Status: &disabled}); err != nil {
		t.Fatal(err)
	}
	waitWorker(t, second.stopped)
	enabled := "enabled"
	if _, err := store.UpdateOrganization(t.Context(), OperatorPrincipal(), app.OrganizationID, OrganizationChange{Status: &enabled}); err != nil {
		t.Fatal(err)
	}
	third := nextStream(t, provider.calls)
	if err := second.consume(t.Context(), event); !errors.Is(err, ErrConflict) {
		t.Fatal("disabled stream survived lifecycle", err)
	}
	organization, err := store.Organization(t.Context(), app.OrganizationID)
	if err != nil {
		t.Fatal(err)
	}
	current, err := apps.Inspect(t.Context(), app.OrganizationID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := apps.recordAuthorization(t.Context(), current, organization.lifecycleRevision, "revoked"); err != nil {
		t.Fatal(err)
	}
	waitWorker(t, third.stopped)
	if _, err := apps.Configure(t.Context(), OperatorPrincipal(), app.OrganizationID, DingTalkApplicationInput{CorpID: app.CorpID, ClientID: app.ClientID, ClientSecret: "rotated-synthetic-secret", ExpectedRevision: rotated.Revision}); err != nil {
		t.Fatal(err)
	}
	fourth := nextStream(t, provider.calls)
	cancel()
	waitWorker(t, done)
	waitWorker(t, fourth.stopped)
}

func TestStreamReconnectAndPositiveEventsRequestFreshDirectoryChecks(t *testing.T) {
	store, _, directory, _, app, member := reconciliationFixture(t)
	provider := &fakeStreamProvider{DingTalkDirectoryProvider: directory.provider, calls: make(chan streamInvocation, 10), connected: true}
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan struct{})
	go func() {
		defer close(done)
		directory.runApplicationStream(ctx, provider, app, 20*time.Millisecond, nil)
	}()
	t.Cleanup(func() { cancel(); waitWorker(t, done) })
	first := nextStream(t, provider.calls)
	revision := func() int64 {
		t.Helper()
		var value int64
		if err := store.pool.QueryRow(t.Context(), "SELECT eligibility_revision FROM members WHERE id=$1", member.ID).Scan(&value); err != nil {
			t.Fatal(err)
		}
		return value
	}
	eventuallyStream(t, func() bool { return revision() > 0 })
	born := time.Now().UnixMilli()
	leave := directoryEvent(app, "leave", "user_leave_org", born)
	if err := first.consume(t.Context(), leave); err != nil {
		t.Fatal(err)
	}
	var departed bool
	if err := store.pool.QueryRow(t.Context(), "SELECT external_departure FROM members WHERE id=$1", member.ID).Scan(&departed); err != nil || !departed {
		t.Fatal("success preceded committed departure", err)
	}
	baseline := revision()
	if err := first.consume(t.Context(), leave); err != nil {
		t.Fatal(err)
	}
	if revision() != baseline {
		t.Fatal("duplicate changed state")
	}
	positive := directoryEvent(app, "return", "user_add_org", born+1)
	if err := first.consume(t.Context(), positive); err != nil {
		t.Fatal(err)
	}
	eventuallyStream(t, func() bool { return revision() >= baseline+2 })
	if err := store.pool.QueryRow(t.Context(), "SELECT external_departure FROM members WHERE id=$1", member.ID).Scan(&departed); err != nil || departed {
		t.Fatal("fresh return not applied", err)
	}
	baseline = revision()
	close(first.disconnected)
	waitWorker(t, first.stopped)
	second := nextStream(t, provider.calls)
	eventuallyStream(t, func() bool { return revision() > baseline })
	if err := second.consume(t.Context(), leave); err != nil {
		t.Fatal(err)
	}
	if err := store.pool.QueryRow(t.Context(), "SELECT external_departure FROM members WHERE id=$1", member.ID).Scan(&departed); err != nil || departed {
		t.Fatal("reconnected replay restored obsolete departure", err)
	}
	cancel()
	waitWorker(t, done)
	waitWorker(t, second.stopped)
}

func TestLeaderOwnsStreamsAndCancelsThemBeforeHandoff(t *testing.T) {
	_, directory, _, _ := workerFixture(t)
	provider := &fakeStreamProvider{DingTalkDirectoryProvider: directory.provider, calls: make(chan streamInvocation, 10)}
	directory.provider = provider
	stopFirst, firstDone := startSynchronization(t, directory)
	first := nextStream(t, provider.calls)
	if err := directory.synchronizeAsLeader(t.Context(), synchronizationTiming{time.Hour, time.Millisecond, time.Millisecond}, nil); err != nil {
		t.Fatal(err)
	}
	select {
	case <-provider.calls:
		t.Fatal("follower opened stream")
	default:
	}
	stopSecond, secondDone := startSynchronization(t, directory)
	stopFirst()
	waitWorker(t, firstDone)
	waitWorker(t, first.stopped)
	second := nextStream(t, provider.calls)
	stopSecond()
	waitWorker(t, secondDone)
	waitWorker(t, second.stopped)
}
