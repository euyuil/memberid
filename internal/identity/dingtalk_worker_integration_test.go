//go:build integration

package identity

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	"github.com/euyuil/memberid/internal/dingtalk"
	"github.com/jackc/pgx/v5/pgxpool"
)

func workerFixture(t *testing.T) (*Store, *DingTalkDirectory, <-chan struct{}, *atomic.Int64) {
	t.Helper()
	store, apps, organization, _ := applicationFixture(t)
	if _, err := apps.Configure(t.Context(), organization.ID, DingTalkApplicationInput{CorpID: "example-corp", ClientID: "example-client", ClientSecret: "synthetic-secret"}); err != nil {
		t.Fatal(err)
	}
	// A leadership session must not exhaust a one-connection application query pool.
	configuration := store.pool.Config()
	configuration.MaxConns = 1
	store.pool.Close()
	pool, err := pgxpool.NewWithConfig(t.Context(), configuration)
	if err != nil {
		t.Fatal(err)
	}
	store.pool = pool
	notifications := make(chan struct{}, 16)
	calls := new(atomic.Int64)
	apps.checker = checkDingTalkFunc(func(context.Context, string, string, string) error {
		calls.Add(1)
		notifications <- struct{}{}
		return nil
	})
	directory, err := NewDingTalkDirectory(apps, directoryDingTalkFunc(func(context.Context, string, string, string, string) (dingtalk.Member, error) {
		t.Error("worker invented a directory identity")
		return dingtalk.Member{}, dingtalk.ErrUnavailable
	}))
	if err != nil {
		t.Fatal(err)
	}
	return store, directory, notifications, calls
}

func startSynchronization(t *testing.T, directory *DingTalkDirectory) (context.CancelFunc, <-chan struct{}) {
	t.Helper()
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan struct{})
	go func() {
		defer close(done)
		directory.runSynchronization(ctx, synchronizationTiming{time.Hour, 20 * time.Millisecond, 20 * time.Millisecond}, nil)
	}()
	t.Cleanup(func() { cancel(); waitWorker(t, done) })
	return cancel, done
}
func waitWorker(t *testing.T, signal <-chan struct{}) {
	t.Helper()
	select {
	case <-signal:
	case <-time.After(10 * time.Second):
		t.Fatal("synchronization did not make progress")
	}
}

func TestSynchronizationLeadershipHandoffAndSmallPool(t *testing.T) {
	_, directory, notifications, calls := workerFixture(t)
	stopFirst, firstDone := startSynchronization(t, directory)
	waitWorker(t, notifications)
	// A second replica must return without provider work while the leader is alive.
	if err := directory.synchronizeAsLeader(t.Context(), synchronizationTiming{time.Hour, time.Millisecond, time.Millisecond}, nil); err != nil {
		t.Fatal(err)
	}
	if calls.Load() != 1 {
		t.Fatal("two replicas synchronized concurrently")
	}
	stopSecond, secondDone := startSynchronization(t, directory)
	stopFirst()
	waitWorker(t, firstDone)
	waitWorker(t, notifications)
	stopSecond()
	waitWorker(t, secondDone)
	if calls.Load() != 2 {
		t.Fatal("leadership handoff did not perform one new pass")
	}
}

func TestSynchronizationReconnectsAfterCoordinationConnectionLoss(t *testing.T) {
	store, directory, notifications, _ := workerFixture(t)
	stop, done := startSynchronization(t, directory)
	waitWorker(t, notifications)
	query := `SELECT pid FROM pg_locks WHERE locktype='advisory' AND classid=0 AND objid=$1 AND granted
 AND database=(SELECT oid FROM pg_database WHERE datname=current_database())`
	var firstPID int32
	if err := store.pool.QueryRow(t.Context(), query, dingtalkSynchronizationLock).Scan(&firstPID); err != nil {
		t.Fatal(err)
	}
	// This is the coordination session in this test's uniquely owned database.
	var terminated bool
	if err := store.pool.QueryRow(t.Context(), "SELECT pg_terminate_backend($1)", firstPID).Scan(&terminated); err != nil || !terminated {
		t.Fatal("could not terminate owned coordination session", err)
	}
	waitWorker(t, notifications)
	var nextPID int32
	if err := store.pool.QueryRow(t.Context(), query, dingtalkSynchronizationLock).Scan(&nextPID); err != nil || nextPID == firstPID {
		t.Fatal("worker did not reconnect and acquire leadership", err)
	}
	stop()
	waitWorker(t, done)
}

func TestSynchronizationCancellationReachesProvider(t *testing.T) {
	_, directory, _, _ := workerFixture(t)
	started := make(chan struct{})
	canceled := make(chan struct{})
	directory.applications.checker = checkDingTalkFunc(func(ctx context.Context, _, _, _ string) error {
		close(started)
		<-ctx.Done()
		close(canceled)
		return ctx.Err()
	})
	stop, done := startSynchronization(t, directory)
	waitWorker(t, started)
	stop()
	waitWorker(t, canceled)
	waitWorker(t, done)
}
