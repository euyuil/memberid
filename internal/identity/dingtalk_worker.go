package identity

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5"
)

const dingtalkSynchronizationLock int64 = 685193274

type synchronizationTiming struct{ interval, retry, heartbeat time.Duration }

// RunSynchronization maintains configured applications and their admitted Members.
// A dedicated PostgreSQL session coordinates replicas without occupying the query pool.
// report receives no provider, credential, or database diagnostics.
func (directory *DingTalkDirectory) RunSynchronization(ctx context.Context, report func()) {
	directory.runSynchronization(ctx, synchronizationTiming{15 * time.Minute, 10 * time.Second, 5 * time.Second}, report)
}

func (directory *DingTalkDirectory) runSynchronization(ctx context.Context, timing synchronizationTiming, report func()) {
	for ctx.Err() == nil {
		err := directory.synchronizeAsLeader(ctx, timing, report)
		if err != nil && ctx.Err() == nil && report != nil {
			report()
		}
		if !waitSynchronization(ctx, timing.retry) {
			return
		}
	}
}

func (directory *DingTalkDirectory) synchronizeAsLeader(ctx context.Context, timing synchronizationTiming, report func()) error {
	connect, cancel := context.WithTimeout(ctx, 5*time.Second)
	connection, err := pgx.ConnectConfig(connect, directory.applications.store.pool.Config().ConnConfig.Copy())
	cancel()
	if err != nil {
		return err
	}
	defer func() {
		closeContext, stop := context.WithTimeout(context.Background(), 5*time.Second)
		defer stop()
		_ = connection.Close(closeContext)
	}()
	var acquired bool
	lock, stop := context.WithTimeout(ctx, 5*time.Second)
	err = connection.QueryRow(lock, "SELECT pg_try_advisory_lock($1)", dingtalkSynchronizationLock).Scan(&acquired)
	stop()
	if err != nil || !acquired {
		return err
	}
	work, finish := context.WithCancel(ctx)
	heartbeatDone := make(chan struct{})
	go func() {
		defer close(heartbeatDone)
		for waitSynchronization(work, timing.heartbeat) {
			ping, stop := context.WithTimeout(work, 5*time.Second)
			_, err := connection.Exec(ping, "SELECT 1")
			stop()
			if err != nil {
				finish()
				return
			}
		}
	}()
	streamsDone := make(chan struct{})
	go func() { defer close(streamsDone); directory.superviseStreams(work, timing, report) }()
	defer func() { finish(); <-heartbeatDone; <-streamsDone }()
	for work.Err() == nil {
		if err := directory.reconcileAll(work); err != nil && work.Err() == nil && report != nil {
			report()
		}
		if !waitSynchronization(work, timing.interval) {
			break
		}
	}
	return work.Err()
}

func (directory *DingTalkDirectory) reconcileAll(ctx context.Context) error {
	after := ""
	incomplete := false
	for {
		rows, err := directory.applications.store.pool.Query(ctx, `SELECT a.organization_id,a.namespace FROM dingtalk_applications a
 JOIN organizations o ON o.id=a.organization_id AND o.status='enabled'
 WHERE a.enabled AND a.namespace>$1 ORDER BY a.namespace LIMIT 100`, after)
		if err != nil {
			return err
		}
		type source struct{ OrganizationID, Namespace string }
		applications, err := pgx.CollectRows(rows, pgx.RowToStructByPos[source])
		if err != nil {
			return err
		}
		if len(applications) == 0 {
			break
		}
		for _, app := range applications {
			if _, err := directory.ReconcileSource(ctx, app.OrganizationID, app.Namespace); err != nil {
				incomplete = true
			}
			if ctx.Err() != nil {
				return ctx.Err()
			}
			after = app.Namespace
		}
	}
	if incomplete {
		return ErrSynchronizationIncomplete
	}
	return nil
}

func waitSynchronization(ctx context.Context, delay time.Duration) bool {
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-timer.C:
		return true
	}
}
