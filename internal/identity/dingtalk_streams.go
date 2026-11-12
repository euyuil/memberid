package identity

import (
	"context"
	"time"

	"github.com/euyuil/memberid/internal/dingtalk"
)

type dingTalkStreamProvider interface {
	Stream(context.Context, string, string, func(), func(context.Context, dingtalk.DirectoryEvent) error) error
}

type applicationStream struct {
	application DingTalkApplication
	cancel      context.CancelFunc
	done        <-chan struct{}
}

func (directory *DingTalkDirectory) superviseStreams(ctx context.Context, timing synchronizationTiming, report func()) {
	provider, ok := directory.provider.(dingTalkStreamProvider)
	if !ok {
		return
	}
	running := make(map[string]applicationStream)
	stopAll := func() {
		for _, stream := range running {
			stream.cancel()
		}
		for id, stream := range running {
			<-stream.done
			delete(running, id)
		}
	}
	defer stopAll()
	for ctx.Err() == nil {
		applications, err := directory.streamApplications(ctx)
		if err != nil {
			stopAll()
			if ctx.Err() == nil && report != nil {
				report()
			}
		} else {
			wanted := make(map[string]DingTalkApplication, len(applications))
			for _, app := range applications {
				wanted[app.OrganizationID] = app
			}
			for id, stream := range running {
				app, exists := wanted[id]
				select {
				case <-stream.done:
					stream.cancel()
					delete(running, id)
					continue
				default:
				}
				if !exists || app.Revision != stream.application.Revision || app.Namespace != stream.application.Namespace || app.organizationRevision != stream.application.organizationRevision {
					stream.cancel()
					<-stream.done
					delete(running, id)
				}
			}
			for id, app := range wanted {
				if _, exists := running[id]; exists {
					continue
				}
				work, cancel := context.WithCancel(ctx)
				done := make(chan struct{})
				running[id] = applicationStream{app, cancel, done}
				go func() { defer close(done); directory.runApplicationStream(work, provider, app, timing.retry, report) }()
			}
		}
		if !waitSynchronization(ctx, timing.heartbeat) {
			return
		}
	}
}

func (directory *DingTalkDirectory) streamApplications(ctx context.Context) ([]DingTalkApplication, error) {
	rows, err := directory.applications.store.pool.Query(ctx, `SELECT a.organization_id,a.namespace,a.corp_id,a.client_id,a.revision,o.lifecycle_revision
  FROM dingtalk_applications a JOIN organizations o ON o.id=a.organization_id
  WHERE o.status='enabled' AND a.authorization_status='active' ORDER BY a.organization_id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var applications []DingTalkApplication
	for rows.Next() {
		var app DingTalkApplication
		if err := rows.Scan(&app.OrganizationID, &app.Namespace, &app.CorpID, &app.ClientID, &app.Revision, &app.organizationRevision); err != nil {
			return nil, err
		}
		applications = append(applications, app)
	}
	return applications, rows.Err()
}

func (directory *DingTalkDirectory) runApplicationStream(ctx context.Context, provider dingTalkStreamProvider, app DingTalkApplication, retry time.Duration, report func()) {
	work, cancel := context.WithCancel(ctx)
	defer cancel()
	refresh := make(chan struct{}, 1)
	notify := func() {
		select {
		case refresh <- struct{}{}:
		default:
		}
	}
	finished := make(chan struct{})
	go func() {
		defer close(finished)
		for work.Err() == nil {
			credentials, err := directory.applications.Load(work, app.OrganizationID)
			if err == nil && (credentials.Revision != app.Revision || credentials.Namespace != app.Namespace || credentials.AuthorizationStatus != "active") {
				return
			}
			if err == nil {
				err = provider.Stream(work, credentials.ClientID, credentials.Secret, notify, func(ctx context.Context, event dingtalk.DirectoryEvent) error {
					if err := directory.acceptDirectoryEvent(ctx, app, event); err != nil {
						if ctx.Err() == nil && report != nil {
							report()
						}
						return err
					}
					if event.Type != "user_leave_org" {
						notify()
					}
					return nil
				})
			}
			if err != nil && work.Err() == nil && report != nil {
				report()
			}
			if !waitSynchronization(work, retry) {
				return
			}
		}
	}()
	defer func() { cancel(); <-finished }()
	for {
		select {
		case <-work.Done():
			return
		case <-finished:
			return
		case <-refresh:
			// Coalesce notifications. Fresh reads, not event profiles, can restore access.
			// A restart or lost notification is covered by the regular complete pass.
			if _, err := directory.Reconcile(work, app.OrganizationID); err != nil && work.Err() == nil && report != nil {
				report()
			}
			if !waitSynchronization(work, retry) {
				return
			}
		}
	}
}
