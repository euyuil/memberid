package authevent

import (
	"context"
	"encoding/json"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

type postgresSink struct {
	pool      *pgxpool.Pool
	retention time.Duration
}

// Open uses one dedicated connection; audit failures cannot exhaust the business
// pool. No startup ping or audit-table write gates authentication availability.
func Open(databaseURL string, retention time.Duration) (*Recorder, error) {
	return open(databaseURL, retention, true)
}

// OpenWriter is for short-lived operator commands emitting current events. It
// does not run retention cleanup without the installation's configured policy.
// The authentication service owns cleanup; the query service owns expiry filters.
func OpenWriter(databaseURL string) (*Recorder, error) {
	return open(databaseURL, 90*24*time.Hour, false)
}

func open(databaseURL string, retention time.Duration, maintenance bool) (*Recorder, error) {
	configuration, err := pgxpool.ParseConfig(databaseURL)
	if err != nil {
		return nil, err
	}
	configuration.MaxConns, configuration.MinConns, configuration.MinIdleConns = 1, 0, 0
	configuration.ConnConfig.ConnectTimeout = 2 * time.Second
	configuration.ConnConfig.RuntimeParams["search_path"] = "public"
	pool, err := pgxpool.NewWithConfig(context.Background(), configuration)
	if err != nil {
		return nil, err
	}
	bounds := defaults()
	if !maintenance {
		bounds.maintenance = 0
	}
	recorder := newRecorder(&postgresSink{pool, retention}, bounds)
	recorder.closeSink = pool.Close
	return recorder, nil
}

func (sink *postgresSink) write(ctx context.Context, event Event) error {
	data, err := json.Marshal(event)
	if err != nil {
		return err
	}
	_, err = sink.pool.Exec(ctx, `INSERT INTO authentication_events
 (event_id,event_type,outcome,occurred_at,organization_id,member_id,client_id,interaction_id,request_id,data)
 SELECT $1,$2,$3,$4,$5,$6,$7,$8,$9,$10 WHERE $4::timestamptz > clock_timestamp()-($11::bigint * interval '1 second')
 ON CONFLICT (event_id) DO NOTHING`, event.EventID, event.Type, event.Outcome, event.OccurredAt, event.OrganizationID, event.MemberID, event.ClientID, event.InteractionID, event.RequestID, data, int64(sink.retention.Seconds()))
	return err
}

func (sink *postgresSink) cleanup(ctx context.Context) (time.Duration, error) {
	cutoff := time.Now().UTC().Add(-sink.retention)
	_, err := sink.pool.Exec(ctx, `DELETE FROM authentication_events WHERE event_id IN
 (SELECT event_id FROM authentication_events WHERE occurred_at<=$1 ORDER BY occurred_at LIMIT 1000)`, cutoff)
	if err != nil {
		return 0, err
	}
	var oldest *time.Time
	if err := sink.pool.QueryRow(ctx, "SELECT min(occurred_at) FROM authentication_events WHERE occurred_at<=$1", cutoff).Scan(&oldest); err != nil {
		return 0, err
	}
	if oldest == nil {
		return 0, nil
	}
	return cutoff.Sub(*oldest), nil
}
