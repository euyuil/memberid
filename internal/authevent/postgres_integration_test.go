//go:build integration

package authevent

import (
	"os"
	"testing"
	"time"

	"github.com/euyuil/memberid/internal/testdb"
	"github.com/jackc/pgx/v5/pgxpool"
)

func TestRetentionCleanupIsBoundedAndUsesOccurrence(t *testing.T) {
	databaseURL := testdb.Create(t)
	pool, err := pgxpool.New(t.Context(), databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	// Exercise the actual fresh-install schema without importing its owning
	// package (which also uses this event recorder).
	schema, err := os.ReadFile("../identity/schema.sql")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(t.Context(), string(schema)); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(t.Context(), `INSERT INTO authentication_events(event_id,event_type,outcome,occurred_at,data)
 SELECT 'expired-'||n,'sms.send','succeeded',clock_timestamp()-interval '2 hours','{}' FROM generate_series(1,1001) n`); err != nil {
		t.Fatal(err)
	}
	sink := &postgresSink{pool, time.Hour}
	fresh := sampleEvent()
	fresh.EventID = NewID()
	fresh.OccurredAt = time.Now()
	if err := sink.write(t.Context(), fresh); err != nil {
		t.Fatal(err)
	}
	lag, err := sink.cleanup(t.Context())
	if err != nil || lag < time.Hour {
		t.Fatal("remaining cleanup lag was hidden", lag, err)
	}
	var count int
	if err := pool.QueryRow(t.Context(), "SELECT count(*) FROM authentication_events").Scan(&count); err != nil || count != 2 {
		t.Fatal("unbounded cleanup", count, err)
	}
	lag, err = sink.cleanup(t.Context())
	if err != nil || lag != 0 {
		t.Fatal(lag, err)
	}
	if err := pool.QueryRow(t.Context(), "SELECT count(*) FROM authentication_events WHERE event_id=$1", fresh.EventID).Scan(&count); err != nil || count != 1 {
		t.Fatal("fresh event removed", err)
	}
	// Increasing retention cannot restore removed records. Decreasing it applies
	// to occurrence time even though this row was only just inserted.
	sink.retention = time.Millisecond
	time.Sleep(2 * time.Millisecond)
	if _, err := sink.cleanup(t.Context()); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(t.Context(), "SELECT count(*) FROM authentication_events").Scan(&count); err != nil || count != 0 {
		t.Fatal(count, err)
	}
}
