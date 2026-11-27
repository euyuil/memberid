//go:build integration

package identity

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/zhizhun-tech/memberid/internal/authevent"
)

func TestPhoneSendEventsAndAuditFailure(t *testing.T) {
	for _, mode := range []string{"accepted", "provider failure", "rate limit", "audit unavailable", "accepted then readiness failed"} {
		t.Run(mode, func(t *testing.T) {
			verifier, sender, binding := phoneFixture(t)
			recorder, err := authevent.Open(verifier.store.pool.Config().ConnString(), 90*24*time.Hour)
			if err != nil {
				t.Fatal(err)
			}
			defer recorder.Close(time.Second)
			verifier.SetEventRecorder(recorder)
			if mode == "provider failure" {
				sender.failure = errors.New("private provider payload")
			}
			if mode == "audit unavailable" {
				if _, err := verifier.store.pool.Exec(t.Context(), "ALTER TABLE authentication_events ADD CONSTRAINT audit_failure CHECK (false) NOT VALID"); err != nil {
					t.Fatal(err)
				}
			}
			if mode == "accepted then readiness failed" {
				if _, err := verifier.store.pool.Exec(t.Context(), "ALTER TABLE phone_challenges ADD CONSTRAINT readiness_failure CHECK (NOT ready) NOT VALID"); err != nil {
					t.Fatal(err)
				}
			}
			ctx := authevent.WithContext(authevent.RequestContext(t.Context()), authevent.Event{InteractionID: authevent.NewID(), Purpose: "login", ClientID: "example-web"})
			challenge, err := verifier.Start(ctx, binding, "19900000001", testPhoneSource())
			switch mode {
			case "provider failure":
				if !errors.Is(err, ErrDeliveryUnavailable) {
					t.Fatal(err)
				}
			case "accepted then readiness failed":
				if err == nil {
					t.Fatal("business failure ignored")
				}
			default:
				if err != nil {
					t.Fatal(err)
				}
				if _, err := verifier.Verify(ctx, binding, challenge.ID, sender.code("+8619900000001")); err != nil {
					t.Fatal("audit prevented authentication", err)
				}
			}
			if mode == "rate limit" {
				if _, err := verifier.Start(ctx, binding, "19900000001", testPhoneSource()); !errors.Is(err, ErrRateLimited) {
					t.Fatal(err)
				}
			}
			recorder.Close(time.Second)
			rows, err := verifier.store.pool.Query(t.Context(), "SELECT data FROM authentication_events ORDER BY occurred_at,event_id")
			if err != nil {
				t.Fatal(err)
			}
			defer rows.Close()
			var events []authevent.Event
			for rows.Next() {
				var data []byte
				if err := rows.Scan(&data); err != nil {
					t.Fatal(err)
				}
				var event authevent.Event
				if err := json.Unmarshal(data, &event); err != nil {
					t.Fatal(err)
				}
				events = append(events, event)
			}
			if err := rows.Err(); err != nil {
				t.Fatal(err)
			}
			expected := 1
			if mode == "audit unavailable" {
				expected = 0
			}
			if mode == "rate limit" {
				expected = 2
			}
			if len(events) != expected {
				t.Fatal("event count", len(events), expected)
			}
			for i, event := range events {
				outcome, reason := "succeeded", ""
				if mode == "provider failure" {
					outcome, reason = "failed", "providerUnavailable"
				}
				if mode == "rate limit" && i == 1 {
					outcome, reason = "rejected", "sendRateLimited"
				}
				if event.Type != "sms.send" || event.Outcome != outcome || event.ReasonCode != reason || event.RequestID == "" || event.InteractionID == "" || event.MemberID != "" || event.OrganizationID != "" || event.Actor.Kind != "" {
					t.Fatalf("unexpected context: %#v", event)
				}
			}
			if mode == "audit unavailable" && recorder.Stats().RetryExhausted != 1 {
				t.Fatal(recorder.Stats())
			}
		})
	}
}

func TestAuthenticationEventsDeduplicateAndExpire(t *testing.T) {
	store := testStore(t)
	recorder, err := authevent.Open(store.pool.Config().ConnString(), time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	event := authevent.Event{EventID: authevent.NewID(), Type: "sms.send", Outcome: "succeeded", OccurredAt: time.Now()}
	recorder.Offer(event)
	recorder.Offer(event)
	old := event
	old.EventID = authevent.NewID()
	old.OccurredAt = time.Now().Add(-2 * time.Hour)
	recorder.Offer(old)
	recorder.Close(time.Second)
	var count int
	var recorded time.Time
	if err := store.pool.QueryRow(context.Background(), "SELECT count(*),min(recorded_at) FROM authentication_events").Scan(&count, &recorded); err != nil || count != 1 || recorded.Before(event.OccurredAt) {
		t.Fatal(count, recorded, err)
	}
	recorder, err = authevent.Open(store.pool.Config().ConnString(), time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	recorder.Offer(event)
	recorder.Close(time.Second)
	var again time.Time
	if err := store.pool.QueryRow(t.Context(), "SELECT recorded_at FROM authentication_events").Scan(&again); err != nil || !again.Equal(recorded) {
		t.Fatal("retry changed original insertion", err)
	}
}

func TestAuthenticationEventClientNamesPreserveHistoryAndProtocol(t *testing.T) {
	store := testStore(t)
	ctx := t.Context()
	const clientID = "shared-client-id"
	_, err := store.pool.Exec(ctx, `INSERT INTO oidc_clients(client_id,display_name,enabled,system,revision,registration,owner_organization_id)
 VALUES($1,'Current OIDC name',true,false,1,jsonb_build_object('client_id',$1::text),'org_system')`, clientID)
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		id, kind, interaction, name, expected string
	}{
		{"old-grant", "oidc.grant.issue", "oidc-login", "", "Current OIDC name"},
		{"old-verify", "authentication.verify", "oidc-login", "", "Current OIDC name"},
		{"saml-assertion", "saml.assertion.issue", "saml-login", "", ""},
		{"saml-verify", "authentication.verify", "saml-login", "", ""},
		{"unattributed", "sms.send", "", "", ""},
		{"named-grant", "oidc.grant.issue", "renamed-login", "Original OIDC name", "Original OIDC name"},
	}
	for _, test := range cases {
		_, err := store.pool.Exec(ctx, `INSERT INTO authentication_events(event_id,event_type,outcome,occurred_at,client_id,interaction_id,data)
 VALUES($1,$2,'succeeded',clock_timestamp(),$3,$4,jsonb_build_object('clientName',$5::text))`, test.id, test.kind, clientID, test.interaction, test.name)
		if err != nil {
			t.Fatal(err)
		}
	}
	query := "SELECT " + authenticationEventColumns + authenticationEventWhere + " AND e.event_id=$3"
	for _, test := range cases {
		event, err := readAuthenticationEvent(store.pool.QueryRow(ctx, query, "", time.Now().Add(-time.Hour), test.id), false)
		if err != nil || event.ClientID != clientID || event.ClientName != test.expected {
			t.Errorf("%s = %q, want %q: %v", test.id, event.ClientName, test.expected, err)
		}
	}
}
