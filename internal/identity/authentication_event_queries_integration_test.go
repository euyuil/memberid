//go:build integration

package identity

import (
	"encoding/json"
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/zhizhun-tech/memberid/internal/authevent"
)

func insertQueryEvent(t *testing.T, store *Store, event authevent.Event) {
	t.Helper()
	data, err := json.Marshal(event)
	if err != nil {
		t.Fatal(err)
	}
	_, err = store.pool.Exec(t.Context(), `INSERT INTO authentication_events(event_id,event_type,outcome,organization_id,member_id,client_id,interaction_id,request_id,occurred_at,data) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`, event.EventID, event.Type, event.Outcome, event.OrganizationID, event.MemberID, event.ClientID, event.InteractionID, event.RequestID, event.OccurredAt, data)
	if err != nil {
		t.Fatal(err)
	}
}

func TestAuthenticationEventQueryIsolationProjectionAndRetention(t *testing.T) {
	s := testStore(t)
	org, member := organizationAndMember(t, s)
	other, _ := organizationAndMember(t, s)
	admin, factor := administratorMember(t, s, org.ID, 81)
	platform, platformFactor := administratorMember(t, s, SystemOrganizationID, 82)
	local := administratorActor(t, s, admin, factor).Principal()
	global := administratorActor(t, s, platform, platformFactor).Principal()
	service := NewManagementService(s, nil, nil, 24*time.Hour)
	now := time.Now().UTC().Add(-time.Minute)
	base := authevent.Event{Type: "grant.revoke", Outcome: "succeeded", OccurredAt: now, FactorID: "shared-factor", SessionID: "shared-session", Actor: authevent.Actor{Kind: "factor", ID: "shared-factor"}, RequestID: "shared-request", InteractionID: "shared-interaction"}
	for _, entry := range []struct {
		id, org, cause string
		age            time.Duration
	}{
		{"global", "", "", 0}, {"foreign", other.ID, "", 0}, {"system", SystemOrganizationID, "", 0},
		{"expired", org.ID, "", 48 * time.Hour}, {"local-cause", org.ID, "", 0},
		{"local-global-cause", org.ID, "global", 0}, {"local-foreign-cause", org.ID, "foreign", 0},
		{"local-expired-cause", org.ID, "expired", 0}, {"local-missing-cause", org.ID, "missing", 0},
		{"local-visible-cause", org.ID, "local-cause", 0},
	} {
		event := base
		event.EventID, event.OrganizationID, event.CausationID = entry.id, entry.org, entry.cause
		event.OccurredAt = now.Add(-entry.age)
		if entry.org == org.ID {
			event.MemberID = member.ID
		}
		insertQueryEvent(t, s, event)
	}
	filter := AuthenticationEventFilter{Limit: 100, RequestID: "shared-request", InteractionID: "shared-interaction"}
	page, err := service.AuthenticationEvents(t.Context(), local, org.ID, filter)
	if err != nil || len(page.Items) != 6 {
		t.Fatal(page, err)
	}
	if len(page.OrganizationNames) != 1 || page.OrganizationNames[org.ID] != org.Name {
		t.Fatal("organization names escaped the authorized page", page.OrganizationNames)
	}
	for _, event := range page.Items {
		if event.OrganizationID != org.ID || event.FactorID != "" || event.SessionID != "" || event.Actor != (authevent.Actor{}) {
			t.Fatal("unsafe organization projection", event)
		}
		want := ""
		if event.EventID == "local-visible-cause" {
			want = "local-cause"
		}
		if event.CausationID != want {
			t.Fatal("unsafe cause", event)
		}
		detail, err := service.AuthenticationEvent(t.Context(), local, org.ID, event.EventID)
		if err != nil || !reflect.DeepEqual(event, detail) {
			t.Fatal("list/detail projection mismatch", detail, err)
		}
	}
	all, err := service.AuthenticationEvents(t.Context(), global, "", filter)
	if err != nil || len(all.Items) != 9 {
		t.Fatal(all, err)
	}
	if len(all.OrganizationNames) != 3 || all.OrganizationNames[other.ID] != other.Name || all.OrganizationNames[SystemOrganizationID] == "" {
		t.Fatal("missing organization display names", all.OrganizationNames)
	}
	renamed := "Renamed organization"
	if _, err := s.UpdateOrganization(t.Context(), OperatorPrincipal(), org.ID, OrganizationChange{Name: &renamed}); err != nil {
		t.Fatal(err)
	}
	current, err := service.AuthenticationEvents(t.Context(), local, org.ID, filter)
	if err != nil || current.OrganizationNames[org.ID] != renamed || !reflect.DeepEqual(current.Items, page.Items) {
		t.Fatal("current display names changed event evidence", current, err)
	}
	empty, err := service.AuthenticationEvents(t.Context(), local, org.ID, AuthenticationEventFilter{Limit: 100, RequestID: "no-matching-request"})
	if err != nil || len(empty.Items) != 0 || len(empty.OrganizationNames) != 0 {
		t.Fatal("empty query exposed organization names", empty, err)
	}
	full, err := service.AuthenticationEvent(t.Context(), global, "", "local-global-cause")
	if err != nil || full.FactorID != "shared-factor" || full.SessionID != "shared-session" || full.CausationID != "global" {
		t.Fatal(full, err)
	}
	for _, id := range []string{"global", "foreign", "system", "expired", "missing"} {
		if _, err := service.AuthenticationEvent(t.Context(), local, org.ID, id); !errors.Is(err, ErrNotFound) {
			t.Fatal("foreign/expired record visible", id, err)
		}
	}
	for _, scope := range []string{"", other.ID, SystemOrganizationID} {
		if _, err := service.AuthenticationEvents(t.Context(), local, scope, filter); !errors.Is(err, ErrForbidden) {
			t.Fatal("escaped scope", scope, err)
		}
	}
	// Expired records still exist physically; policy controls both list and get.
	longer := NewManagementService(s, nil, nil, 72*time.Hour)
	if _, err := longer.AuthenticationEvent(t.Context(), local, org.ID, "expired"); err != nil {
		t.Fatal(err)
	}
	for _, actor := range []authevent.Actor{{Kind: "member", ID: member.ID}, {Kind: "member", ID: platform.ID}, {Kind: "client", ID: "client-a"}} {
		event := base
		event.EventID = authevent.NewID()
		event.OrganizationID = org.ID
		event.MemberID = member.ID
		event.Actor = actor
		insertQueryEvent(t, s, event)
		visible, err := service.AuthenticationEvent(t.Context(), local, org.ID, event.EventID)
		if err != nil {
			t.Fatal(err)
		}
		want := actor
		if actor.ID == platform.ID {
			want = authevent.Actor{}
		}
		if visible.Actor != want {
			t.Fatal("actor projection", visible.Actor, want)
		}
	}
	administratorMember(t, s, org.ID, 83)
	if err := service.SetAdministrator(t.Context(), global, org.ID, admin.ID, false); err != nil {
		t.Fatal(err)
	}
	if _, err := service.AuthenticationEvents(t.Context(), local, org.ID, filter); !errors.Is(err, ErrForbidden) {
		t.Fatal("revoked admin retained access", err)
	}
}

func TestAuthenticationEventFiltersAndTimestampPagination(t *testing.T) {
	s := testStore(t)
	org, member := organizationAndMember(t, s)
	admin, factor := administratorMember(t, s, org.ID, 81)
	principal := administratorActor(t, s, admin, factor).Principal()
	service := NewManagementService(s, nil, nil, 24*time.Hour)
	// JSON carries nanoseconds; PostgreSQL stores microseconds. Cursor timestamps
	// must use the latter or ties can duplicate or skip records.
	now := time.Now().UTC().Add(-time.Minute).Truncate(time.Microsecond).Add(123 * time.Nanosecond)
	for _, id := range []string{"a", "b", "c", "d", "e"} {
		insertQueryEvent(t, s, authevent.Event{EventID: id, Type: "authentication.verify", Outcome: "succeeded", OccurredAt: now, OrganizationID: org.ID, MemberID: member.ID, ClientID: "client", GrantID: "grant", Method: "sms", RequestID: "request", InteractionID: "interaction"})
	}
	filter := AuthenticationEventFilter{Limit: 2, Type: "authentication.verify", Outcome: "succeeded", Method: "sms", MemberID: member.ID, ClientID: "client", GrantID: "grant", RequestID: "request", InteractionID: "interaction", From: now.Add(-time.Second).Format(time.RFC3339Nano), To: now.Add(time.Second).Format(time.RFC3339Nano)}
	var got []string
	for range 4 {
		page, err := service.AuthenticationEvents(t.Context(), principal, org.ID, filter)
		if err != nil {
			t.Fatal(err)
		}
		for _, e := range page.Items {
			got = append(got, e.EventID)
		}
		if page.NextAfter == "" {
			break
		}
		filter.After = page.NextAfter
	}
	if !reflect.DeepEqual(got, []string{"e", "d", "c", "b", "a"}) {
		t.Fatal("unstable pagination", got)
	}
	filter.After = ""
	filter.Outcome = "failed"
	page, err := service.AuthenticationEvents(t.Context(), principal, org.ID, filter)
	if err != nil || len(page.Items) != 0 {
		t.Fatal("filter ignored", page, err)
	}
	// A cursor is only a boundary, never a lookup granting access to its ID.
	filter.Outcome = "succeeded"
	filter.After = encodeEventCursor(authevent.Event{OccurredAt: now.Add(time.Second), EventID: "foreign-id"})
	page, err = service.AuthenticationEvents(t.Context(), principal, org.ID, filter)
	if err != nil || len(page.Items) != 2 {
		t.Fatal(page, err)
	}
}
