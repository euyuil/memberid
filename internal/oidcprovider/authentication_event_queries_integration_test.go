//go:build integration

package oidcprovider

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/zhizhun-tech/memberid/internal/authevent"
	"github.com/zhizhun-tech/memberid/internal/identity"
)

func TestConsoleAuthenticationEventQueries(t *testing.T) {
	f := newFixture(t)
	if err := f.store.SetAdministrator(t.Context(), identity.OperatorPrincipal(), f.member.OrganizationID, f.member.ID, true); err != nil {
		t.Fatal(err)
	}
	server := consoleFixture(t, f)
	f.status(f.call(f.browser, "GET", server.URL+"/api/authentication-events", nil, nil), 401)
	consoleLogin(t, f, server, f.member.ID)
	for _, entry := range []struct {
		id, org string
		age     time.Duration
	}{
		{"local", f.member.OrganizationID, 0}, {"foreign", f.otherMember.OrganizationID, 0}, {"global", "", 0}, {"expired", f.member.OrganizationID, 100 * 24 * time.Hour},
	} {
		e := authevent.Event{EventID: entry.id, Type: "grant.revoke", Outcome: "succeeded", OccurredAt: time.Now().UTC().Add(-entry.age), OrganizationID: entry.org, RequestID: "shared-request", FactorID: "global-factor", SessionID: "global-session", Actor: authevent.Actor{Kind: "factor", ID: "global-factor"}, CausationID: "global"}
		data, err := json.Marshal(e)
		if err != nil {
			t.Fatal(err)
		}
		_, err = f.store.Database().Exec(t.Context(), `INSERT INTO authentication_events(event_id,event_type,outcome,organization_id,request_id,occurred_at,data) VALUES($1,$2,$3,$4,$5,$6,$7)`, e.EventID, e.Type, e.Outcome, e.OrganizationID, e.RequestID, e.OccurredAt, data)
		if err != nil {
			t.Fatal(err)
		}
	}
	base := "/api/organizations/" + f.member.OrganizationID + "/authentication-events"
	page := consoleJSON(t, f, server, "GET", base+"?requestId=shared-request&limit=1", "", "", 200)
	if len(page["items"].([]any)) != 1 || page["nextAfter"] != nil {
		t.Fatal(page)
	}
	names := page["organizationNames"].(map[string]any)
	if len(names) != 1 || names[f.member.OrganizationID] != "Example Team" {
		t.Fatal("unsafe organization display names", names)
	}
	event := consoleJSON(t, f, server, "GET", base+"/local", "", "", 200)
	for _, field := range []string{"factorId", "sessionId", "actor", "causationId"} {
		if _, ok := event[field]; ok {
			t.Fatal("unsafe field", field, event)
		}
	}
	for _, id := range []string{"foreign", "global", "expired", "missing"} {
		consoleJSON(t, f, server, "GET", base+"/"+id, "", "", 404)
	}
	consoleJSON(t, f, server, "GET", "/api/authentication-events", "", "", 403)
	consoleJSON(t, f, server, "GET", "/api/authentication-events/global", "", "", 403)
	consoleJSON(t, f, server, "GET", "/api/organizations/"+f.otherMember.OrganizationID+"/authentication-events", "", "", 403)
	for _, q := range []string{"limit=0", "limit=101", "limit=no", "after=bad", "from=bad", "type=unknown"} {
		consoleJSON(t, f, server, "GET", base+"?"+q, "", "", 400)
	}
	csrf := consoleJSON(t, f, server, "GET", "/api/session", "", "", 200)["csrf"].(string)
	for _, method := range []string{"POST", "PATCH", "DELETE"} {
		r := f.call(f.browser, method, server.URL+base, nil, map[string]string{"Origin": server.URL, "X-CSRF-Token": csrf})
		f.status(r, 404)
	}
	if _, err := f.store.SetExternalDeparture(t.Context(), f.member.OrganizationID, f.member.ID, true); err != nil {
		t.Fatal(err)
	}
	consoleJSON(t, f, server, "GET", base, "", "", 401)
}
