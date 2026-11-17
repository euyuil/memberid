//go:build integration

package oidcprovider

import (
	"encoding/json"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/euyuil/memberid/internal/authevent"
	"github.com/euyuil/memberid/internal/config"
)

func enableAuthenticationEvents(t *testing.T, f *fixture) *authevent.Recorder {
	t.Helper()
	recorder, err := authevent.Open(f.store.Database().Config().ConnString(), 90*24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { recorder.Close(time.Second) })
	f.service.SetEventRecorder(recorder)
	return recorder
}
func authenticationEvents(t *testing.T, f *fixture) []authevent.Event {
	t.Helper()
	rows, err := f.store.Database().Query(t.Context(), "SELECT data,recorded_at FROM authentication_events ORDER BY occurred_at,event_id")
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	events := []authevent.Event{}
	for rows.Next() {
		var data []byte
		var recorded time.Time
		if err := rows.Scan(&data, &recorded); err != nil {
			t.Fatal(err)
		}
		var event authevent.Event
		if err := json.Unmarshal(data, &event); err != nil {
			t.Fatal(err)
		}
		event.RecordedAt = recorded
		events = append(events, event)
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	return events
}
func TestSMSLoginEventCorrelationAndUnknownIdentity(t *testing.T) {
	for _, restricted := range []bool{true, false} {
		t.Run(map[bool]string{true: "registered organization", false: "shared login"}[restricted], func(t *testing.T) {
			f := newFixture(t)
			if !restricted {
				for _, id := range []string{"example-web", "second-web"} {
					f.updateClient(id, func(c *config.Client) { c.OrganizationID = "" })
				}
			}
			registered, _ := f.service.storage.client(t.Context(), "example-web")
			recorder := enableAuthenticationEvents(t, f)
			page, _ := f.loginPage("example-web", "openid")
			f.status(f.submit(page.body, "send", url.Values{"phone": {"not-a-number"}}), 200)
			f.status(f.submit(page.body, "send", url.Values{"phone": {"19900000001"}}), 200)
			recorder.Close(time.Second)
			events := authenticationEvents(t, f)
			if len(events) != 2 {
				t.Fatal(events)
			}
			if events[0].Outcome != "rejected" || events[1].Outcome != "succeeded" || events[0].InteractionID == "" || events[0].InteractionID != events[1].InteractionID || events[0].RequestID == "" || events[0].RequestID == events[1].RequestID {
				t.Fatal("invalid correlation", events)
			}
			for _, event := range events {
				if event.MemberID != "" || event.FactorID != "" || event.Actor.Kind != "" || event.OrganizationID != registered.registration.OrganizationID || event.ClientID != "example-web" || event.Purpose != "login" {
					t.Fatal("inferred identity", event)
				}
			}
		})
	}
}
func TestSMSAccountEventUsesValidatedMember(t *testing.T) {
	f, account := phoneAccountFixture(t)
	recorder := enableAuthenticationEvents(t, f)
	sendAccountPhone(f, account)
	recorder.Close(time.Second)
	events := authenticationEvents(t, f)
	if len(events) != 1 {
		t.Fatal(events)
	}
	event := events[0]
	if event.Type != "sms.send" || event.Outcome != "succeeded" || event.Purpose != "accountLinking" || event.OrganizationID == "" || event.MemberID == "" || event.Actor.Kind != "member" || event.Actor.ID != event.MemberID || event.SessionID == "" || event.FactorID == "" || event.InteractionID == "" || event.RequestID == "" {
		t.Fatal(event)
	}
}

func TestOIDCApplicationNameOnLoginConsentAndEvents(t *testing.T) {
	f := newFixture(t)
	const name = "Member portal <demo>"
	if _, err := f.store.Database().Exec(t.Context(), "UPDATE oidc_clients SET display_name=$2 WHERE client_id=$1", "example-web", name); err != nil {
		t.Fatal(err)
	}
	recorder := enableAuthenticationEvents(t, f)
	page, verifier := f.loginPage("example-web", "openid profile")
	assertName := func(body string) {
		t.Helper()
		if !strings.Contains(body, "Sign in to <strong>Member portal &lt;demo&gt;</strong>") {
			t.Fatal("application name was missing or was not escaped")
		}
	}
	assertName(page.body)
	page = f.verifyPhone(page)
	assertName(page.body)
	code := f.complete(page, f.member.ID)
	f.status(f.exchange("example-web", code, verifier), 200)
	recorder.Close(time.Second)
	seen := map[string]bool{}
	for _, event := range authenticationEvents(t, f) {
		if event.ClientID != "example-web" || event.ClientName != name {
			t.Fatalf("incorrect application context on %s", event.Type)
		}
		seen[event.Type] = true
	}
	if !seen["authentication.verify"] || !seen["oidc.grant.issue"] {
		t.Fatal("verification or issuance record missing", seen)
	}
}
