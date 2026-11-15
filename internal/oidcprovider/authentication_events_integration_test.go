//go:build integration

package oidcprovider

import (
	"encoding/json"
	"net/url"
	"testing"
	"time"

	"github.com/euyuil/memberid/internal/authevent"
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
				for i := range f.service.configuration.Clients {
					f.service.configuration.Clients[i].OrganizationID = ""
				}
			}
			registered, _ := f.service.storage.client("example-web")
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
