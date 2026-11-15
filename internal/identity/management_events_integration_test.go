//go:build integration

package identity

import (
	"context"
	"encoding/json"
	"reflect"
	"strings"
	"sync"
	"testing"
)

func TestManagementEventSnapshotsSurviveRenaming(t *testing.T) {
	s := testStore(t)
	org, member := organizationAndMember(t, s)
	administrator, factor := administratorMember(t, s, SystemOrganizationID, 81)
	principal := administratorActor(t, s, administrator, factor).Principal()
	name, blocked := "Historical member", true
	if _, err := s.Manage(t.Context(), principal, "member.update", org.ID, member.ID, ManagementChange{DisplayName: &name, ManualBlocked: &blocked}); err != nil {
		t.Fatal(err)
	}
	events, err := s.ManagementEvents(t.Context(), org.ID, member.ID, 0)
	if err != nil || len(events) != 1 {
		t.Fatal(events, err)
	}
	event := events[0]
	expected := ManagementEventSnapshot{ActorName: administrator.DisplayName, OrganizationName: org.Name, TargetName: name}
	if event.Snapshot != expected {
		t.Fatal("missing operation-time names", event.Snapshot)
	}
	var previous map[string]any
	if err := json.Unmarshal(event.Previous, &previous); err != nil {
		t.Fatal(err)
	}
	if previous["displayName"] != member.DisplayName || previous["manualBlocked"] != false {
		t.Fatal("incorrect previous values", previous)
	}
	later := "Later name"
	if _, err := s.UpdateOrganization(t.Context(), OperatorPrincipal(), org.ID, OrganizationChange{Name: &later}); err != nil {
		t.Fatal(err)
	}
	for _, target := range []Member{member, administrator} {
		if _, err := s.UpdateMember(t.Context(), OperatorPrincipal(), target.OrganizationID, target.ID, MemberChange{DisplayName: &later}); err != nil {
			t.Fatal(err)
		}
	}
	events, err = s.ManagementEvents(t.Context(), org.ID, member.ID, 0)
	if err != nil || len(events) != 2 || !reflect.DeepEqual(events[1], event) {
		t.Fatal("later names rewrote history", events, err)
	}
	if events[0].Snapshot.ActorName != "" || events[0].Actor != "installation-operator" {
		t.Fatal("installation actor became a member", events[0])
	}
}

func TestConcurrentManagementEventsCaptureCommittedPreviousValue(t *testing.T) {
	s := testStore(t)
	org, member := organizationAndMember(t, s)
	start := make(chan struct{})
	errs := make(chan error, 2)
	var workers sync.WaitGroup
	for _, name := range []string{"First candidate", "Second candidate"} {
		workers.Go(func() {
			<-start
			_, err := s.UpdateMember(t.Context(), OperatorPrincipal(), org.ID, member.ID, MemberChange{DisplayName: &name})
			errs <- err
		})
	}
	close(start)
	workers.Wait()
	for range 2 {
		if err := <-errs; err != nil {
			t.Fatal(err)
		}
	}
	events, err := s.ManagementEvents(t.Context(), org.ID, member.ID, 0)
	if err != nil || len(events) != 2 {
		t.Fatal(events, err)
	}
	priorName := member.DisplayName
	for i := len(events) - 1; i >= 0; i-- {
		var previous, changes map[string]any
		if err := json.Unmarshal(events[i].Previous, &previous); err != nil {
			t.Fatal(err)
		}
		if err := json.Unmarshal(events[i].Changes, &changes); err != nil {
			t.Fatal(err)
		}
		if previous["displayName"] != priorName {
			t.Fatal("stale previous name", previous, priorName)
		}
		priorName = changes["displayName"].(string)
		if events[i].Snapshot.TargetName != priorName {
			t.Fatal("snapshot differs from committed name", events[i])
		}
	}
}

func TestProviderHistoryRecordsCredentialRotationWithoutSecrets(t *testing.T) {
	for _, kind := range []string{"dingtalk", "feishu"} {
		t.Run(kind, func(t *testing.T) {
			s, dingTalk, org, key := applicationFixture(t)
			local, factor := administratorMember(t, s, org.ID, 85)
			principal := administratorActor(t, s, local, factor).Principal()
			dingTalk.checker = checkDingTalkFunc(func(context.Context, string, string, string) error { return nil })
			feishuApps, err := NewFeishuApplications(s, key, checkFeishuFunc(func(context.Context, string, string) error { return nil }))
			if err != nil {
				t.Fatal(err)
			}
			enabled := true
			input := ProviderInput{DisplayName: "Employee login", TenantID: "example-tenant", ClientID: "cli_example", ClientSecret: "synthetic-original-credential", Enabled: &enabled}
			created, err := ConfigureProvider(t.Context(), principal, org.ID, kind, "", input, dingTalk, feishuApps)
			if err != nil {
				t.Fatal(err)
			}
			input.ClientSecret, input.ExpectedRevision = "synthetic-rotated-credential", created.Revision
			if _, err := ConfigureProvider(t.Context(), principal, org.ID, kind, created.ID, input, dingTalk, feishuApps); err != nil {
				t.Fatal(err)
			}
			events, err := s.ManagementEvents(t.Context(), org.ID, "", 0)
			if err != nil || len(events) != 3 {
				t.Fatal(events, err)
			}
			var changes, previous map[string]any
			if err := json.Unmarshal(events[0].Changes, &changes); err != nil {
				t.Fatal(err)
			}
			if err := json.Unmarshal(events[0].Previous, &previous); err != nil {
				t.Fatal(err)
			}
			if changes["credentialsUpdated"] != true || changes["created"] != false || changes["providerId"] != created.ID || previous["displayName"] != input.DisplayName || previous["enabled"] != true {
				t.Fatal("rotation evidence", previous, changes)
			}
			encoded, err := json.Marshal(events)
			if err != nil || strings.Contains(string(encoded), "synthetic-") {
				t.Fatal("credential entered history", err)
			}
		})
	}
}
