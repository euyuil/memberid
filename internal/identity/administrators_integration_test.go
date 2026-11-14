//go:build integration

package identity

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"testing"
	"time"
)

func TestAdministratorActorScopeAndRevocation(t *testing.T) {
	s := testStore(t)
	org, err := s.CreateOrganization(t.Context(), OperatorPrincipal(), "", "Administrator scope")
	if err != nil {
		t.Fatal(err)
	}
	local, factor := administratorMember(t, s, org.ID, 1)
	platform, platformFactor := administratorMember(t, s, SystemOrganizationID, 2)
	actorFor := func(member Member, factor Factor) ManagementActor {
		t.Helper()
		bindings, err := s.Bindings(t.Context(), member.OrganizationID, member.ID)
		if err != nil || len(bindings) != 1 {
			t.Fatal(bindings, err)
		}
		data, err := json.Marshal(map[string]string{"memberId": member.ID, "factorId": factor.ID, "bindingId": bindings[0].ID})
		if err != nil {
			t.Fatal(err)
		}
		if _, err = s.pool.Exec(t.Context(), "INSERT INTO oidc_sessions(id,secret_hash,verification,expires_at,absolute_expires_at) VALUES($1,$1,'{}',clock_timestamp()+interval '1 hour',clock_timestamp()+interval '2 hours')", member.ID); err != nil {
			t.Fatal(err)
		}
		if _, err = s.pool.Exec(t.Context(), "INSERT INTO oidc_grants(id,client_id,session_id,data,expires_at,absolute_expires_at) VALUES($1,'synthetic-management',$1,$2,clock_timestamp()+interval '1 hour',clock_timestamp()+interval '2 hours')", member.ID, data); err != nil {
			t.Fatal(err)
		}
		actor, err := s.ManagementActor(t.Context(), member.ID, member.ID)
		if err != nil {
			t.Fatal(err)
		}
		return actor
	}
	localActor, platformActor := actorFor(local, factor), actorFor(platform, platformFactor)
	if localActor.Platform || !platformActor.Platform {
		t.Fatal("incorrect administrator scope")
	}
	name := "Renamed organization"
	change := ManagementChange{Name: &name}
	if _, err = s.Manage(t.Context(), localActor.Principal(), "organization.update", org.ID, "", change); err != nil {
		t.Fatal("own organization update", err)
	}
	localActor.Platform = true
	localActor.OrganizationID = SystemOrganizationID
	if _, err = s.Manage(t.Context(), localActor.Principal(), "organization.update", SystemOrganizationID, "", change); !errors.Is(err, ErrForbidden) {
		t.Fatal("actor fields bypassed stored scope", err)
	}
	if _, err = s.Manage(t.Context(), localActor.Principal(), "organization.create", "", "", change); !errors.Is(err, ErrForbidden) {
		t.Fatal("organization administrator created an organization", err)
	}
	if err = s.SetAdministrator(t.Context(), localActor.Principal(), SystemOrganizationID, platform.ID, false); !errors.Is(err, ErrForbidden) {
		t.Fatal("organization administrator changed platform access", err)
	}
	if _, err = s.Manage(t.Context(), platformActor.Principal(), "organization.update", org.ID, "", change); err != nil {
		t.Fatal("platform organization update", err)
	}
	events, err := s.ManagementEvents(t.Context(), org.ID, "", 0)
	if err != nil || len(events) != 3 || events[0].Actor != platform.ID || events[1].Actor != local.ID {
		t.Fatal("atomic actor attribution", events, err)
	}
	if _, err = s.pool.Exec(t.Context(), "UPDATE oidc_grants SET revoked_at=clock_timestamp() WHERE id=$1", local.ID); err != nil {
		t.Fatal(err)
	}
	if _, err = s.Manage(t.Context(), localActor.Principal(), "organization.update", org.ID, "", change); !errors.Is(err, ErrForbidden) {
		t.Fatal("revoked grant retained access", err)
	}
}

func TestMemberAuditDoesNotInvertProviderLockOrder(t *testing.T) {
	s := testStore(t)
	m, _ := administratorMember(t, s, SystemOrganizationID, 1)
	provider, err := s.pool.Begin(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer provider.Rollback(t.Context())
	if _, err = provider.Exec(t.Context(), "SELECT id FROM organizations WHERE id=$1 FOR UPDATE", SystemOrganizationID); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
	defer cancel()
	name := "Renamed administrator"
	if _, err = s.UpdateMember(ctx, OperatorPrincipal(), SystemOrganizationID, m.ID, MemberChange{DisplayName: &name}); err != nil {
		t.Fatal("Member audit waited on provider's organization lock", err)
	}
}

func administratorMember(t *testing.T, s *Store, org string, n int) (Member, Factor) {
	t.Helper()
	m, e := s.CreateMember(t.Context(), OperatorPrincipal(), org, "", fmt.Sprintf("Administrator %d", n))
	if e != nil {
		t.Fatal(e)
	}
	f, e := s.EnsureFactor(t.Context(), "phone", "phone:e164", fmt.Sprintf("+861990000%04d", n))
	if e != nil {
		t.Fatal(e)
	}
	if _, e = s.BindFactor(t.Context(), OperatorPrincipal(), org, m.ID, f.ID); e != nil {
		t.Fatal(e)
	}
	if e = s.SetAdministrator(t.Context(), OperatorPrincipal(), org, m.ID, true); e != nil {
		t.Fatal(e)
	}
	return m, f
}

func TestSystemOrganizationAndAdministratorGuards(t *testing.T) {
	s := testStore(t)
	if !ValidID(SystemOrganizationID, OrganizationKind) || ValidID(SystemOrganizationID, MemberKind) {
		t.Fatal("invalid reserved ID boundary")
	}
	if _, e := s.Organization(t.Context(), SystemOrganizationID); e != nil {
		t.Fatal(e)
	}
	if _, e := s.CreateOrganization(t.Context(), OperatorPrincipal(), SystemOrganizationID, "Reserved"); !errors.Is(e, ErrInvalid) {
		t.Fatal(e)
	}
	disabled := "disabled"
	if _, e := s.UpdateOrganization(t.Context(), OperatorPrincipal(), SystemOrganizationID, OrganizationChange{Status: &disabled}); !errors.Is(e, ErrForbidden) {
		t.Fatal(e)
	}
	m, f := administratorMember(t, s, SystemOrganizationID, 1)
	if e := s.SetAdministrator(t.Context(), OperatorPrincipal(), SystemOrganizationID, m.ID, false); !errors.Is(e, ErrLastAdministrator) {
		t.Fatal(e)
	}
	if _, e := s.SetManualBlock(t.Context(), OperatorPrincipal(), SystemOrganizationID, m.ID, true); !errors.Is(e, ErrLastAdministrator) {
		t.Fatal(e)
	}
	if e := s.RevokeBinding(t.Context(), OperatorPrincipal(), SystemOrganizationID, m.ID, f.ID); !errors.Is(e, ErrLastAdministrator) {
		t.Fatal(e)
	}
	blocked := true
	if _, _, e := s.UpdateMemberOnce(t.Context(), OperatorPrincipal(), SystemOrganizationID, m.ID, "00000000-0000-4000-8000-000000000001", MemberChange{ManualBlocked: &blocked}); !errors.Is(e, ErrLastAdministrator) {
		t.Fatal(e)
	}
	if _, e := s.SetExternalDeparture(t.Context(), SystemOrganizationID, m.ID, true); e != nil {
		t.Fatal("departure must remain authoritative", e)
	}
	if _, e := s.SetExternalDeparture(t.Context(), SystemOrganizationID, m.ID, false); e != nil {
		t.Fatal(e)
	}
	other, _ := administratorMember(t, s, SystemOrganizationID, 2)
	results := make(chan error, 2)
	for _, id := range []string{m.ID, other.ID} {
		go func() {
			results <- s.SetAdministrator(t.Context(), OperatorPrincipal(), SystemOrganizationID, id, false)
		}()
	}
	accepted, rejected := 0, 0
	for range 2 {
		e := <-results
		if e == nil {
			accepted++
		} else if errors.Is(e, ErrLastAdministrator) {
			rejected++
		} else {
			t.Fatal(e)
		}
	}
	if accepted != 1 || rejected != 1 {
		t.Fatalf("concurrent removals: %d/%d", accepted, rejected)
	}
	var count int
	if e := s.pool.QueryRow(t.Context(), "SELECT count(*) FROM management_events WHERE action='administrator.update'").Scan(&count); e != nil || count != 3 {
		t.Fatal("rejected changes must not create success events", count, e)
	}
}

func TestSystemOrganizationRejectsAutomaticDingTalkAdmission(t *testing.T) {
	s, apps, verifier, _ := verifierFixture(t)
	app, e := apps.Configure(t.Context(), OperatorPrincipal(), SystemOrganizationID, DingTalkApplicationInput{CorpID: "example-corp", ClientID: "system-client", ClientSecret: "synthetic-system-secret"})
	if e != nil {
		t.Fatal(e)
	}
	proof := DingTalkLoginProof{verifier: verifier, application: app, authenticatedAt: verifier.now()}
	proof.member.UnionID = "system-union"
	proof.member.UserID = "system-employee"
	proof.member.DisplayName = "Uninvited employee"
	if _, e = admitLogin(t.Context(), verifier, proof); !errors.Is(e, ErrIneligible) {
		t.Fatal(e)
	}
	members, e := s.Members(t.Context(), SystemOrganizationID, "", 50)
	if e != nil || len(members.Items) != 0 {
		t.Fatal("automatic admission created a system member", e)
	}
	m, e := s.CreateMember(t.Context(), OperatorPrincipal(), SystemOrganizationID, "", "Explicit system member")
	if e != nil {
		t.Fatal(e)
	}
	if e = s.PrepareSystemDingTalkAdmission(t.Context(), OperatorPrincipal(), m.ID, proof.member.UnionID); e != nil {
		t.Fatal(e)
	}
	if e = s.SetAdministrator(t.Context(), OperatorPrincipal(), SystemOrganizationID, m.ID, true); !errors.Is(e, ErrIneligible) {
		t.Fatal("approval was treated as authentication", e)
	}
	if _, e = s.SetManualBlock(t.Context(), OperatorPrincipal(), SystemOrganizationID, m.ID, true); e != nil {
		t.Fatal(e)
	}
	if _, e = admitLogin(t.Context(), verifier, proof); !errors.Is(e, ErrIneligible) {
		t.Fatal("approval bypassed block", e)
	}
	if _, e = s.SetManualBlock(t.Context(), OperatorPrincipal(), SystemOrganizationID, m.ID, false); e != nil {
		t.Fatal(e)
	}
	if _, e = admitLogin(t.Context(), verifier, proof); e != nil {
		t.Fatal(e)
	}
	bound, e := s.Bindings(t.Context(), SystemOrganizationID, m.ID)
	if e != nil || len(bound) != 1 || bound[0].FactorType != "dingtalk" {
		t.Fatal(bound, e)
	}
	ids, e := s.AdministratorIDs(t.Context(), SystemOrganizationID)
	if e != nil || len(ids) != 0 {
		t.Fatal("verified admission granted management", e)
	}
	if e = s.RevokeBinding(t.Context(), OperatorPrincipal(), SystemOrganizationID, m.ID, bound[0].FactorID); e != nil {
		t.Fatal(e)
	}
	if e = s.PrepareSystemDingTalkAdmission(t.Context(), OperatorPrincipal(), m.ID, proof.member.UnionID); !errors.Is(e, ErrConflict) {
		t.Fatal("approval reused revoked slot", e)
	}
	if _, e = admitLogin(t.Context(), verifier, proof); !errors.Is(e, ErrConflict) {
		t.Fatal("revoked binding restored", e)
	}
}
