//go:build integration

package identity

import (
	"errors"
	"testing"

	"github.com/euyuil/memberid/internal/authorization"
)

func TestScopedOrganizationUpdates(t *testing.T) {
	s := testStore(t)
	org, _ := organizationAndMember(t, s)
	local, factor := administratorMember(t, s, org.ID, 41)
	platform, platformFactor := administratorMember(t, s, SystemOrganizationID, 42)
	principal := administratorActor(t, s, local, factor).Principal()
	platformPrincipal := administratorActor(t, s, platform, platformFactor).Principal()
	name := "Allowed name"
	if _, err := s.Manage(t.Context(), principal, "organization.update", org.ID, "", ManagementChange{Name: &name}); err != nil {
		t.Fatal(err)
	}
	for _, status := range []string{"enabled", "disabled"} {
		deniedName := "Must not be written"
		if _, err := s.Manage(t.Context(), principal, "organization.update", org.ID, "", ManagementChange{Name: &deniedName, Status: &status}); !errors.Is(err, ErrForbidden) {
			t.Fatal("mixed update did not require status authority", status, err)
		}
		current, err := s.Organization(t.Context(), org.ID)
		if err != nil || current.Name != name || current.Status != "enabled" {
			t.Fatal("denied combined update had an effect", current, err)
		}
	}
	if _, err := s.Manage(t.Context(), principal, "organization.update", SystemOrganizationID, "", ManagementChange{Name: &name}); !errors.Is(err, ErrForbidden) {
		t.Fatal("organization scope escaped", err)
	}
	disabled, enabled := "disabled", "enabled"
	if _, err := s.Manage(t.Context(), platformPrincipal, "organization.update", org.ID, "", ManagementChange{Status: &disabled}); err != nil {
		t.Fatal("platform status permission", err)
	}
	if _, err := s.Manage(t.Context(), platformPrincipal, "organization.update", org.ID, "", ManagementChange{Name: &name, Status: &enabled}); err != nil {
		t.Fatal("platform combined permission", err)
	}
	if _, err := s.Manage(t.Context(), platformPrincipal, "organization.update", SystemOrganizationID, "", ManagementChange{Status: &disabled}); !errors.Is(err, ErrForbidden) {
		t.Fatal("permission bypassed system lifecycle constraint", err)
	}
	for _, requirement := range []authorization.Requirement{
		{Target: "organizations/" + org.ID, Action: "delete"},
		{Target: "organizations/" + org.ID, Action: "**"},
		{Target: "unregistered/" + org.ID, Action: "get"},
	} {
		if err := authorizeAll(t.Context(), s.pool, platformPrincipal, requirement); !errors.Is(err, ErrInvalid) {
			t.Fatal("wildcard enabled an unregistered operation", requirement, err)
		}
	}
	events, err := s.ManagementEvents(t.Context(), org.ID, "", 0)
	// One assignment and the three allowed updates; denied operations are absent.
	if err != nil || len(events) != 4 {
		t.Fatal("authorization failure recorded a successful mutation", events, err)
	}
}

func TestScopedAuthorizationRevocationBoundary(t *testing.T) {
	s := testStore(t)
	org, _ := organizationAndMember(t, s)
	member, factor := administratorMember(t, s, org.ID, 51)
	administratorMember(t, s, org.ID, 52)
	principal := administratorActor(t, s, member, factor).Principal()
	name := "Authorized before revocation"
	requirements, err := organizationUpdateRequirements(org.ID, OrganizationChange{Name: &name})
	if err != nil {
		t.Fatal(err)
	}
	tx, err := s.pool.Begin(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(t.Context())
	if err := authorizeAll(t.Context(), tx, principal, requirements...); err != nil {
		t.Fatal(err)
	}
	if err := s.SetAdministrator(t.Context(), OperatorPrincipal(), org.ID, member.ID, false); err != nil {
		t.Fatal(err)
	}
	// The evaluator adds no permission lock and does not invalidate an already
	// admitted bounded operation. Existing service lifecycle locks remain separate.
	if _, err := updateOrganization(t.Context(), tx, org.ID, OrganizationChange{Name: &name}); err != nil {
		t.Fatal(err)
	}
	if err := managementEvent(t.Context(), tx, principal, org.ID, "", "organization.update", OrganizationChange{Name: &name}); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(t.Context()); err != nil {
		t.Fatal(err)
	}
	if err := authorizeAll(t.Context(), s.pool, principal, requirements...); !errors.Is(err, ErrForbidden) {
		t.Fatal("new decision retained revoked authority", err)
	}
	if _, err := s.Manage(t.Context(), principal, "organization.update", org.ID, "", ManagementChange{Name: &name}); !errors.Is(err, ErrForbidden) {
		t.Fatal("next service operation retained revoked authority", err)
	}
	current, err := s.Organization(t.Context(), org.ID)
	if err != nil || current.Name != name {
		t.Fatal("admitted operation did not complete", current, err)
	}
}

func TestScopedManagementWrites(t *testing.T) {
	s := testStore(t)
	org, target := organizationAndMember(t, s)
	otherOrg, otherMember := organizationAndMember(t, s)
	local, factor := administratorMember(t, s, org.ID, 61)
	platform, platformFactor := administratorMember(t, s, SystemOrganizationID, 62)
	localPrincipal := administratorActor(t, s, local, factor).Principal()
	platformPrincipal := administratorActor(t, s, platform, platformFactor).Principal()
	name, blocked := "Scoped member", true
	if _, err := s.Manage(t.Context(), localPrincipal, "member.update", org.ID, target.ID, ManagementChange{DisplayName: &name, ManualBlocked: &blocked}); err != nil {
		t.Fatal("organization administrator member status", err)
	}
	if _, err := s.Manage(t.Context(), localPrincipal, "member.create", org.ID, "", ManagementChange{DisplayName: &name}); err != nil {
		t.Fatal(err)
	}
	for _, operation := range []func() error{
		func() error {
			_, err := s.Manage(t.Context(), localPrincipal, "member.create", otherOrg.ID, "", ManagementChange{DisplayName: &name})
			return err
		},
		func() error {
			_, err := s.Manage(t.Context(), localPrincipal, "member.update", otherOrg.ID, otherMember.ID, ManagementChange{DisplayName: &name})
			return err
		},
		func() error {
			_, err := s.Manage(t.Context(), localPrincipal, "member.create", SystemOrganizationID, "", ManagementChange{DisplayName: &name})
			return err
		},
	} {
		if err := operation(); !errors.Is(err, ErrForbidden) {
			t.Fatal("cross-organization mutation", err)
		}
	}
	if _, err := s.Manage(t.Context(), localPrincipal, "member.update", org.ID, otherMember.ID, ManagementChange{DisplayName: &name}); !errors.Is(err, ErrNotFound) {
		t.Fatal("forged ownership", err)
	}
	if _, err := s.Manage(t.Context(), platformPrincipal, "organization.create", "", "", ManagementChange{Name: &name}); err != nil {
		t.Fatal(err)
	}
	result, err := s.Manage(t.Context(), platformPrincipal, "member.create", SystemOrganizationID, "", ManagementChange{DisplayName: &name})
	if err != nil {
		t.Fatal(err)
	}
	systemMember := result.(Member)
	if err := authorizeAll(t.Context(), s.pool, (ManagementActor{MemberID: systemMember.ID, GrantID: platform.ID}).Principal(), authorization.Requirement{Target: "organizations", Action: "create"}); !errors.Is(err, ErrForbidden) {
		t.Fatal("ordinary system membership gained authority", err)
	}
	current, err := s.Member(t.Context(), org.ID, target.ID)
	if err != nil || current.DisplayName != name || current.Status != "blocked" {
		t.Fatal(current, err)
	}
	untouched, err := s.Member(t.Context(), otherOrg.ID, otherMember.ID)
	if err != nil || untouched.DisplayName != otherMember.DisplayName {
		t.Fatal(untouched, err)
	}
	events, err := s.ManagementEvents(t.Context(), org.ID, "", 0)
	if err != nil || len(events) != 3 {
		t.Fatal("denied writes changed audit history", events, err)
	}
}

func TestScopedAdministratorAssignments(t *testing.T) {
	s := testStore(t)
	org, _ := organizationAndMember(t, s)
	local, factor := administratorMember(t, s, org.ID, 71)
	recipient, _ := administratorMember(t, s, org.ID, 72)
	platform, platformFactor := administratorMember(t, s, SystemOrganizationID, 73)
	localPrincipal := administratorActor(t, s, local, factor).Principal()
	platformPrincipal := administratorActor(t, s, platform, platformFactor).Principal()
	for _, enabled := range []bool{false, true} {
		if err := s.SetAdministrator(t.Context(), localPrincipal, org.ID, recipient.ID, enabled); err != nil {
			t.Fatal(err)
		}
		if err := s.SetAdministrator(t.Context(), localPrincipal, SystemOrganizationID, platform.ID, enabled); !errors.Is(err, ErrForbidden) {
			t.Fatal("cross-scope assignment", err)
		}
		if err := s.SetAdministrator(t.Context(), localPrincipal, org.ID, platform.ID, enabled); !errors.Is(err, ErrNotFound) {
			t.Fatal("forged assignment ownership", err)
		}
	}
	if err := s.SetAdministrator(t.Context(), platformPrincipal, org.ID, local.ID, false); err != nil {
		t.Fatal(err)
	}
	if err := s.SetAdministrator(t.Context(), localPrincipal, org.ID, local.ID, true); !errors.Is(err, ErrForbidden) {
		t.Fatal("revoked principal restored itself", err)
	}
	if err := s.SetAdministrator(t.Context(), platformPrincipal, org.ID, recipient.ID, false); !errors.Is(err, ErrLastAdministrator) {
		t.Fatal("last administrator", err)
	}
	ids, err := s.AdministratorIDs(t.Context(), org.ID)
	if err != nil || len(ids) != 1 || ids[0] != recipient.ID {
		t.Fatal(ids, err)
	}
}
