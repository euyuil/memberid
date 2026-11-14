//go:build integration

package identity

import (
	"errors"
	"testing"
)

func TestManagementReadServicesEnforceScope(t *testing.T) {
	s := testStore(t)
	org, target := organizationAndMember(t, s)
	otherOrg, otherTarget := organizationAndMember(t, s)
	local, factor := administratorMember(t, s, org.ID, 81)
	platform, platformFactor := administratorMember(t, s, SystemOrganizationID, 82)
	administratorMember(t, s, otherOrg.ID, 83)
	actor := administratorActor(t, s, local, factor)
	// Presentation fields cannot select the navigation organization or role.
	actor.OrganizationID, actor.Platform = otherOrg.ID, true
	principal := actor.Principal()
	platformPrincipal := administratorActor(t, s, platform, platformFactor).Principal()
	navigation, err := s.ManagementOrganizations(t.Context(), principal, "", 50)
	if err != nil || len(navigation.Items) != 1 || navigation.Items[0].ID != org.ID {
		t.Fatal(navigation, err)
	}
	all, err := s.ManagementOrganizations(t.Context(), platformPrincipal, "", 50)
	if err != nil || len(all.Items) != 3 {
		t.Fatal(all, err)
	}
	page, err := s.ManagementMembers(t.Context(), principal, org.ID, "", 1, MemberDirectoryFilter{})
	if err != nil || len(page.Items) != 1 || page.NextAfter == "" || len(page.AdministratorIDs) != 1 || page.AdministratorIDs[0] != local.ID {
		t.Fatal(page, err)
	}
	detail, err := s.ManagementMember(t.Context(), principal, org.ID, local.ID)
	if err != nil || detail.Member.ID != local.ID || len(detail.Bindings) != 1 || len(detail.AdministratorIDs) != 1 {
		t.Fatal(detail, err)
	}
	rejected, err := s.ManagementMember(t.Context(), principal, org.ID, otherTarget.ID)
	if !errors.Is(err, ErrNotFound) || rejected.Member.ID != "" || len(rejected.AdministratorIDs) != 0 {
		t.Fatal("forged member ownership", rejected, err)
	}
	for _, read := range []func() error{
		func() error { _, err := s.ManagementOrganization(t.Context(), principal, otherOrg.ID); return err },
		func() error {
			_, err := s.ManagementMembers(t.Context(), principal, otherOrg.ID, "", 50, MemberDirectoryFilter{})
			return err
		},
		func() error {
			_, err := s.ManagementMember(t.Context(), principal, otherOrg.ID, otherTarget.ID)
			return err
		},
		func() error {
			_, err := s.ManagementMemberDirectory(t.Context(), principal, "", 50, MemberDirectoryFilter{})
			return err
		},
		func() error { _, err := s.ManagementHistory(t.Context(), principal, otherOrg.ID, "", 0); return err },
		func() error {
			_, err := s.ManagementOrganization(t.Context(), InstallationManagerPrincipal(), org.ID)
			return err
		},
		func() error {
			_, err := s.ManagementMembers(t.Context(), Principal{}, org.ID, "", 50, MemberDirectoryFilter{})
			return err
		},
	} {
		if err := read(); !errors.Is(err, ErrForbidden) {
			t.Fatal("service read escaped principal scope", err)
		}
	}
	events, err := s.ManagementHistory(t.Context(), principal, "", "", 0)
	if err != nil || len(events) != 1 || events[0].OrganizationID != org.ID {
		t.Fatal(events, err)
	}
	filtered, err := s.ManagementHistory(t.Context(), principal, "", otherTarget.ID, 0)
	if err != nil || len(filtered) != 0 {
		t.Fatal("Member filter widened event scope", filtered, err)
	}
	global, err := s.ManagementHistory(t.Context(), platformPrincipal, "", "", 0)
	if err != nil || len(global) != 3 {
		t.Fatal(global, err)
	}
	directory, err := s.ManagementMemberDirectory(t.Context(), platformPrincipal, "", 50, MemberDirectoryFilter{})
	if err != nil || len(directory.Items) != 5 {
		t.Fatal(directory, err)
	}
	administratorMember(t, s, org.ID, 84)
	if err := s.SetAdministrator(t.Context(), platformPrincipal, org.ID, local.ID, false); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ManagementMember(t.Context(), principal, org.ID, target.ID); !errors.Is(err, ErrForbidden) {
		t.Fatal("revoked assignment retained read access", err)
	}
	if _, err := s.ManagementOrganizations(t.Context(), principal, "", 50); !errors.Is(err, ErrForbidden) {
		t.Fatal("revoked assignment retained navigation", err)
	}
}
