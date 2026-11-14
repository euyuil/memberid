package identity

import (
	"errors"
	"testing"

	"github.com/euyuil/memberid/internal/authorization"
)

func TestManagementWritePermissionBoundaries(t *testing.T) {
	org, _ := NewID(OrganizationKind)
	member, _ := NewID(MemberKind)
	base := "organizations/" + org
	permissions := managementPermissions(ManagementActor{OrganizationID: org})
	for _, test := range []struct {
		target, action string
		allow          bool
	}{
		{"organizations", "create", false}, {base, "update", true}, {base, "status.update", false},
		{base + "/members", "create", true}, {base + "/members/" + member, "update", true},
		{base + "/members/" + member, "status.update", true},
		{base + "/members/" + member + "/bindings", "create", false},
		{base + "/roleAssignments", "create", true}, {base + "/roleAssignments/" + member, "delete", true},
		{base + "/roleAssignments/" + member, "update", false},
		{"organizations/" + SystemOrganizationID + "/members", "create", false},
	} {
		err := authorization.Check(permissions, authorization.Requirement{Target: test.target, Action: test.action})
		if (err == nil) != test.allow {
			t.Errorf("%s %s: %v", test.action, test.target, err)
		}
	}
	name, blocked := "Example", false
	requirements, err := memberUpdateRequirements(org, member, MemberChange{DisplayName: &name, ManualBlocked: &blocked})
	if err != nil {
		t.Fatal(err)
	}
	if err := authorization.Check([]authorization.Permission{permission(base+"/members/*", "update")}, requirements...); !errors.Is(err, authorization.ErrDenied) {
		t.Fatal("explicit unchanged status did not require status.update", err)
	}
	for _, action := range []string{"organization.create", "organization.update", "member.create", "member.update", "unknown"} {
		if _, err := managementWriteRequirements(action, org, member, ManagementChange{Name: &name, DisplayName: &name, ManualBlocked: &blocked}); !errors.Is(err, ErrInvalid) {
			t.Fatal("unsupported fields accepted", action, err)
		}
	}
	if err := (&Store{}).SetAdministrator(t.Context(), InstallationManagerPrincipal(), org, member, true); !errors.Is(err, ErrForbidden) {
		t.Fatal("private installation principal acquired administrator entry", err)
	}
}

func TestCompositeMemberReadRequiresEveryComponent(t *testing.T) {
	org, _ := NewID(OrganizationKind)
	member, _ := NewID(MemberKind)
	base := "organizations/" + org
	requirements := memberReadRequirements(org, member)
	permissions := []authorization.Permission{
		permission(base+"/members/"+member, "get"),
		permission(base+"/members/"+member+"/bindings", "list"),
		permission(base+"/roleAssignments", "list"),
	}
	if err := checkManagementPermissions(permissions, requirements...); err != nil {
		t.Fatal(err)
	}
	for omitted := range permissions {
		partial := append([]authorization.Permission{}, permissions[:omitted]...)
		partial = append(partial, permissions[omitted+1:]...)
		if err := checkManagementPermissions(partial, requirements...); !errors.Is(err, ErrForbidden) {
			t.Fatalf("missing component %d allowed composite: %v", omitted, err)
		}
	}
	if err := checkManagementPermissions([]authorization.Permission{permission(base+"/members", "list")}, memberReadRequirements(org, "")...); !errors.Is(err, ErrForbidden) {
		t.Fatal("member listing implicitly included full assignment directory", err)
	}
	if err := checkManagementPermissions([]authorization.Permission{permission(base+"/members/*", "get")}, authorization.Requirement{Target: base + "/members", Action: "list"}); !errors.Is(err, ErrForbidden) {
		t.Fatal("instance get implied collection listing", err)
	}
}
