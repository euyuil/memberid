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

func TestProviderActionsSeparateCreationConfigurationAndStatus(t *testing.T) {
	org, _ := NewID(OrganizationKind)
	base := "organizations/" + org + "/providers/dingtalk"
	create := providerWriteRequirements(org, "dingtalk", "", true)
	if err := checkManagementPermissions([]authorization.Permission{permission(base, "create")}, create...); err != nil {
		t.Fatal("initial enabled is part of creation", err)
	}
	update := providerWriteRequirements(org, "dingtalk", "example-provider", true)
	if err := checkManagementPermissions([]authorization.Permission{permission(base+"/*", "update")}, update...); !errors.Is(err, ErrForbidden) {
		t.Fatal("submitted enabled did not require status authority", err)
	}
	if err := checkManagementPermissions(managementPermissions(ManagementActor{OrganizationID: org}), update...); err != nil {
		t.Fatal(err)
	}
	credentials := providerWriteRequirements(org, "dingtalk", "example-provider", false)
	if err := checkManagementPermissions([]authorization.Permission{permission(base+"/*", "update")}, credentials...); err != nil {
		t.Fatal("credential-only update required status authority", err)
	}
	if err := checkManagementPermissions([]authorization.Permission{permission("**", "**")}, authorization.Requirement{Target: base + "/example-provider", Action: "delete"}); !errors.Is(err, ErrInvalid) {
		t.Fatal("unsupported provider deletion", err)
	}
}

func TestAccountAuthorityIsLimitedToSelectedSelf(t *testing.T) {
	org, _ := NewID(OrganizationKind)
	member, _ := NewID(MemberKind)
	other, _ := NewID(MemberKind)
	factor, _ := NewID(FactorKind)
	target := "organizations/" + org + "/members/" + member
	permissions := accountPermissions(org, member)
	for _, test := range []struct {
		target, action string
		allow          bool
	}{
		{target, "get", true}, {target + "/bindings", "create", true},
		{target, "update", false}, {target + "/bindings", "list", false},
		{target + "/bindings/00000000-0000-4000-8000-000000000001", "delete", false},
		{"organizations/" + org + "/members/" + other, "get", false},
		{"organizations/" + org + "/roleAssignments", "create", false},
		{"organizations", "create", false}, {"memberDirectory", "list", false},
	} {
		err := checkManagementPermissions(permissions, authorization.Requirement{Target: test.target, Action: test.action})
		if (err == nil) != test.allow {
			t.Errorf("%s %s: %v", test.action, test.target, err)
		}
	}
	if err := checkManagementPermissions(managementPermissions(ManagementActor{Platform: true}), authorization.Requirement{Target: target + "/bindings/" + factor, Action: "delete"}); !errors.Is(err, ErrInvalid) {
		t.Fatal("factor ID accepted as binding ID", err)
	}
	// Even platform/installation credentials cannot substitute for a verified
	// account-flow context at self-service binding entry points.
	for _, principal := range []Principal{{}, OperatorPrincipal(), InstallationManagerPrincipal(), (ManagementActor{MemberID: member, GrantID: "synthetic-grant", Platform: true}).Principal()} {
		if err := LinkPhone(t.Context(), nil, principal, Verification{}, PhoneLinkTarget{}); !errors.Is(err, ErrForbidden) {
			t.Fatal(err)
		}
		if _, err := (&DingTalkVerifier{}).Link(t.Context(), nil, principal, DingTalkLoginProof{}, member); !errors.Is(err, ErrForbidden) {
			t.Fatal(err)
		}
	}
}
