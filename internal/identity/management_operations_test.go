package identity

import (
	"errors"
	"slices"
	"testing"

	"github.com/euyuil/memberid/internal/authorization"
)

func TestManagementOperationMatrix(t *testing.T) {
	organizationID, _ := NewID(OrganizationKind)
	foreignOrganizationID, _ := NewID(OrganizationKind)
	memberID, _ := NewID(MemberKind)
	otherMemberID, _ := NewID(MemberKind)
	const bindingID = "00000000-0000-4000-8000-000000000001"
	for _, targetOrganization := range []string{organizationID, SystemOrganizationID} {
		base := "organizations/" + targetOrganization
		// Literal paths and actions are an independent contract: deriving expected
		// results from the registry would hide a shared builder/registry mistake.
		cases := []struct {
			resource               managementResource
			ids                    []string
			target                 string
			supported, admin, self []string
		}{
			{organizationsResource, nil, "organizations", []string{"create", "list"}, nil, nil},
			{organizationResource, []string{targetOrganization}, base, []string{"get", "update", "status.update"}, []string{"get", "update"}, nil},
			{membersResource, []string{targetOrganization}, base + "/members", []string{"create", "list"}, []string{"create", "list"}, nil},
			{memberResource, []string{targetOrganization, memberID}, base + "/members/" + memberID, []string{"get", "update", "status.update"}, []string{"get", "update", "status.update"}, []string{"get"}},
			{bindingsResource, []string{targetOrganization, memberID}, base + "/members/" + memberID + "/bindings", []string{"create", "list"}, []string{"list"}, []string{"create"}},
			{bindingResource, []string{targetOrganization, memberID, bindingID}, base + "/members/" + memberID + "/bindings/" + bindingID, []string{"delete"}, nil, nil},
			{roleAssignmentsResource, []string{targetOrganization}, base + "/roleAssignments", []string{"create", "list"}, []string{"create", "list"}, nil},
			{roleAssignmentResource, []string{targetOrganization, memberID}, base + "/roleAssignments/" + memberID, []string{"delete"}, []string{"delete"}, nil},
			{providersResource, []string{targetOrganization}, base + "/providers", []string{"list"}, []string{"list"}, nil},
			{providerTypeResource, []string{targetOrganization, "dingtalk"}, base + "/providers/dingtalk", []string{"create"}, []string{"create"}, nil},
			{providerTypeResource, []string{targetOrganization, "feishu"}, base + "/providers/feishu", []string{"create"}, []string{"create"}, nil},
			{providerResource, []string{targetOrganization, "dingtalk", "example"}, base + "/providers/dingtalk/example", []string{"update", "status.update"}, []string{"update", "status.update"}, nil},
			{providerResource, []string{targetOrganization, "feishu", "example"}, base + "/providers/feishu/example", []string{"update", "status.update"}, []string{"update", "status.update"}, nil},
			{organizationEventsResource, []string{targetOrganization}, base + "/managementEvents", []string{"list"}, []string{"list"}, nil},
			{memberDirectoryResource, nil, "memberDirectory", []string{"list"}, nil, nil},
			{managementEventsResource, nil, "managementEvents", []string{"list"}, nil, nil},
		}
		covered := map[managementResource]bool{}
		for _, test := range cases {
			covered[test.resource] = true
			registered := slices.Clone(managementOperations[test.resource])
			expected := slices.Clone(test.supported)
			slices.Sort(registered)
			slices.Sort(expected)
			if !slices.Equal(registered, expected) {
				t.Errorf("%s: registered actions %v, want %v", test.resource, registered, expected)
			}
			for _, action := range []string{"create", "list", "get", "update", "delete", "status.update", "read", "unknown", "*", "?"} {
				required := authorization.Requirement{Target: test.target, Action: action}
				supported := slices.Contains(test.supported, action)
				built := test.resource.require(action, test.ids...)
				if supported && built != required {
					t.Fatalf("constructed %s: got %+v, want %+v", test.resource, built, required)
				}
				if !supported && registeredManagementOperation(built) {
					t.Fatalf("constructed unsupported operation: %+v", built)
				}
				for _, role := range []struct {
					name        string
					permissions []authorization.Permission
					allow       bool
				}{
					{"platform", managementPermissions(ManagementActor{Platform: true}), supported},
					{"organization", managementPermissions(ManagementActor{OrganizationID: organizationID}), targetOrganization == organizationID && slices.Contains(test.admin, action)},
					{"foreign organization", managementPermissions(ManagementActor{OrganizationID: foreignOrganizationID}), false},
					{"selected self", accountPermissions(targetOrganization, memberID), slices.Contains(test.self, action)},
					{"other self", accountPermissions(targetOrganization, otherMemberID), false},
					{"foreign self", accountPermissions(foreignOrganizationID, memberID), false},
					{"ordinary management", nil, false},
				} {
					var want error
					if !supported {
						want = ErrInvalid
					} else if !role.allow {
						want = ErrForbidden
					}
					if err := checkManagementPermissions(role.permissions, required); !errors.Is(err, want) {
						t.Errorf("%s: %s %s: got %v, want %v", role.name, action, test.target, err, want)
					}
				}
			}
		}
		for resource := range managementOperations {
			if !covered[resource] {
				t.Errorf("resource missing from authority matrix: %s", resource)
			}
		}
		// Every built-in grant must cover a registered operation. This catches
		// stale or misspelled paths/actions even when they fail closed.
		for _, permissions := range [][]authorization.Permission{
			managementPermissions(ManagementActor{Platform: true}),
			managementPermissions(ManagementActor{OrganizationID: organizationID}),
			accountPermissions(organizationID, memberID),
		} {
			if targetOrganization != organizationID {
				continue
			}
			for _, grant := range permissions {
				for _, action := range grant.Actions {
					matched := false
					for _, test := range cases {
						for _, operation := range test.supported {
							matched = matched || checkManagementPermissions([]authorization.Permission{permission(grant.Scope.Pattern, action)}, authorization.Requirement{Target: test.target, Action: operation}) == nil
						}
					}
					if !matched {
						t.Errorf("unused built-in grant: %s %s", grant.Scope.Pattern, action)
					}
				}
			}
		}
	}
}

func TestManagementTargetsRejectMalformedArguments(t *testing.T) {
	org, _ := NewID(OrganizationKind)
	member, _ := NewID(MemberKind)
	factor, _ := NewID(FactorKind)
	platform := managementPermissions(ManagementActor{Platform: true})
	for _, requirement := range []authorization.Requirement{
		organizationResource.require("get"),
		organizationResource.require("get", org, member),
		organizationResource.require("get", org+"/members/"+member),
		organizationResource.require("get", ""),
		organizationResource.require("get", member),
		memberResource.require("get", org, "?"),
		memberResource.require("get", org, "*"),
		memberResource.require("get", org, "**"),
		bindingResource.require("delete", org, member, factor),
		roleAssignmentResource.require("delete", org, "00000000-0000-4000-8000-000000000001"),
		providerTypeResource.require("create", org, "unknown"),
		providerResource.require("update", org, "feishu", "example/nested"),
		providerResource.require("update", org, "feishu", "exam?le"),
		providerResource.require("update", org, "feishu", "example provider"),
		managementResource("unknown").require("get"),
		{Target: "organizations/" + org + "/members/?", Action: "get"},
		{Target: "organizations/" + org + "/providers/feishu/*", Action: "update"},
	} {
		if err := checkManagementPermissions(platform, requirement); !errors.Is(err, ErrInvalid) {
			t.Errorf("malformed target accepted: %+v: %v", requirement, err)
		}
	}
	if got := providerResource.pattern(org, "?", "?"); got != "organizations/"+org+"/providers/?/?" {
		t.Fatal("policy selectors lost single-segment wildcards", got)
	}
	if err := checkManagementPermissions([]authorization.Permission{permission(memberResource.pattern("", "?"), "get")}, memberResource.require("get", org, member)); !errors.Is(err, ErrInvalid) {
		t.Fatal("invalid policy arguments granted authority", err)
	}
}
