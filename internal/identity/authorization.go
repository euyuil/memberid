package identity

import (
	"context"
	"errors"
	"strings"

	"github.com/euyuil/memberid/internal/authorization"
)

func permission(scope string, actions ...string) authorization.Permission {
	return authorization.Permission{Scope: authorization.Scope{Pattern: scope}, Actions: actions}
}

// managementPermissions defines built-in role authority. Assignments are read
// from storage for each operation; these descriptions are not session claims.
func managementPermissions(actor ManagementActor) []authorization.Permission {
	if actor.Platform {
		return []authorization.Permission{permission("**", "**")}
	}
	organization := "organizations/" + actor.OrganizationID
	return []authorization.Permission{
		permission(organization, "get", "update"),
		permission(organization+"/members", "list", "create"),
		permission(organization+"/members/*", "get", "update", "status.update"),
		permission(organization+"/members/*/bindings", "list"),
		permission(organization+"/roleAssignments", "list", "create"),
		permission(organization+"/roleAssignments/*", "delete"),
		permission(organization+"/managementEvents", "list"),
		permission(organization+"/providers", "list"),
		permission(organization+"/providers/*", "create"),
		permission(organization+"/providers/*/*", "update", "status.update"),
	}
}

func authorizeAll(ctx context.Context, db queryer, principal Principal, requirements ...authorization.Requirement) error {
	if principal.installation() {
		return checkManagementPermissions([]authorization.Permission{permission("**", "**")}, requirements...)
	}
	if principal.kind != memberPrincipal {
		return ErrForbidden
	}
	actor, err := managementActor(ctx, db, principal.memberID, principal.grantID)
	if err != nil {
		return err
	}
	return checkManagementPermissions(managementPermissions(actor), requirements...)
}

func checkManagementPermissions(permissions []authorization.Permission, requirements ...authorization.Requirement) error {
	if len(requirements) == 0 {
		return ErrInvalid
	}
	for _, requirement := range requirements {
		if !registeredManagementOperation(requirement) {
			return ErrInvalid
		}
	}
	if err := authorization.Check(permissions, requirements...); errors.Is(err, authorization.ErrDenied) {
		return ErrForbidden
	} else if err != nil {
		return ErrInvalid
	}
	return nil
}

// Registered operations constrain even a platform-wide wildcard. Further
// resource families are registered when their service boundaries are migrated.
func registeredManagementOperation(requirement authorization.Requirement) bool {
	parts := strings.Split(requirement.Target, "/")
	if requirement.Target == "organizations" {
		return requirement.Action == "create" || requirement.Action == "list"
	}
	if requirement.Target == "memberDirectory" || requirement.Target == "managementEvents" {
		return requirement.Action == "list"
	}
	if len(parts) < 2 || parts[0] != "organizations" || !ValidID(parts[1], OrganizationKind) {
		return false
	}
	if len(parts) == 2 {
		return requirement.Action == "get" || requirement.Action == "update" || requirement.Action == "status.update"
	}
	switch parts[2] {
	case "members":
		if len(parts) == 3 {
			return requirement.Action == "create" || requirement.Action == "list"
		}
		if !ValidID(parts[3], MemberKind) {
			return false
		}
		if len(parts) == 5 && parts[4] == "bindings" {
			return requirement.Action == "list"
		}
		return len(parts) == 4 && (requirement.Action == "get" || requirement.Action == "update" || requirement.Action == "status.update")
	case "providers":
		if len(parts) == 3 {
			return requirement.Action == "list"
		}
		if parts[3] != "dingtalk" && parts[3] != "feishu" {
			return false
		}
		if len(parts) == 4 {
			return requirement.Action == "create"
		}
		return len(parts) == 5 && validText(parts[4], 128) && (requirement.Action == "update" || requirement.Action == "status.update")
	case "managementEvents":
		return len(parts) == 3 && requirement.Action == "list"
	case "roleAssignments":
		if len(parts) == 3 {
			return requirement.Action == "create" || requirement.Action == "list"
		}
		// Existing assignments are keyed by Member, not a separate public ID.
		return len(parts) == 4 && ValidID(parts[3], MemberKind) && requirement.Action == "delete"
	}
	return false
}

func memberUpdateRequirements(organizationID, memberID string, change MemberChange) ([]authorization.Requirement, error) {
	if !ValidID(organizationID, OrganizationKind) || !ValidID(memberID, MemberKind) || !validMemberChange(change) {
		return nil, ErrInvalid
	}
	target := "organizations/" + organizationID + "/members/" + memberID
	var requirements []authorization.Requirement
	if change.DisplayName != nil {
		requirements = append(requirements, authorization.Requirement{Target: target, Action: "update"})
	}
	if change.ManualBlocked != nil {
		requirements = append(requirements, authorization.Requirement{Target: target, Action: "status.update"})
	}
	return requirements, nil
}

func managementWriteRequirements(action, organizationID, memberID string, change ManagementChange) ([]authorization.Requirement, error) {
	switch action {
	case "organization.create":
		if organizationID == "" && memberID == "" && change.Name != nil && validText(*change.Name, 128) && change.Status == nil && change.DisplayName == nil && change.ManualBlocked == nil {
			return []authorization.Requirement{{Target: "organizations", Action: "create"}}, nil
		}
	case "organization.update":
		if memberID == "" && change.DisplayName == nil && change.ManualBlocked == nil {
			return organizationUpdateRequirements(organizationID, OrganizationChange{Name: change.Name, Status: change.Status})
		}
	case "member.create":
		if ValidID(organizationID, OrganizationKind) && memberID == "" && change.DisplayName != nil && validText(*change.DisplayName, 128) && change.Name == nil && change.Status == nil && change.ManualBlocked == nil {
			return []authorization.Requirement{{Target: "organizations/" + organizationID + "/members", Action: "create"}}, nil
		}
	case "member.update":
		if change.Name == nil && change.Status == nil {
			return memberUpdateRequirements(organizationID, memberID, MemberChange{DisplayName: change.DisplayName, ManualBlocked: change.ManualBlocked})
		}
	}
	return nil, ErrInvalid
}

func organizationUpdateRequirements(organizationID string, change OrganizationChange) ([]authorization.Requirement, error) {
	if !ValidID(organizationID, OrganizationKind) || change.Name == nil && change.Status == nil {
		return nil, ErrInvalid
	}
	target := "organizations/" + organizationID
	var requirements []authorization.Requirement
	if change.Name != nil {
		requirements = append(requirements, authorization.Requirement{Target: target, Action: "update"})
	}
	if change.Status != nil {
		requirements = append(requirements, authorization.Requirement{Target: target, Action: "status.update"})
	}
	return requirements, nil
}

func providerWriteRequirements(organizationID, kind, namespace string, statusSubmitted bool) []authorization.Requirement {
	target := "organizations/" + organizationID + "/providers/" + kind
	if namespace == "" {
		return []authorization.Requirement{{Target: target, Action: "create"}}
	}
	target += "/" + namespace
	requirements := []authorization.Requirement{{Target: target, Action: "update"}}
	if statusSubmitted {
		requirements = append(requirements, authorization.Requirement{Target: target, Action: "status.update"})
	}
	return requirements
}
