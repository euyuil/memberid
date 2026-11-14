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
		permission(organization+"/members", "create"),
		permission(organization+"/members/*", "update", "status.update"),
		permission(organization+"/roleAssignments", "create"),
		permission(organization+"/roleAssignments/*", "delete"),
	}
}

func authorizeAll(ctx context.Context, db queryer, principal Principal, requirements ...authorization.Requirement) error {
	if len(requirements) == 0 {
		return ErrInvalid
	}
	for _, requirement := range requirements {
		if !registeredManagementOperation(requirement) {
			return ErrInvalid
		}
	}
	if principal.installation() {
		return nil
	}
	if principal.kind != memberPrincipal {
		return ErrForbidden
	}
	actor, err := managementActor(ctx, db, principal.memberID, principal.grantID)
	if err != nil {
		return err
	}
	if err = authorization.Check(managementPermissions(actor), requirements...); errors.Is(err, authorization.ErrDenied) {
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
		return requirement.Action == "create"
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
			return requirement.Action == "create"
		}
		return len(parts) == 4 && ValidID(parts[3], MemberKind) && (requirement.Action == "update" || requirement.Action == "status.update")
	case "roleAssignments":
		if len(parts) == 3 {
			return requirement.Action == "create"
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
