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
	return []authorization.Permission{permission("organizations/"+actor.OrganizationID, "get", "update")}
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
	if len(parts) != 2 || parts[0] != "organizations" || !ValidID(parts[1], OrganizationKind) {
		return false
	}
	switch requirement.Action {
	case "get", "update", "status.update":
		return true
	default:
		return false
	}
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
