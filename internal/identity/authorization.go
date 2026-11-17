package identity

import (
	"context"
	"errors"

	"github.com/euyuil/memberid/internal/authorization"
)

func permission(scope string, actions ...string) authorization.Permission {
	return authorization.Permission{Scope: authorization.Scope{Pattern: scope}, Actions: actions}
}

// managementPermissions defines built-in role authority. Assignments are read
// from storage for each operation; these descriptions are not session claims.
func managementPermissions(actor ManagementActor) []authorization.Permission {
	if actor.Platform {
		return []authorization.Permission{permission("*", "*")}
	}
	organizationID := actor.OrganizationID
	return []authorization.Permission{
		permission(organizationResource.pattern(organizationID), actionGet, actionUpdate),
		permission(membersResource.pattern(organizationID), actionList, actionCreate),
		permission(memberResource.pattern(organizationID, "?"), actionGet, actionUpdate, actionStatusUpdate),
		permission(memberEmailResource.pattern(organizationID, "?"), actionGet, actionUpdate),
		permission(memberGrantsResource.pattern(organizationID, "?"), actionList),
		permission(bindingsResource.pattern(organizationID, "?"), actionList),
		permission(roleAssignmentsResource.pattern(organizationID), actionList, actionCreate),
		permission(roleAssignmentResource.pattern(organizationID, "?"), actionDelete),
		permission(organizationEventsResource.pattern(organizationID), actionList),
		permission(organizationAuthenticationEventResource.pattern(organizationID, "*"), "read"),
		permission(providersResource.pattern(organizationID), actionList),
		permission(providerTypeResource.pattern(organizationID, "?"), actionCreate),
		permission(providerResource.pattern(organizationID, "?", "?"), actionUpdate, actionStatusUpdate, "credential.check"),
		permission(samlServiceProvidersResource.pattern(organizationID), actionList, actionCreate),
		permission(samlServiceProviderResource.pattern(organizationID, "?"), actionGet, actionUpdate, actionStatusUpdate, actionDelete),
	}
}

func authorizeAll(ctx context.Context, db queryer, principal Principal, requirements ...authorization.Requirement) error {
	if principal.installation() {
		return checkManagementPermissions([]authorization.Permission{permission("*", "*")}, requirements...)
	}
	if principal.kind == accountPrincipal {
		organizationID, err := accountOrganization(ctx, db, principal)
		if err != nil {
			return err
		}
		return checkManagementPermissions(accountPermissions(organizationID, principal.memberID), requirements...)
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

func memberUpdateRequirements(organizationID, memberID string, change MemberChange) ([]authorization.Requirement, error) {
	if !ValidID(organizationID, OrganizationKind) || !ValidID(memberID, MemberKind) || !validMemberChange(change) {
		return nil, ErrInvalid
	}
	var requirements []authorization.Requirement
	if change.DisplayName != nil {
		requirements = append(requirements, memberResource.require(actionUpdate, organizationID, memberID))
	}
	if change.ManualBlocked != nil {
		requirements = append(requirements, memberResource.require(actionStatusUpdate, organizationID, memberID))
	}
	return requirements, nil
}

func managementWriteRequirements(action, organizationID, memberID string, change ManagementChange) ([]authorization.Requirement, error) {
	switch action {
	case "organization.create":
		if organizationID == "" && memberID == "" && change.Name != nil && validText(*change.Name, 128) && change.Status == nil && change.DisplayName == nil && change.ManualBlocked == nil {
			return []authorization.Requirement{organizationsResource.require(actionCreate)}, nil
		}
	case "organization.update":
		if memberID == "" && change.DisplayName == nil && change.ManualBlocked == nil {
			return organizationUpdateRequirements(organizationID, OrganizationChange{Name: change.Name, Status: change.Status})
		}
	case "member.create":
		if ValidID(organizationID, OrganizationKind) && memberID == "" && change.DisplayName != nil && validText(*change.DisplayName, 128) && change.Name == nil && change.Status == nil && change.ManualBlocked == nil {
			return []authorization.Requirement{membersResource.require(actionCreate, organizationID)}, nil
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
	var requirements []authorization.Requirement
	if change.Name != nil {
		requirements = append(requirements, organizationResource.require(actionUpdate, organizationID))
	}
	if change.Status != nil {
		requirements = append(requirements, organizationResource.require(actionStatusUpdate, organizationID))
	}
	return requirements, nil
}

func providerWriteRequirements(organizationID, kind, namespace string, statusSubmitted bool) []authorization.Requirement {
	if namespace == "" {
		return []authorization.Requirement{providerTypeResource.require(actionCreate, organizationID, kind)}
	}
	requirements := []authorization.Requirement{providerResource.require(actionUpdate, organizationID, kind, namespace)}
	if statusSubmitted {
		requirements = append(requirements, providerResource.require(actionStatusUpdate, organizationID, kind, namespace))
	}
	return requirements
}
