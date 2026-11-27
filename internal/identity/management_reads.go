package identity

import (
	"context"
	"errors"

	"github.com/zhizhun-tech/memberid/internal/authorization"
)

// Management read services authorize the complete response before querying its
// contents. Raw store queries also serve protocol and installation-only callers.
func (store *Store) managementReadActor(ctx context.Context, principal Principal) (ManagementActor, error) {
	if principal.kind != memberPrincipal {
		return ManagementActor{}, ErrForbidden
	}
	return managementActor(ctx, store.pool, principal.memberID, principal.grantID)
}

func (store *Store) authorizeManagementRead(ctx context.Context, principal Principal, requirements ...authorization.Requirement) error {
	actor, err := store.managementReadActor(ctx, principal)
	if err != nil {
		return err
	}
	return checkManagementPermissions(managementPermissions(actor), requirements...)
}

func (service *ManagementService) Organizations(ctx context.Context, principal Principal, after string, limit int) (Page[Organization], error) {
	store := service.store
	actor, err := store.managementReadActor(ctx, principal)
	if err != nil {
		return Page[Organization]{}, err
	}
	permissions := managementPermissions(actor)
	err = checkManagementPermissions(permissions, organizationsResource.require(actionList))
	if err == nil {
		return store.Organizations(ctx, after, limit)
	}
	if !errors.Is(err, ErrForbidden) {
		return Page[Organization]{}, err
	}
	if err := checkManagementPermissions(permissions, organizationResource.require(actionGet, actor.OrganizationID)); err != nil {
		return Page[Organization]{}, err
	}
	organization, err := store.Organization(ctx, actor.OrganizationID)
	if err != nil {
		return Page[Organization]{}, err
	}
	return Page[Organization]{Items: []Organization{organization}}, nil
}

func (service *ManagementService) Organization(ctx context.Context, principal Principal, organizationID string) (Organization, error) {
	store := service.store
	if err := store.authorizeManagementRead(ctx, principal, organizationResource.require(actionGet, organizationID)); err != nil {
		return Organization{}, err
	}
	return store.Organization(ctx, organizationID)
}

type ManagementMemberPage struct {
	Items            []Member `json:"items"`
	NextAfter        string   `json:"nextAfter"`
	AdministratorIDs []string `json:"administratorIds"`
}

func memberReadRequirements(organizationID, memberID string) []authorization.Requirement {
	if memberID == "" {
		return []authorization.Requirement{
			membersResource.require(actionList, organizationID),
			roleAssignmentsResource.require(actionList, organizationID),
		}
	}
	return []authorization.Requirement{
		memberResource.require(actionGet, organizationID, memberID),
		bindingsResource.require(actionList, organizationID, memberID),
		memberEmailResource.require(actionGet, organizationID, memberID),
		roleAssignmentsResource.require(actionList, organizationID),
	}
}

func (service *ManagementService) Members(ctx context.Context, principal Principal, organizationID, after string, limit int, filter MemberDirectoryFilter) (ManagementMemberPage, error) {
	store := service.store
	if err := store.authorizeManagementRead(ctx, principal, memberReadRequirements(organizationID, "")...); err != nil {
		return ManagementMemberPage{}, err
	}
	page, err := store.MemberDirectory(ctx, organizationID, after, limit, filter)
	if err != nil {
		return ManagementMemberPage{}, err
	}
	ids, err := store.AdministratorIDs(ctx, organizationID)
	if err != nil {
		return ManagementMemberPage{}, err
	}
	return ManagementMemberPage{Items: page.Items, NextAfter: page.NextAfter, AdministratorIDs: ids}, nil
}

type ManagementMemberDetail struct {
	Member           Member              `json:"member"`
	Bindings         []ManagementBinding `json:"bindings"`
	AdministratorIDs []string            `json:"administratorIds"`
	PasswordUsername string              `json:"passwordUsername,omitempty"`
	Email            MemberEmail         `json:"email"`
}

func (service *ManagementService) Member(ctx context.Context, principal Principal, organizationID, memberID string) (ManagementMemberDetail, error) {
	store := service.store
	if !ValidID(memberID, MemberKind) {
		return ManagementMemberDetail{}, ErrInvalid
	}
	if err := store.authorizeManagementRead(ctx, principal, memberReadRequirements(organizationID, memberID)...); err != nil {
		return ManagementMemberDetail{}, err
	}
	var member Member
	var username string
	row := store.pool.QueryRow(ctx, "SELECT "+memberColumns+
		",COALESCE((SELECT f.subject"+memberPasswordBinding+"),'') FROM members WHERE organization_id=$1 AND id=$2",
		organizationID, memberID)
	err := scanMember(row, &member, &username)
	if err != nil {
		return ManagementMemberDetail{}, err
	}
	bindings, err := store.managementBindings(ctx, member.OrganizationID, member.ID)
	if err != nil {
		return ManagementMemberDetail{}, err
	}
	ids, err := store.AdministratorIDs(ctx, organizationID)
	if err != nil {
		return ManagementMemberDetail{}, err
	}
	email, err := readMemberEmail(ctx, store.pool, organizationID, memberID)
	if err != nil {
		return ManagementMemberDetail{}, err
	}
	return ManagementMemberDetail{Member: member, Bindings: bindings, AdministratorIDs: ids, PasswordUsername: username, Email: email}, nil
}

func (service *ManagementService) MemberDirectory(ctx context.Context, principal Principal, after string, limit int, filter MemberDirectoryFilter) (Page[MemberDirectoryEntry], error) {
	store := service.store
	if err := store.authorizeManagementRead(ctx, principal, memberDirectoryResource.require(actionList)); err != nil {
		return Page[MemberDirectoryEntry]{}, err
	}
	return store.AllOrganizationMembers(ctx, after, limit, filter)
}

func (service *ManagementService) History(ctx context.Context, principal Principal, organizationID, memberID string, before int64) ([]ManagementEvent, error) {
	store := service.store
	actor, err := store.managementReadActor(ctx, principal)
	if err != nil {
		return nil, err
	}
	if before < 0 || memberID != "" && !ValidID(memberID, MemberKind) {
		return nil, ErrInvalid
	}
	permissions := managementPermissions(actor)
	if organizationID == "" {
		err := checkManagementPermissions(permissions, managementEventsResource.require(actionList))
		if err == nil {
			return store.ManagementEvents(ctx, "", memberID, before)
		}
		if !errors.Is(err, ErrForbidden) {
			return nil, err
		}
		organizationID = actor.OrganizationID
	}
	if err := checkManagementPermissions(permissions, organizationEventsResource.require(actionList, organizationID)); err != nil {
		return nil, err
	}
	return store.ManagementEvents(ctx, organizationID, memberID, before)
}
