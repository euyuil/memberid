package identity

import (
	"context"
	"errors"

	"github.com/euyuil/memberid/internal/authorization"
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

func (store *Store) ManagementOrganizations(ctx context.Context, principal Principal, after string, limit int) (Page[Organization], error) {
	actor, err := store.managementReadActor(ctx, principal)
	if err != nil {
		return Page[Organization]{}, err
	}
	permissions := managementPermissions(actor)
	err = checkManagementPermissions(permissions, authorization.Requirement{Target: "organizations", Action: "list"})
	if err == nil {
		return store.Organizations(ctx, after, limit)
	}
	if !errors.Is(err, ErrForbidden) {
		return Page[Organization]{}, err
	}
	if err := checkManagementPermissions(permissions, authorization.Requirement{Target: "organizations/" + actor.OrganizationID, Action: "get"}); err != nil {
		return Page[Organization]{}, err
	}
	organization, err := store.Organization(ctx, actor.OrganizationID)
	if err != nil {
		return Page[Organization]{}, err
	}
	return Page[Organization]{Items: []Organization{organization}}, nil
}

func (store *Store) ManagementOrganization(ctx context.Context, principal Principal, organizationID string) (Organization, error) {
	if err := store.authorizeManagementRead(ctx, principal, authorization.Requirement{Target: "organizations/" + organizationID, Action: "get"}); err != nil {
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
	organization := "organizations/" + organizationID
	if memberID == "" {
		return []authorization.Requirement{{Target: organization + "/members", Action: "list"}, {Target: organization + "/roleAssignments", Action: "list"}}
	}
	member := organization + "/members/" + memberID
	return []authorization.Requirement{{Target: member, Action: "get"}, {Target: member + "/bindings", Action: "list"}, {Target: organization + "/roleAssignments", Action: "list"}}
}

func (store *Store) ManagementMembers(ctx context.Context, principal Principal, organizationID, after string, limit int, filter MemberDirectoryFilter) (ManagementMemberPage, error) {
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
	Member           Member    `json:"member"`
	Bindings         []Binding `json:"bindings"`
	AdministratorIDs []string  `json:"administratorIds"`
}

func (store *Store) ManagementMember(ctx context.Context, principal Principal, organizationID, memberID string) (ManagementMemberDetail, error) {
	if !ValidID(memberID, MemberKind) {
		return ManagementMemberDetail{}, ErrInvalid
	}
	if err := store.authorizeManagementRead(ctx, principal, memberReadRequirements(organizationID, memberID)...); err != nil {
		return ManagementMemberDetail{}, err
	}
	member, err := store.Member(ctx, organizationID, memberID)
	if err != nil {
		return ManagementMemberDetail{}, err
	}
	bindings, err := store.Bindings(ctx, organizationID, memberID)
	if err != nil {
		return ManagementMemberDetail{}, err
	}
	ids, err := store.AdministratorIDs(ctx, organizationID)
	if err != nil {
		return ManagementMemberDetail{}, err
	}
	return ManagementMemberDetail{Member: member, Bindings: bindings, AdministratorIDs: ids}, nil
}

func (store *Store) ManagementMemberDirectory(ctx context.Context, principal Principal, after string, limit int, filter MemberDirectoryFilter) (Page[MemberDirectoryEntry], error) {
	if err := store.authorizeManagementRead(ctx, principal, authorization.Requirement{Target: "memberDirectory", Action: "list"}); err != nil {
		return Page[MemberDirectoryEntry]{}, err
	}
	return store.AllOrganizationMembers(ctx, after, limit, filter)
}

func (store *Store) ManagementHistory(ctx context.Context, principal Principal, organizationID, memberID string, before int64) ([]ManagementEvent, error) {
	actor, err := store.managementReadActor(ctx, principal)
	if err != nil {
		return nil, err
	}
	if before < 0 || memberID != "" && !ValidID(memberID, MemberKind) {
		return nil, ErrInvalid
	}
	permissions := managementPermissions(actor)
	if organizationID == "" {
		err := checkManagementPermissions(permissions, authorization.Requirement{Target: "managementEvents", Action: "list"})
		if err == nil {
			return store.ManagementEvents(ctx, "", memberID, before)
		}
		if !errors.Is(err, ErrForbidden) {
			return nil, err
		}
		organizationID = actor.OrganizationID
	}
	if err := checkManagementPermissions(permissions, authorization.Requirement{Target: "organizations/" + organizationID + "/managementEvents", Action: "list"}); err != nil {
		return nil, err
	}
	return store.ManagementEvents(ctx, organizationID, memberID, before)
}
