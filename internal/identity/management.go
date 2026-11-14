package identity

import (
	"context"
	"strings"

	"github.com/jackc/pgx/v5"
)

type Page[T any] struct {
	Items     []T    `json:"items"`
	NextAfter string `json:"nextAfter,omitempty"`
}

func (store *Store) Organizations(ctx context.Context, after string, limit int) (Page[Organization], error) {
	page := Page[Organization]{Items: []Organization{}}
	if limit < 1 || limit > 100 || after != "" && !ValidID(after, OrganizationKind) {
		return page, ErrInvalid
	}
	rows, err := store.pool.Query(ctx, "SELECT "+organizationColumns+" FROM organizations WHERE id>$1 ORDER BY id LIMIT $2", after, limit+1)
	if err != nil {
		return page, err
	}
	defer rows.Close()
	for rows.Next() {
		item, err := readOrganization(rows)
		if err != nil {
			return page, err
		}
		if len(page.Items) == limit {
			page.NextAfter = page.Items[limit-1].ID
			break
		}
		page.Items = append(page.Items, item)
	}
	return page, rows.Err()
}

type MemberDirectoryFilter struct {
	Query         string
	Status        string
	Administrator string
}

func (store *Store) Members(ctx context.Context, organizationID, after string, limit int) (Page[Member], error) {
	return store.MemberDirectory(ctx, organizationID, after, limit, MemberDirectoryFilter{})
}

func (store *Store) MemberDirectory(ctx context.Context, organizationID, after string, limit int, filter MemberDirectoryFilter) (Page[Member], error) {
	page := Page[Member]{Items: []Member{}}
	if !ValidID(organizationID, OrganizationKind) {
		return page, ErrInvalid
	}
	entries, err := store.memberDirectory(ctx, organizationID, after, limit, filter)
	if err != nil {
		return page, err
	}
	page.NextAfter = entries.NextAfter
	for _, entry := range entries.Items {
		page.Items = append(page.Items, entry.Member)
	}
	return page, nil
}

type MemberDirectoryEntry struct {
	Member
	OrganizationName string `json:"organizationName"`
	Administrator    bool   `json:"administrator"`
}

func (store *Store) AllOrganizationMembers(ctx context.Context, after string, limit int, filter MemberDirectoryFilter) (Page[MemberDirectoryEntry], error) {
	return store.memberDirectory(ctx, "", after, limit, filter)
}

func (store *Store) memberDirectory(ctx context.Context, organizationID, after string, limit int, filter MemberDirectoryFilter) (Page[MemberDirectoryEntry], error) {
	page := Page[MemberDirectoryEntry]{Items: []MemberDirectoryEntry{}}
	if limit < 1 || limit > 100 || after != "" && !ValidID(after, MemberKind) {
		return page, ErrInvalid
	}
	filter.Query = strings.TrimSpace(filter.Query)
	if filter.Query != "" && !validText(filter.Query, 128) ||
		filter.Status != "" && filter.Status != "active" && filter.Status != "blocked" ||
		filter.Administrator != "" && filter.Administrator != "yes" && filter.Administrator != "no" {
		return page, ErrInvalid
	}
	if organizationID != "" {
		if _, err := store.Organization(ctx, organizationID); err != nil {
			return page, err
		}
	}
	rows, err := store.pool.Query(ctx, `SELECT
 m.id,m.organization_id,m.display_name,m.manual_block,m.external_departure,m.created_at,m.updated_at,
 o.name,a.member_id IS NOT NULL
 FROM members m JOIN organizations o ON o.id=m.organization_id
 LEFT JOIN administrators a ON a.organization_id=m.organization_id AND a.member_id=m.id
 WHERE ($1='' OR m.organization_id=$1) AND m.id>$2
 AND ($4='' OR strpos(lower(m.display_name),lower($4))>0 OR strpos(m.id,lower($4))>0)
 AND ($5='' OR (m.manual_block OR m.external_departure)=($5='blocked'))
 AND ($6='' OR (a.member_id IS NOT NULL)=($6='yes'))
 ORDER BY m.id LIMIT $3`, organizationID, after, limit+1, filter.Query, filter.Status, filter.Administrator)
	if err != nil {
		return page, err
	}
	defer rows.Close()
	for rows.Next() {
		var item MemberDirectoryEntry
		if err := scanMember(rows, &item.Member, &item.OrganizationName, &item.Administrator); err != nil {
			return page, err
		}
		if len(page.Items) == limit {
			page.NextAfter = page.Items[limit-1].ID
			break
		}
		page.Items = append(page.Items, item)
	}
	return page, rows.Err()
}

type OrganizationChange struct {
	Name   *string `json:"name"`
	Status *string `json:"status"`
}

func (store *Store) UpdateOrganization(ctx context.Context, principal Principal, id string, change OrganizationChange) (Organization, error) {
	if !principal.installation() {
		return Organization{}, ErrForbidden
	}
	requirements, err := organizationUpdateRequirements(id, change)
	if err != nil {
		return Organization{}, err
	}
	var result Organization
	err = pgx.BeginFunc(ctx, store.pool, func(tx pgx.Tx) error {
		if err := managementLock(ctx, tx); err != nil {
			return err
		}
		if err := authorizeAll(ctx, tx, principal, requirements...); err != nil {
			return err
		}
		var err error
		result, err = updateOrganization(ctx, tx, id, change)
		if err != nil {
			return err
		}
		return managementEvent(ctx, tx, principal, id, "", "organization.update", change)
	})
	return result, err
}

func updateOrganization(ctx context.Context, database queryer, id string, change OrganizationChange) (Organization, error) {
	if id == SystemOrganizationID && change.Status != nil && *change.Status != "enabled" {
		return Organization{}, ErrForbidden
	}
	if !ValidID(id, OrganizationKind) || change.Name == nil && change.Status == nil || change.Name != nil && !validText(*change.Name, 128) || change.Status != nil && *change.Status != "enabled" && *change.Status != "disabled" {
		return Organization{}, ErrInvalid
	}
	return readOrganization(database.QueryRow(ctx, "UPDATE organizations SET name=COALESCE($2,name),status=COALESCE($3,status),lifecycle_revision=lifecycle_revision+CASE WHEN $3 IS NOT NULL AND status<>$3 THEN 1 ELSE 0 END,updated_at=clock_timestamp() WHERE id=$1 RETURNING "+organizationColumns, id, change.Name, change.Status))
}

type MemberChange struct {
	DisplayName   *string `json:"displayName"`
	ManualBlocked *bool   `json:"manualBlocked"`
}

func validMemberChange(change MemberChange) bool {
	return (change.DisplayName != nil || change.ManualBlocked != nil) && (change.DisplayName == nil || validText(*change.DisplayName, 128))
}

func (store *Store) UpdateMember(ctx context.Context, principal Principal, organizationID, memberID string, change MemberChange) (Member, error) {
	if !principal.installation() {
		return Member{}, ErrForbidden
	}
	var result Member
	err := pgx.BeginFunc(ctx, store.pool, func(tx pgx.Tx) error {
		var err error
		result, err = updateMember(ctx, tx, organizationID, memberID, change)
		if err != nil {
			return err
		}
		return managementEvent(ctx, tx, principal, organizationID, memberID, "member.update", change)
	})
	return result, err
}

func updateMember(ctx context.Context, database pgx.Tx, organizationID, memberID string, change MemberChange) (Member, error) {
	if !ValidID(organizationID, OrganizationKind) || !ValidID(memberID, MemberKind) || !validMemberChange(change) {
		return Member{}, ErrInvalid
	}
	if err := managementLock(ctx, database); err != nil {
		return Member{}, err
	}
	before, err := availableAdministrators(ctx, database, organizationID)
	if err != nil {
		return Member{}, err
	}
	member, err := readMember(database.QueryRow(ctx, "UPDATE members SET display_name=COALESCE($3,display_name),manual_block=COALESCE($4,manual_block),eligibility_revision=eligibility_revision+CASE WHEN $4 IS NOT NULL AND manual_block<>$4 THEN 1 ELSE 0 END,updated_at=clock_timestamp() WHERE id=$1 AND organization_id=$2 RETURNING "+memberColumns, memberID, organizationID, change.DisplayName, change.ManualBlocked))
	if err != nil {
		return member, err
	}
	return member, preserveAdministrators(ctx, database, organizationID, before)
}

func (store *Store) Bindings(ctx context.Context, organizationID, memberID string) ([]Binding, error) {
	if _, err := store.Member(ctx, organizationID, memberID); err != nil {
		return nil, err
	}
	rows, err := store.pool.Query(ctx, "SELECT "+bindingColumns+" FROM member_auth_factor_bindings WHERE organization_id=$1 AND member_id=$2 ORDER BY factor_type", organizationID, memberID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := []Binding{}
	for rows.Next() {
		binding, err := readBinding(rows)
		if err != nil {
			return nil, err
		}
		result = append(result, binding)
	}
	return result, rows.Err()
}
