package identity

import (
	"context"
	"errors"

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

func (store *Store) Members(ctx context.Context, organizationID, after string, limit int) (Page[Member], error) {
	page := Page[Member]{Items: []Member{}}
	if !ValidID(organizationID, OrganizationKind) || limit < 1 || limit > 100 || after != "" && !ValidID(after, MemberKind) {
		return page, ErrInvalid
	}
	if _, err := store.Organization(ctx, organizationID); err != nil {
		return page, err
	}
	rows, err := store.pool.Query(ctx, "SELECT "+memberColumns+" FROM members WHERE organization_id=$1 AND id>$2 ORDER BY id LIMIT $3", organizationID, after, limit+1)
	if err != nil {
		return page, err
	}
	defer rows.Close()
	for rows.Next() {
		item, err := readMember(rows)
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

type OrganizationChange struct {
	Name   *string `json:"name"`
	Status *string `json:"status"`
}

func (store *Store) UpdateOrganization(ctx context.Context, id string, change OrganizationChange) (Organization, error) {
	if !ValidID(id, OrganizationKind) || change.Name == nil && change.Status == nil || change.Name != nil && !validText(*change.Name, 128) || change.Status != nil && *change.Status != "enabled" && *change.Status != "disabled" {
		return Organization{}, ErrInvalid
	}
	return readOrganization(store.pool.QueryRow(ctx, "UPDATE organizations SET name=COALESCE($2,name),status=COALESCE($3,status),lifecycle_revision=lifecycle_revision+CASE WHEN $3 IS NOT NULL AND status<>$3 THEN 1 ELSE 0 END,updated_at=clock_timestamp() WHERE id=$1 RETURNING "+organizationColumns, id, change.Name, change.Status))
}

type MemberChange struct {
	DisplayName   *string `json:"displayName"`
	ManualBlocked *bool   `json:"manualBlocked"`
}

func (store *Store) UpdateMember(ctx context.Context, organizationID, memberID string, change MemberChange) (Member, error) {
	if !ValidID(organizationID, OrganizationKind) || !ValidID(memberID, MemberKind) || change.DisplayName == nil && change.ManualBlocked == nil || change.DisplayName != nil && !validText(*change.DisplayName, 128) {
		return Member{}, ErrInvalid
	}
	return readMember(store.pool.QueryRow(ctx, "UPDATE members SET display_name=COALESCE($3,display_name),manual_block=COALESCE($4,manual_block),eligibility_revision=eligibility_revision+CASE WHEN $4 IS NOT NULL AND manual_block<>$4 THEN 1 ELSE 0 END,updated_at=clock_timestamp() WHERE id=$1 AND organization_id=$2 RETURNING "+memberColumns, memberID, organizationID, change.DisplayName, change.ManualBlocked))
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

type Eligibility struct {
	Eligible  bool   `json:"eligible"`
	BindingID string `json:"bindingId,omitempty"`
}

// Eligibility is a current binding check, not authentication or business authorization.
func (store *Store) Eligibility(ctx context.Context, organizationID, memberID, factorID, factorType string) (Eligibility, error) {
	if !ValidID(organizationID, OrganizationKind) || !ValidID(memberID, MemberKind) || !ValidID(factorID, FactorKind) || !validFactorType(factorType) {
		return Eligibility{}, ErrInvalid
	}
	var result Eligibility
	err := store.pool.QueryRow(ctx, `SELECT b.id::text FROM member_auth_factor_bindings b
        JOIN members m ON m.id=b.member_id AND m.organization_id=b.organization_id
        JOIN organizations o ON o.id=m.organization_id
        JOIN authentication_factors f ON f.id=b.authentication_factor_id
        WHERE b.organization_id=$1 AND b.member_id=$2 AND b.authentication_factor_id=$3 AND f.type=$4
        AND b.status='active' AND f.status='active' AND o.status='enabled'
        AND (f.type<>'dingtalk' OR EXISTS(SELECT 1 FROM dingtalk_applications da WHERE da.organization_id=o.id AND da.namespace=f.namespace))
        AND NOT EXISTS(SELECT 1 FROM dingtalk_applications revoked WHERE revoked.organization_id=o.id AND revoked.authorization_status='revoked')
        AND NOT m.manual_block AND NOT m.external_departure`, organizationID, memberID, factorID, factorType).Scan(&result.BindingID)
	if errors.Is(err, pgx.ErrNoRows) {
		return result, nil
	}
	result.Eligible = err == nil
	return result, err
}
