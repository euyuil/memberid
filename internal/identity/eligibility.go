package identity

import (
	"context"
	"errors"

	"github.com/jackc/pgx/v5"
)

// eligibleBindings selects stored identity facts in the statement's snapshot.
// It neither verifies a new provider authentication nor grants application access.
const eligibleBindings = ` FROM member_auth_factor_bindings b
 JOIN members m ON m.id=b.member_id AND m.organization_id=b.organization_id
 JOIN organizations o ON o.id=m.organization_id
 JOIN authentication_factors f ON f.id=b.authentication_factor_id
 WHERE b.status='active' AND f.status='active' AND o.status='enabled'
 AND NOT m.manual_block AND NOT m.external_departure
 AND (f.type<>'dingtalk' OR EXISTS(SELECT 1 FROM dingtalk_applications da
 WHERE da.organization_id=o.id AND da.namespace=f.namespace AND da.enabled AND da.authorization_status='active'))
 AND (f.type<>'feishu' OR EXISTS(SELECT 1 FROM feishu_applications fa
 WHERE fa.organization_id=o.id AND fa.namespace=f.namespace AND fa.enabled AND fa.authorization_status='active'))`

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
	err := store.pool.QueryRow(ctx, "SELECT b.id::text"+eligibleBindings+" AND b.organization_id=$1 AND b.member_id=$2 AND b.authentication_factor_id=$3 AND f.type=$4", organizationID, memberID, factorID, factorType).Scan(&result.BindingID)
	if errors.Is(err, pgx.ErrNoRows) {
		return result, nil
	}
	result.Eligible = err == nil
	return result, err
}

// EligibleMemberIDs returns the requested Members with at least one eligible
// binding in this organization. It must not replace a token's specific binding check.
func (store *Store) EligibleMemberIDs(ctx context.Context, organizationID string, memberIDs []string) ([]string, error) {
	if !ValidID(organizationID, OrganizationKind) || len(memberIDs) < 1 || len(memberIDs) > 100 {
		return nil, ErrInvalid
	}
	seen := make(map[string]bool, len(memberIDs))
	for _, id := range memberIDs {
		if !ValidID(id, MemberKind) || seen[id] {
			return nil, ErrInvalid
		}
		seen[id] = true
	}
	rows, err := store.pool.Query(ctx, "SELECT DISTINCT b.member_id"+eligibleBindings+" AND b.organization_id=$1 AND b.member_id=ANY($2::text[]) ORDER BY b.member_id", organizationID, memberIDs)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := []string{}
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		result = append(result, id)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return result, nil
}
