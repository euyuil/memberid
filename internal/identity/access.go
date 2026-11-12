package identity

import (
	"context"

	"github.com/jackc/pgx/v5/pgxpool"
)

// Database coordinates protocol transactions in this service's dedicated database.
func (store *Store) Database() *pgxpool.Pool { return store.pool }

func (store *Store) EligibleMembers(ctx context.Context, factorID string) ([]Member, error) {
	if !ValidID(factorID, FactorKind) {
		return nil, ErrInvalid
	}
	rows, err := store.pool.Query(ctx, `SELECT m.id,m.organization_id,m.display_name,m.manual_block,m.external_departure,m.created_at,m.updated_at
        FROM members m JOIN organizations o ON o.id=m.organization_id
        JOIN member_auth_factor_bindings b ON b.member_id=m.id
        JOIN authentication_factors f ON f.id=b.authentication_factor_id
        WHERE f.id=$1 AND f.status='active' AND b.status='active' AND o.status='enabled'
        AND (f.type<>'dingtalk' OR EXISTS(SELECT 1 FROM dingtalk_applications da WHERE da.organization_id=o.id AND da.namespace=f.namespace))
        AND NOT EXISTS(SELECT 1 FROM dingtalk_applications revoked WHERE revoked.organization_id=o.id AND revoked.authorization_status='revoked')
        AND NOT m.manual_block AND NOT m.external_departure ORDER BY m.organization_id,m.id`, factorID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	members := []Member{}
	for rows.Next() {
		member, err := readMember(rows)
		if err != nil {
			return nil, err
		}
		members = append(members, member)
	}
	return members, rows.Err()
}

// MemberEvidence evaluates the current explicit binding and eligibility in the caller's transaction.
func MemberEvidence(ctx context.Context, database queryer, factorID, memberID, organizationID string) (string, error) {
	if !ValidID(factorID, FactorKind) || !ValidID(memberID, MemberKind) || !ValidID(organizationID, OrganizationKind) {
		return "", ErrInvalid
	}
	var bindingID string
	err := database.QueryRow(ctx, `SELECT b.id::text FROM member_auth_factor_bindings b
        JOIN members m ON m.id=b.member_id AND m.organization_id=b.organization_id
        JOIN organizations o ON o.id=m.organization_id
        JOIN authentication_factors f ON f.id=b.authentication_factor_id
        WHERE b.authentication_factor_id=$1 AND b.member_id=$2 AND b.organization_id=$3
        AND b.status='active' AND f.status='active' AND o.status='enabled'
        AND (f.type<>'dingtalk' OR EXISTS(SELECT 1 FROM dingtalk_applications da WHERE da.organization_id=o.id AND da.namespace=f.namespace))
        AND NOT EXISTS(SELECT 1 FROM dingtalk_applications revoked WHERE revoked.organization_id=o.id AND revoked.authorization_status='revoked')
        AND NOT m.manual_block AND NOT m.external_departure`, factorID, memberID, organizationID).Scan(&bindingID)
	return bindingID, storageError(err)
}

// PhoneFactor finds existing verification evidence; it does not provision or verify it.
func (store *Store) PhoneFactor(ctx context.Context, number string) (Factor, error) {
	phone, err := NormalizePhone(number)
	if err != nil {
		return Factor{}, err
	}
	return readFactor(store.pool.QueryRow(ctx, "SELECT "+factorColumns+" FROM authentication_factors WHERE type='phone' AND namespace='phone:e164' AND subject=$1", phone))
}
