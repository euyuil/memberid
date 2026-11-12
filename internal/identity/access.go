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
	rows, err := store.pool.Query(ctx, "SELECT m.id,m.organization_id,m.display_name,m.manual_block,m.external_departure,m.created_at,m.updated_at"+eligibleBindings+" AND f.id=$1 ORDER BY m.organization_id,m.id", factorID)
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
	err := database.QueryRow(ctx, "SELECT b.id::text"+eligibleBindings+" AND b.authentication_factor_id=$1 AND b.member_id=$2 AND b.organization_id=$3", factorID, memberID, organizationID).Scan(&bindingID)
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
