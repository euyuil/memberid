package identity

import (
	"context"

	"github.com/jackc/pgx/v5"
)

const RootUsername = "root"

func provisionRoot(ctx context.Context, tx pgx.Tx, savePassword func(string) error) error {
	memberID, err := NewID(MemberKind)
	if err != nil {
		return err
	}
	password, hash, err := randomPassword()
	if err != nil {
		return err
	}
	if _, err = tx.Exec(ctx, "INSERT INTO members(id,organization_id,display_name) VALUES($1,$2,$3)", memberID, SystemOrganizationID, RootUsername); err != nil {
		return err
	}
	if err = insertMemberPassword(ctx, tx, OperatorPrincipal(), SystemOrganizationID, memberID, RootUsername, hash); err != nil {
		return err
	}
	if _, err = tx.Exec(ctx, "INSERT INTO administrators(organization_id,member_id) VALUES($1,$2)", SystemOrganizationID, memberID); err != nil {
		return err
	}
	if err = managementEvent(ctx, tx, OperatorPrincipal(), SystemOrganizationID, memberID, "administrator.update", map[string]bool{"enabled": true}, map[string]any{"enabled": false}); err != nil {
		return err
	}
	return savePassword(password)
}

func (store *Store) ResetRootPassword(ctx context.Context, principal Principal) (string, error) {
	if principal.kind != operatorPrincipal {
		return "", ErrForbidden
	}
	password, hash, err := randomPassword()
	if err != nil {
		return "", err
	}
	err = pgx.BeginFunc(ctx, store.pool, func(tx pgx.Tx) error {
		if err := managementLock(ctx, tx); err != nil {
			return err
		}
		var memberID string
		err := tx.QueryRow(ctx, `SELECT b.member_id FROM member_auth_factor_bindings b
			JOIN authentication_factors f ON f.id=b.authentication_factor_id
			WHERE b.organization_id=$1 AND f.namespace=$1 AND f.type='password' AND f.subject=$2`, SystemOrganizationID, RootUsername).Scan(&memberID)
		if err != nil {
			return storageError(err)
		}
		return rotateMemberPassword(ctx, tx, SystemOrganizationID, memberID, RootUsername, hash)
	})
	if err != nil {
		return "", err
	}
	return password, nil
}
