package identity

import (
	"context"

	"github.com/jackc/pgx/v5"
)

const RootUsername = "root"

func provisionRoot(ctx context.Context, tx pgx.Tx, systemID, rootID string, savePassword func(string) error) error {
	password, hash, err := randomPassword()
	if err != nil {
		return err
	}
	if _, err = tx.Exec(ctx, "INSERT INTO members(id,organization_id,display_name) VALUES($1,$2,$3)", rootID, systemID, RootUsername); err != nil {
		return err
	}
	if err = insertMemberPassword(ctx, tx, OperatorPrincipal(), systemID, rootID, RootUsername, hash); err != nil {
		return err
	}
	if _, err = tx.Exec(ctx, "INSERT INTO administrators(organization_id,member_id) VALUES($1,$2)", systemID, rootID); err != nil {
		return err
	}
	if err = managementEvent(ctx, tx, OperatorPrincipal(), systemID, rootID, "administrator.update", map[string]bool{"enabled": true}, map[string]any{"enabled": false}); err != nil {
		return err
	}
	return savePassword(password)
}

func (store *Store) ResetRootPassword(ctx context.Context, principal Principal) (GeneratedMemberPassword, error) {
	if principal.kind != operatorPrincipal {
		return GeneratedMemberPassword{}, ErrForbidden
	}
	password, hash, err := randomPassword()
	if err != nil {
		return GeneratedMemberPassword{}, err
	}
	var username string
	err = pgx.BeginFunc(ctx, store.pool, func(tx pgx.Tx) error {
		if err := managementLock(ctx, tx); err != nil {
			return err
		}
		var factorID string
		err := tx.QueryRow(ctx, `SELECT f.id,f.subject`+eligibleBindings+`
			AND m.organization_id=$1 AND m.id=$2 AND f.type='password' AND f.subject='root'`, store.systemOrganizationID, store.rootMemberID).Scan(&factorID, &username)
		if err != nil {
			return storageError(err)
		}
		return rotatePassword(ctx, tx, principal, store.systemOrganizationID, store.rootMemberID, factorID, username, hash)
	})
	if err != nil {
		return GeneratedMemberPassword{}, err
	}
	return GeneratedMemberPassword{Username: username, Password: password}, nil
}
