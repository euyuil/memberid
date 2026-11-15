package identity

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"

	"github.com/jackc/pgx/v5"
)

const RootUsername = "root"

var ErrSetupCredential = errors.New("setup code or confirmation is invalid or expired")
var ErrSetupClosed = errors.New("first-time setup is complete")

func setupHash(value string) string {
	digest := sha256.Sum256([]byte(value))
	return hex.EncodeToString(digest[:])
}

func (store *Store) SetupAvailable(ctx context.Context) (bool, error) {
	var available bool
	err := store.pool.QueryRow(ctx, "SELECT NOT closed FROM installation_setup WHERE singleton").Scan(&available)
	return available, err
}

// IssueSetupCode replaces any uncompleted setup attempt. A completed
// installation cannot be reopened with this operator command.
func (store *Store) IssueSetupCode(ctx context.Context, principal Principal) (string, error) {
	if principal.kind != operatorPrincipal {
		return "", ErrForbidden
	}
	var secret [32]byte
	if _, err := rand.Read(secret[:]); err != nil {
		return "", err
	}
	code := base64.RawURLEncoding.EncodeToString(secret[:])
	result, err := store.pool.Exec(ctx, `UPDATE installation_setup SET code_hash=$1,
		expires_at=clock_timestamp()+interval '15 minutes', confirmation_hash=NULL, salt=NULL, digest=NULL
		WHERE singleton AND NOT closed`, setupHash(code))
	if err != nil {
		return "", err
	}
	if result.RowsAffected() != 1 {
		return "", ErrSetupClosed
	}
	return code, nil
}

// PrepareSetupPassword consumes the setup code before returning the plaintext
// once. The pending hash can only be activated by its browser's confirmation.
func (store *Store) PrepareSetupPassword(ctx context.Context, code, confirmation string) (string, error) {
	if len(code) != 43 || len(confirmation) != 43 {
		return "", ErrSetupCredential
	}
	var password string
	err := pgx.BeginFunc(ctx, store.pool, func(tx pgx.Tx) error {
		var allowed bool
		err := tx.QueryRow(ctx, `SELECT true FROM installation_setup WHERE singleton AND NOT closed
			AND code_hash=$1 AND expires_at>clock_timestamp() FOR UPDATE`, setupHash(code)).Scan(&allowed)
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrSetupCredential
		}
		if err != nil {
			return err
		}
		var hash passwordHash
		password, hash, err = randomPassword()
		if err != nil {
			return err
		}
		_, err = tx.Exec(ctx, `UPDATE installation_setup SET code_hash=NULL,confirmation_hash=$1,salt=$2,digest=$3,
			expires_at=clock_timestamp()+interval '15 minutes' WHERE singleton`, setupHash(confirmation), hash.salt, hash.digest)
		return err
	})
	if err != nil {
		return "", err
	}
	return password, nil
}

func (store *Store) CompleteSetup(ctx context.Context, confirmation string) error {
	if len(confirmation) != 43 {
		return ErrSetupCredential
	}
	return pgx.BeginFunc(ctx, store.pool, func(tx pgx.Tx) error {
		if err := managementLock(ctx, tx); err != nil {
			return err
		}
		hash := passwordHash{iterations: passwordIterations}
		err := tx.QueryRow(ctx, `SELECT salt,digest FROM installation_setup WHERE singleton AND NOT closed
			AND confirmation_hash=$1 AND expires_at>clock_timestamp() FOR UPDATE`, setupHash(confirmation)).Scan(&hash.salt, &hash.digest)
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrSetupCredential
		}
		if err != nil {
			return err
		}
		memberID, err := NewID(MemberKind)
		if err != nil {
			return err
		}
		if _, err = tx.Exec(ctx, "INSERT INTO members(id,organization_id,display_name) VALUES($1,$2,$3)", memberID, SystemOrganizationID, RootUsername); err != nil {
			return err
		}
		if err = insertMemberPassword(ctx, tx, SystemOrganizationID, memberID, RootUsername, hash); err != nil {
			return err
		}
		if _, err = tx.Exec(ctx, "INSERT INTO administrators(organization_id,member_id) VALUES($1,$2)", SystemOrganizationID, memberID); err != nil {
			return err
		}
		if err = closeSetup(ctx, tx, &memberID); err != nil {
			return err
		}
		return managementEvent(ctx, tx, OperatorPrincipal(), SystemOrganizationID, memberID, "administrator.update", map[string]bool{"enabled": true}, map[string]any{"enabled": false})
	})
}

func closeSetup(ctx context.Context, tx pgx.Tx, rootMemberID *string) error {
	_, err := tx.Exec(ctx, `UPDATE installation_setup SET closed=true,root_member_id=$1,
		code_hash=NULL,expires_at=NULL,confirmation_hash=NULL,salt=NULL,digest=NULL
		WHERE singleton AND NOT closed`, rootMemberID)
	return err
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
		err := tx.QueryRow(ctx, "SELECT root_member_id FROM installation_setup WHERE singleton AND root_member_id IS NOT NULL").Scan(&memberID)
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
