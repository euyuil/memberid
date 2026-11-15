package identity

import (
	"context"
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"regexp"
	"time"

	"github.com/jackc/pgx/v5"
)

const passwordIterations = 600000

var (
	passwordUsername      = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,63}$`)
	ErrPasswordCredential = errors.New("invalid organization, username, or password")
)

type passwordHash struct {
	salt, digest []byte
	iterations   int
}

func randomPassword() (string, passwordHash, error) {
	var secret [24]byte
	hash := passwordHash{salt: make([]byte, 16), iterations: passwordIterations}
	if _, err := rand.Read(secret[:]); err != nil {
		return "", passwordHash{}, err
	}
	if _, err := rand.Read(hash.salt); err != nil {
		return "", passwordHash{}, err
	}
	password := base64.RawURLEncoding.EncodeToString(secret[:])
	var err error
	hash.digest, err = pbkdf2.Key(sha256.New, password, hash.salt, hash.iterations, 32)
	return password, hash, err
}

// HasPasswordCredentials controls whether password entry is offered to a Member
// client. It never reveals which usernames exist.
func (store *Store) HasPasswordCredentials(ctx context.Context, organizationID string) (bool, error) {
	var found bool
	err := store.pool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM password_credentials c
		JOIN authentication_factors f ON f.id=c.authentication_factor_id
		WHERE ($1='' OR f.namespace=$1))`, organizationID).Scan(&found)
	return found, err
}

// SetMemberPassword provisions or rotates a locally managed credential. The
// username is an immutable organization-scoped identifier for that credential.
func (store *Store) SetMemberPassword(ctx context.Context, principal Principal, organizationID, memberID, username string) (string, error) {
	if principal.kind != operatorPrincipal {
		return "", ErrForbidden
	}
	if !ValidID(organizationID, OrganizationKind) || !ValidID(memberID, MemberKind) || !passwordUsername.MatchString(username) ||
		organizationID == SystemOrganizationID && username == RootUsername {
		return "", ErrInvalid
	}
	password, hash, err := randomPassword()
	if err != nil {
		return "", err
	}
	err = pgx.BeginFunc(ctx, store.pool, func(tx pgx.Tx) error {
		if err := managementLock(ctx, tx); err != nil {
			return err
		}
		if _, err := readMember(tx.QueryRow(ctx, "SELECT "+memberColumns+" FROM members WHERE id=$1 AND organization_id=$2", memberID, organizationID)); err != nil {
			return err
		}
		var exists bool
		err := tx.QueryRow(ctx, "SELECT EXISTS(SELECT 1 FROM member_auth_factor_bindings WHERE member_id=$1 AND factor_type='password')", memberID).Scan(&exists)
		if err != nil {
			return err
		}
		if !exists {
			return insertMemberPassword(ctx, tx, organizationID, memberID, username, hash)
		}
		return rotateMemberPassword(ctx, tx, organizationID, memberID, username, hash)
	})
	if err != nil {
		return "", err
	}
	return password, nil
}

func insertMemberPassword(ctx context.Context, tx pgx.Tx, organizationID, memberID, username string, hash passwordHash) error {
	factorID, err := NewID(FactorKind)
	if err != nil {
		return err
	}
	if _, err = tx.Exec(ctx, "INSERT INTO authentication_factors(id,type,namespace,subject) VALUES($1,'password',$2,$3)", factorID, organizationID, username); err != nil {
		return storageError(err)
	}
	if _, err = tx.Exec(ctx, "INSERT INTO password_credentials(authentication_factor_id,salt,digest,iterations) VALUES($1,$2,$3,$4)", factorID, hash.salt, hash.digest, hash.iterations); err != nil {
		return err
	}
	if _, err = tx.Exec(ctx, "INSERT INTO member_auth_factor_bindings(organization_id,member_id,authentication_factor_id,factor_type) VALUES($1,$2,$3,'password')", organizationID, memberID, factorID); err != nil {
		return storageError(err)
	}
	return managementEvent(ctx, tx, OperatorPrincipal(), organizationID, memberID, "password.create", struct{}{}, nil)
}

func rotateMemberPassword(ctx context.Context, tx pgx.Tx, organizationID, memberID, username string, hash passwordHash) error {
	var factorID string
	err := tx.QueryRow(ctx, `SELECT f.id`+eligibleBindings+` AND m.id=$1 AND m.organization_id=$2
		AND f.type='password' AND f.subject=$3`, memberID, organizationID, username).Scan(&factorID)
	if err != nil {
		return storageError(err)
	}
	if _, err = tx.Exec(ctx, "UPDATE password_credentials SET salt=$2,digest=$3,iterations=$4 WHERE authentication_factor_id=$1", factorID, hash.salt, hash.digest, hash.iterations); err != nil {
		return err
	}
	if _, err = tx.Exec(ctx, "UPDATE authentication_sessions SET revoked_at=clock_timestamp() WHERE revoked_at IS NULL AND verification->'factor'->>'id'=$1", factorID); err != nil {
		return err
	}
	if _, err = tx.Exec(ctx, "UPDATE oidc_grants SET revoked_at=clock_timestamp() WHERE revoked_at IS NULL AND data->>'memberId'=$1", memberID); err != nil {
		return err
	}
	attemptKey := passwordAttemptKey(organizationID, username)
	if _, err = tx.Exec(ctx, "DELETE FROM password_attempt_windows WHERE account_hash=$1", attemptKey[:]); err != nil {
		return err
	}
	return managementEvent(ctx, tx, OperatorPrincipal(), organizationID, memberID, "password.reset", struct{}{}, nil)
}

func passwordAttemptKey(organizationID, username string) [32]byte {
	return sha256.Sum256([]byte(organizationID + "\x00" + username))
}

// VerifyPasswordAndApply commits the caller's session changes only while the
// verified credential is still current. Password reset uses an exclusive lock
// on that same credential and revokes sessions issued with the previous secret.
func (store *Store) VerifyPasswordAndApply(ctx context.Context, organizationID, username, password string, apply func(pgx.Tx, MemberAdmission) error) error {
	if !ValidID(organizationID, OrganizationKind) || !passwordUsername.MatchString(username) || len(password) == 0 || len(password) > 1024 {
		return ErrPasswordCredential
	}
	key := passwordAttemptKey(organizationID, username)
	result, err := store.pool.Exec(ctx, `INSERT INTO password_attempt_windows(account_hash,attempts,expires_at)
		VALUES($1,1,clock_timestamp()+interval '5 minutes')
		ON CONFLICT (account_hash) DO UPDATE SET
		attempts=CASE WHEN password_attempt_windows.expires_at <= clock_timestamp() THEN 1 ELSE password_attempt_windows.attempts+1 END,
		expires_at=CASE WHEN password_attempt_windows.expires_at <= clock_timestamp() THEN EXCLUDED.expires_at ELSE password_attempt_windows.expires_at END
		WHERE password_attempt_windows.expires_at <= clock_timestamp() OR password_attempt_windows.attempts<10`, key[:])
	if err != nil {
		return err
	}
	if result.RowsAffected() != 1 {
		return ErrRateLimited
	}
	hash := passwordHash{salt: make([]byte, 16), digest: make([]byte, 32), iterations: passwordIterations}
	var factorID string
	err = store.pool.QueryRow(ctx, `SELECT f.id,c.salt,c.digest,c.iterations FROM password_credentials c
		JOIN authentication_factors f ON f.id=c.authentication_factor_id
		WHERE f.type='password' AND f.namespace=$1 AND f.subject=$2`, organizationID, username).Scan(&factorID, &hash.salt, &hash.digest, &hash.iterations)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return err
	}
	actual, err := pbkdf2.Key(sha256.New, password, hash.salt, hash.iterations, 32)
	if err != nil {
		return err
	}
	if subtle.ConstantTimeCompare(actual, hash.digest) != 1 || factorID == "" {
		return ErrPasswordCredential
	}
	return pgx.BeginFunc(ctx, store.pool, func(tx pgx.Tx) error {
		var current []byte
		if err := tx.QueryRow(ctx, "SELECT salt FROM password_credentials WHERE authentication_factor_id=$1 FOR SHARE", factorID).Scan(&current); err != nil {
			return err
		}
		if subtle.ConstantTimeCompare(current, hash.salt) != 1 {
			return ErrPasswordCredential
		}
		var admission MemberAdmission
		admission.OrganizationID = organizationID
		err := tx.QueryRow(ctx, "SELECT m.id,b.id::text"+eligibleBindings+" AND o.id=$1 AND f.id=$2", organizationID, factorID).Scan(&admission.MemberID, &admission.BindingID)
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrPasswordCredential
		}
		if err != nil {
			return err
		}
		factor, err := readFactor(tx.QueryRow(ctx, "SELECT "+factorColumns+" FROM authentication_factors WHERE id=$1", factorID))
		if err != nil {
			return err
		}
		admission.Verification = Verification{Factor: factor, Method: "pwd", AuthenticatedAt: time.Now().UTC().Truncate(time.Second)}
		return apply(tx, admission)
	})
}
