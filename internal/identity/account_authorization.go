package identity

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/zhizhun-tech/memberid/internal/authorization"
)

// AccountFreshness is the maximum age of the source authentication for account changes.
const AccountFreshness = 5 * time.Minute

func accountPermissions(organizationID, memberID string) []authorization.Permission {
	return []authorization.Permission{
		permission(memberResource.pattern(organizationID, memberID), actionGet),
		permission(memberLoginNameResource.pattern(organizationID, memberID), actionCreate),
		permission(bindingsResource.pattern(organizationID, memberID), actionCreate),
	}
}

// Account authority comes from the selected Member's current source binding and
// SSO session, independently of administrator assignments. Fresh authentication,
// target verification and single-use workflow checks remain at the account commit.
func accountOrganization(ctx context.Context, db queryer, principal Principal) (string, error) {
	var organizationID string
	err := db.QueryRow(ctx, "SELECT m.organization_id"+eligibleBindings+`
 AND m.id=$1 AND f.id=$2 AND b.id::text=$3
 AND EXISTS(SELECT 1 FROM authentication_sessions s WHERE s.id=$4
 AND s.revoked_at IS NULL AND s.expires_at>clock_timestamp()
 AND s.absolute_expires_at>clock_timestamp()
 AND s.verification->'factor'->>'id'=f.id)`, principal.memberID, principal.factorID, principal.bindingID, principal.sessionID).Scan(&organizationID)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", ErrForbidden
	}
	return organizationID, err
}

// AuthorizeAccountView covers the fixed account-page representation of the
// selected Member. It does not authorize the console's composite Member detail.
func (store *Store) AuthorizeAccountView(ctx context.Context, principal Principal, organizationID string) error {
	if principal.kind != accountPrincipal {
		return ErrForbidden
	}
	return authorizeAll(ctx, store.pool, principal, memberResource.require(actionGet, organizationID, principal.memberID))
}

// AccountLoginName reads the name of the Member selected by the account session.
func (store *Store) AccountLoginName(ctx context.Context, principal Principal, organizationID string) (string, error) {
	if err := store.AuthorizeAccountView(ctx, principal, organizationID); err != nil {
		return "", err
	}
	var username string
	err := store.pool.QueryRow(ctx, "SELECT COALESCE((SELECT f.subject"+memberLoginBinding+"),'')", organizationID, principal.memberID).Scan(&username)
	return username, err
}

// SetFirstAccountLoginName checks live source evidence under the same lock as administrative assignments.
func (store *Store) SetFirstAccountLoginName(ctx context.Context, principal Principal, organizationID, username string) error {
	if principal.kind != accountPrincipal {
		return ErrForbidden
	}
	username = CanonicalLoginName(username)
	if !passwordUsername.MatchString(username) {
		return ErrInvalid
	}
	return pgx.BeginFunc(ctx, store.pool, func(tx pgx.Tx) error {
		if err := managementLock(ctx, tx); err != nil {
			return err
		}
		var authenticatedAt time.Time
		err := tx.QueryRow(ctx, `SELECT (verification->>'authenticatedAt')::timestamptz FROM authentication_sessions
   WHERE id=$1 FOR SHARE`, principal.sessionID).Scan(&authenticatedAt)
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrForbidden
		}
		if err != nil {
			return err
		}
		if now := time.Now(); authenticatedAt.After(now) || !authenticatedAt.Add(AccountFreshness).After(now) {
			return ErrIneligible
		}
		if err := authorizeAll(ctx, tx, principal, memberLoginNameResource.require(actionCreate, organizationID, principal.memberID)); err != nil {
			return err
		}
		if principal.memberID == store.rootMemberID || organizationID == store.systemOrganizationID && username == RootUsername {
			return ErrForbidden
		}
		return assignMemberLoginName(ctx, tx, principal, organizationID, principal.memberID, username)
	})
}
