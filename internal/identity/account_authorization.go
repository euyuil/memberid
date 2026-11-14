package identity

import (
	"context"
	"errors"

	"github.com/euyuil/memberid/internal/authorization"
	"github.com/jackc/pgx/v5"
)

func accountPermissions(organizationID, memberID string) []authorization.Permission {
	member := "organizations/" + organizationID + "/members/" + memberID
	return []authorization.Permission{permission(member, "get"), permission(member+"/bindings", "create")}
}

// Account authority comes from the selected Member's current source binding and
// SSO session, independently of administrator assignments. Fresh authentication,
// target verification and single-use workflow checks remain at the account commit.
func accountOrganization(ctx context.Context, db queryer, principal Principal) (string, error) {
	var organizationID string
	err := db.QueryRow(ctx, "SELECT m.organization_id"+eligibleBindings+`
 AND m.id=$1 AND f.id=$2 AND b.id::text=$3
 AND EXISTS(SELECT 1 FROM oidc_sessions s WHERE s.id=$4
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
	return authorizeAll(ctx, store.pool, principal, authorization.Requirement{Target: "organizations/" + organizationID + "/members/" + principal.memberID, Action: "get"})
}
