package identity

import (
	"context"

	"github.com/jackc/pgx/v5"
)

type GeneratedMemberPassword struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

// GenerateMemberPassword issues a credential under the current console actor.
// A username creates a new binding. Reset resolves the existing username from
// the target Member and rotates its credential without changing eligibility.
func (service *ManagementService) GenerateMemberPassword(ctx context.Context, principal Principal, organizationID, memberID string, username *string) (GeneratedMemberPassword, error) {
	if principal.kind != memberPrincipal {
		return GeneratedMemberPassword{}, ErrForbidden
	}
	if !ValidID(organizationID, OrganizationKind) || !ValidID(memberID, MemberKind) ||
		username != nil && !validNewPasswordUsername(organizationID, *username) {
		return GeneratedMemberPassword{}, ErrInvalid
	}
	action := actionUpdate
	if username != nil {
		action = actionCreate
	}
	var result GeneratedMemberPassword
	err := pgx.BeginFunc(ctx, service.store.pool, func(tx pgx.Tx) error {
		if err := managementLock(ctx, tx); err != nil {
			return err
		}
		if err := authorizeAll(ctx, tx, principal, memberPasswordResource.require(action, organizationID, memberID)); err != nil {
			return err
		}
		var factorID string
		if username != nil {
			result.Username = *username
			if _, err := readMember(tx.QueryRow(ctx, "SELECT "+memberColumns+" FROM members WHERE organization_id=$1 AND id=$2", organizationID, memberID)); err != nil {
				return err
			}
		} else {
			err := tx.QueryRow(ctx, `SELECT f.id,f.subject FROM member_auth_factor_bindings b
				JOIN authentication_factors f ON f.id=b.authentication_factor_id
				JOIN password_credentials c ON c.authentication_factor_id=f.id
				WHERE b.organization_id=$1 AND b.member_id=$2 AND b.factor_type='password' AND f.namespace=$1`,
				organizationID, memberID).Scan(&factorID, &result.Username)
			if err != nil {
				return storageError(err)
			}
		}
		password, hash, err := randomPassword()
		if err != nil {
			return err
		}
		result.Password = password
		if username != nil {
			return insertMemberPassword(ctx, tx, principal, organizationID, memberID, result.Username, hash)
		}
		return rotatePassword(ctx, tx, principal, organizationID, memberID, factorID, result.Username, hash)
	})
	if err != nil {
		return GeneratedMemberPassword{}, err
	}
	return result, nil
}
