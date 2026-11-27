package identity

import (
	"context"
	"errors"

	"github.com/jackc/pgx/v5"
)

var ErrPasswordUsernameTaken = errors.New("password username already in use")

const memberPasswordBinding = ` FROM member_auth_factor_bindings b
	JOIN authentication_factors f ON f.id=b.authentication_factor_id
	JOIN password_credentials c ON c.authentication_factor_id=f.id
	WHERE b.organization_id=$1 AND b.member_id=$2 AND b.factor_type='password' AND f.namespace=$1`

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
	if username != nil {
		canonical := CanonicalLoginName(*username)
		username = &canonical
	}
	if !ValidID(organizationID, OrganizationKind) || !ValidID(memberID, MemberKind) ||
		username != nil && !passwordUsername.MatchString(*username) {
		return GeneratedMemberPassword{}, ErrInvalid
	}
	if username != nil && organizationID == service.store.systemOrganizationID && *username == RootUsername {
		return GeneratedMemberPassword{}, ErrForbidden
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
			err := tx.QueryRow(ctx, "SELECT f.id,f.subject"+memberPasswordBinding,
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

// RenameMemberPassword updates the login name while keeping the credential,
// binding, and Member identity. expectedUsername protects stale forms.
func (service *ManagementService) RenameMemberPassword(ctx context.Context, principal Principal, organizationID, memberID, expectedUsername, username string) error {
	if principal.kind != memberPrincipal {
		return ErrForbidden
	}
	expectedUsername = CanonicalLoginName(expectedUsername)
	username = CanonicalLoginName(username)
	if !ValidID(organizationID, OrganizationKind) || !ValidID(memberID, MemberKind) ||
		!passwordUsername.MatchString(expectedUsername) || !passwordUsername.MatchString(username) {
		return ErrInvalid
	}
	return pgx.BeginFunc(ctx, service.store.pool, func(tx pgx.Tx) error {
		if err := managementLock(ctx, tx); err != nil {
			return err
		}
		if err := authorizeAll(ctx, tx, principal, memberPasswordResource.require(actionUpdate, organizationID, memberID)); err != nil {
			return err
		}
		var factorID, currentUsername string
		// Serialize the name change with final password verification.
		err := tx.QueryRow(ctx, "SELECT f.id,f.subject"+memberPasswordBinding+" FOR UPDATE OF c", organizationID, memberID).
			Scan(&factorID, &currentUsername)
		if err != nil {
			return storageError(err)
		}
		if currentUsername == username {
			return nil
		}
		if organizationID == service.store.systemOrganizationID && (memberID == service.store.rootMemberID || username == RootUsername) {
			return ErrForbidden
		}
		if currentUsername != expectedUsername {
			return ErrConflict
		}
		if _, err := tx.Exec(ctx, "UPDATE authentication_factors SET subject=$2,updated_at=clock_timestamp() WHERE id=$1", factorID, username); err != nil {
			if errors.Is(storageError(err), ErrConflict) {
				return ErrPasswordUsernameTaken
			}
			return storageError(err)
		}
		return managementEvent(ctx, tx, principal, organizationID, memberID, "password.username.update", struct{}{}, nil)
	})
}
