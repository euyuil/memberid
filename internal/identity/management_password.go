package identity

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
)

var ErrPasswordUsernameTaken = fmt.Errorf("%w: password username already in use", ErrConflict)

const memberLoginBinding = ` FROM member_auth_factor_bindings b
	JOIN authentication_factors f ON f.id=b.authentication_factor_id
	LEFT JOIN password_credentials c ON c.authentication_factor_id=f.id
	WHERE b.organization_id=$1 AND b.member_id=$2 AND b.factor_type='password' AND f.namespace=$1`

const memberPasswordBinding = memberLoginBinding + " AND c.authentication_factor_id IS NOT NULL"

type GeneratedMemberPassword struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

// GenerateMemberPassword issues a credential under the current console actor.
// First issuance uses the Member's assigned name or creates its binding.
// Reset resolves and rotates the existing credential.
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

// ChangeMemberLoginName assigns a local username independently of password issuance.
func (service *ManagementService) ChangeMemberLoginName(ctx context.Context, principal Principal, organizationID, memberID, expected, username string) error {
	if principal.kind != memberPrincipal {
		return ErrForbidden
	}
	expected, username = CanonicalLoginName(expected), CanonicalLoginName(username)
	if !ValidID(organizationID, OrganizationKind) || !ValidID(memberID, MemberKind) || !passwordUsername.MatchString(username) || expected != "" && !passwordUsername.MatchString(expected) {
		return ErrInvalid
	}
	action := actionCreate
	if expected != "" {
		action = actionUpdate
	}
	return pgx.BeginFunc(ctx, service.store.pool, func(tx pgx.Tx) error {
		if err := managementLock(ctx, tx); err != nil {
			return err
		}
		if err := authorizeAll(ctx, tx, principal, memberLoginNameResource.require(action, organizationID, memberID)); err != nil {
			return err
		}
		if memberID == service.store.rootMemberID || organizationID == service.store.systemOrganizationID && username == RootUsername {
			return ErrForbidden
		}
		if expected == "" {
			return assignMemberLoginName(ctx, tx, principal, organizationID, memberID, username)
		}
		var factorID, current string
		err := tx.QueryRow(ctx, "SELECT f.id,f.subject"+memberLoginBinding, organizationID, memberID).Scan(&factorID, &current)
		if err != nil {
			return storageError(err)
		}
		if current != expected {
			return ErrConflict
		}
		if current == username {
			return nil
		}
		// Password verification takes a shared lock on the verifier before checking its current name.
		if _, err := tx.Exec(ctx, "SELECT 1 FROM password_credentials WHERE authentication_factor_id=$1 FOR UPDATE", factorID); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, "UPDATE authentication_factors SET subject=$2,updated_at=clock_timestamp() WHERE id=$1", factorID, username); err != nil {
			return loginNameError(err)
		}
		return managementEvent(ctx, tx, principal, organizationID, memberID, "password.username.update", struct{}{}, nil)
	})
}

// Call under managementLock after checking the actor and validating the canonical username.
func assignMemberLoginName(ctx context.Context, tx pgx.Tx, principal Principal, organizationID, memberID, username string) error {
	if _, err := readMember(tx.QueryRow(ctx, "SELECT "+memberColumns+" FROM members WHERE id=$1 AND organization_id=$2", memberID, organizationID)); err != nil {
		return err
	}
	var assigned bool
	if err := tx.QueryRow(ctx, "SELECT EXISTS(SELECT 1"+memberLoginBinding+")", organizationID, memberID).Scan(&assigned); err != nil {
		return err
	}
	if assigned {
		return ErrConflict
	}
	if _, err := insertLoginBinding(ctx, tx, organizationID, memberID, username); err != nil {
		return err
	}
	return managementEvent(ctx, tx, principal, organizationID, memberID, "member.username.create", struct{}{}, nil)
}

func loginNameError(err error) error {
	if errors.Is(storageError(err), ErrConflict) {
		return ErrPasswordUsernameTaken
	}
	return storageError(err)
}
