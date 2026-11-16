package identity

import (
	"context"
	"errors"
	"net/mail"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
)

var ErrMemberEmailTaken = errors.New("member email already assigned in organization")

// MemberEmail is an administrator assertion, never evidence of mailbox control
// or an authentication/binding identifier. Clearing preserves its revision.
type MemberEmail struct {
	Address         string     `json:"address"`
	Source          string     `json:"source"`
	MailboxVerified bool       `json:"mailboxVerified"`
	Revision        int64      `json:"revision"`
	UpdatedBy       string     `json:"updatedBy"`
	UpdatedAt       *time.Time `json:"updatedAt"`
}

type MemberEmailInput struct {
	Address  string `json:"address"`
	Revision int64  `json:"revision"`
}

// Accept a single ASCII mailbox with an unquoted local part and DNS domain.
// Preserve the local part; the unique index conservatively compares it without
// case. Internationalized domains must be supplied as ASCII A-labels.
func normalizeMemberEmail(value string) (string, error) {
	if value == "" {
		return "", nil
	}
	if len(value) > 254 || strings.ContainsAny(value, "\"()[]\\") {
		return "", ErrInvalid
	}
	for _, c := range value {
		if c <= ' ' || c >= 127 {
			return "", ErrInvalid
		}
	}
	parsed, err := mail.ParseAddress(value)
	if err != nil || parsed.Name != "" || parsed.Address != value {
		return "", ErrInvalid
	}
	local, domain, ok := strings.Cut(value, "@")
	if !ok || len(local) > 64 || !strings.Contains(domain, ".") {
		return "", ErrInvalid
	}
	for _, label := range strings.Split(domain, ".") {
		if len(label) == 0 || len(label) > 63 || strings.HasPrefix(label, "-") || strings.HasSuffix(label, "-") || strings.Trim(label, "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-") != "" {
			return "", ErrInvalid
		}
	}
	return local + "@" + strings.ToLower(domain), nil
}

func readMemberEmail(ctx context.Context, db queryer, organizationID, memberID string) (MemberEmail, error) {
	result := MemberEmail{Source: "administrator"}
	err := db.QueryRow(ctx, `SELECT COALESCE(e.address,''),COALESCE(e.revision,0),COALESCE(e.updated_by,''),e.updated_at
 FROM members m LEFT JOIN member_emails e ON e.member_id=m.id AND e.organization_id=m.organization_id
 WHERE m.organization_id=$1 AND m.id=$2`, organizationID, memberID).
		Scan(&result.Address, &result.Revision, &result.UpdatedBy, &result.UpdatedAt)
	return result, storageError(err)
}

// MemberEmail is an installation-only read; console reads use ManagementService.
func (store *Store) MemberEmail(ctx context.Context, principal Principal, organizationID, memberID string) (MemberEmail, error) {
	if !principal.installation() {
		return MemberEmail{}, ErrForbidden
	}
	return readMemberEmail(ctx, store.pool, organizationID, memberID)
}

func (service *ManagementService) PutMemberEmail(ctx context.Context, principal Principal, organizationID, memberID string, input MemberEmailInput) (MemberEmail, error) {
	if principal.kind != memberPrincipal {
		return MemberEmail{}, ErrForbidden
	}
	return service.store.putMemberEmail(ctx, principal, organizationID, memberID, input)
}

func (store *Store) PutMemberEmail(ctx context.Context, principal Principal, organizationID, memberID string, input MemberEmailInput) (MemberEmail, error) {
	if !principal.installation() {
		return MemberEmail{}, ErrForbidden
	}
	return store.putMemberEmail(ctx, principal, organizationID, memberID, input)
}

func (store *Store) putMemberEmail(ctx context.Context, principal Principal, organizationID, memberID string, input MemberEmailInput) (MemberEmail, error) {
	var result MemberEmail
	address, err := normalizeMemberEmail(input.Address)
	if err != nil || input.Revision < 0 || !ValidID(organizationID, OrganizationKind) || !ValidID(memberID, MemberKind) {
		return result, ErrInvalid
	}
	err = pgx.BeginFunc(ctx, store.pool, func(tx pgx.Tx) error {
		if err := managementLock(ctx, tx); err != nil {
			return err
		}
		if err := authorizeAll(ctx, tx, principal, memberEmailResource.require(actionUpdate, organizationID, memberID)); err != nil {
			return err
		}
		// SAML issuance holds a shared lock on this same Member, including when
		// no email row exists yet. Updates cannot race a signed assertion.
		var id string
		if err := tx.QueryRow(ctx, "SELECT id FROM members WHERE organization_id=$1 AND id=$2 FOR UPDATE", organizationID, memberID).Scan(&id); err != nil {
			return storageError(err)
		}
		previous, err := readMemberEmail(ctx, tx, organizationID, memberID)
		if err != nil {
			return err
		}
		if previous.Revision != input.Revision {
			return ErrConflict
		}
		if previous.Address == address {
			result = previous
			return nil
		}
		actor, err := principal.auditID()
		if err != nil {
			return err
		}
		_, err = tx.Exec(ctx, `INSERT INTO member_emails(member_id,organization_id,address,revision,updated_by)
 VALUES($1,$2,$3,1,$4) ON CONFLICT(member_id) DO UPDATE SET address=EXCLUDED.address,
 revision=member_emails.revision+1,updated_by=EXCLUDED.updated_by,updated_at=clock_timestamp()`, memberID, organizationID, address, actor)
		if err != nil {
			if errors.Is(storageError(err), ErrConflict) {
				return ErrMemberEmailTaken
			}
			return err
		}
		result, err = readMemberEmail(ctx, tx, organizationID, memberID)
		if err != nil {
			return err
		}
		return managementEvent(ctx, tx, principal, organizationID, memberID, "member.email.update", result, map[string]any{"address": previous.Address, "revision": previous.Revision})
	})
	if err != nil {
		return MemberEmail{}, err
	}
	return result, nil
}

// SAMLMemberEmail must follow LockSAMLMemberEvidence in the issuance transaction.
func SAMLMemberEmail(ctx context.Context, tx pgx.Tx, organizationID, memberID string) (string, error) {
	email, err := readMemberEmail(ctx, tx, organizationID, memberID)
	return email.Address, err
}
