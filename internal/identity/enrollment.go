package identity

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
)

type OrganizationEnrollment struct {
	IdempotencyKey string `json:"idempotencyKey"`
	Name           string `json:"name"`
	BindingID      string `json:"bindingId"`
	FactorID       string `json:"authenticationFactorId"`
}

type EnrollmentReceipt struct {
	OrganizationID string    `json:"organizationId"`
	MemberID       string    `json:"memberId"`
	BindingID      string    `json:"bindingId"`
	FactorID       string    `json:"authenticationFactorId"`
	CreatedAt      time.Time `json:"createdAt"`
}

const enrollmentColumns = "organization_id,member_id,binding_id::text,authentication_factor_id,created_at"

func readEnrollment(row pgx.Row) (EnrollmentReceipt, error) {
	var receipt EnrollmentReceipt
	err := row.Scan(&receipt.OrganizationID, &receipt.MemberID, &receipt.BindingID, &receipt.FactorID, &receipt.CreatedAt)
	receipt.CreatedAt = receipt.CreatedAt.UTC()
	return receipt, storageError(err)
}

func (store *Store) Enrollment(ctx context.Context, organizationID string) (EnrollmentReceipt, error) {
	if !ValidID(organizationID, OrganizationKind) {
		return EnrollmentReceipt{}, ErrInvalid
	}
	return readEnrollment(store.pool.QueryRow(ctx, "SELECT "+enrollmentColumns+" FROM organization_enrollments WHERE organization_id=$1", organizationID))
}

// EnrollOrganization records a privileged, atomic provisioning decision using an already verified phone factor.
// An accepted replay returns its original receipt and never changes current identity or eligibility.
func (store *Store) EnrollOrganization(ctx context.Context, principal Principal, input OrganizationEnrollment) (EnrollmentReceipt, error) {
	if !principal.installation() {
		return EnrollmentReceipt{}, ErrForbidden
	}
	var receipt EnrollmentReceipt
	if !ValidUUID(input.IdempotencyKey) || !ValidID(input.FactorID, FactorKind) || !ValidUUID(input.BindingID) || !validText(input.Name, 128) {
		return receipt, ErrInvalid
	}
	input.IdempotencyKey = strings.ToLower(input.IdempotencyKey)
	input.BindingID = strings.ToLower(input.BindingID)
	encoded, err := json.Marshal(input)
	if err != nil {
		return receipt, err
	}
	fingerprint := sha256.Sum256(encoded)
	err = pgx.BeginFunc(ctx, store.pool, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, "SELECT pg_advisory_xact_lock(hashtextextended($1,0))", "memberid:enrollment:"+input.IdempotencyKey); err != nil {
			return err
		}
		var accepted []byte
		err := tx.QueryRow(ctx, "SELECT request_hash FROM organization_enrollments WHERE idempotency_key=$1", input.IdempotencyKey).Scan(&accepted)
		if err == nil {
			if !bytes.Equal(accepted, fingerprint[:]) {
				return ErrConflict
			}
			receipt, err = readEnrollment(tx.QueryRow(ctx, "SELECT "+enrollmentColumns+" FROM organization_enrollments WHERE idempotency_key=$1", input.IdempotencyKey))
			return err
		}
		if !errors.Is(err, pgx.ErrNoRows) {
			return err
		}
		factor, err := readFactor(tx.QueryRow(ctx, "SELECT "+factorColumns+" FROM authentication_factors WHERE id=$1 FOR SHARE", input.FactorID))
		if err != nil {
			return err
		}
		if factor.Status != "active" || factor.Type != "phone" || factor.Namespace != "phone:e164" {
			return ErrIneligible
		}
		organizationID, err := NewID(OrganizationKind)
		if err != nil {
			return err
		}
		memberID, err := NewID(MemberKind)
		if err != nil {
			return err
		}
		var created time.Time
		if err := tx.QueryRow(ctx, "INSERT INTO organizations(id,name) VALUES($1,$2) RETURNING created_at", organizationID, input.Name).Scan(&created); err != nil {
			return storageError(err)
		}
		if _, err := tx.Exec(ctx, "INSERT INTO members(id,organization_id,display_name) VALUES($1,$2,'Member')", memberID, organizationID); err != nil {
			return storageError(err)
		}
		if _, err := tx.Exec(ctx, "INSERT INTO member_auth_factor_bindings(id,member_id,organization_id,authentication_factor_id,factor_type) VALUES($1,$2,$3,$4,'phone')", input.BindingID, memberID, organizationID, input.FactorID); err != nil {
			return storageError(err)
		}
		receipt, err = readEnrollment(tx.QueryRow(ctx, "INSERT INTO organization_enrollments(organization_id,member_id,binding_id,authentication_factor_id,request_hash,created_at,idempotency_key) VALUES($1,$2,$3,$4,$5,$6,$7) RETURNING "+enrollmentColumns, organizationID, memberID, input.BindingID, input.FactorID, fingerprint[:], created, input.IdempotencyKey))
		return err
	})
	return receipt, err
}
