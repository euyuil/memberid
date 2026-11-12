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

var ErrMemberIDConflict = errors.New("candidate Member identifier is already in use")

type OrganizationEnrollment struct {
	OrganizationID string `json:"organizationId"`
	Name           string `json:"name"`
	MemberID       string `json:"memberId"`
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
func (store *Store) EnrollOrganization(ctx context.Context, input OrganizationEnrollment) (EnrollmentReceipt, error) {
	var receipt EnrollmentReceipt
	if !ValidID(input.OrganizationID, OrganizationKind) || !ValidID(input.MemberID, MemberKind) || !ValidID(input.FactorID, FactorKind) || !ValidUUID(input.BindingID) || !validText(input.Name, 128) {
		return receipt, ErrInvalid
	}
	input.BindingID = strings.ToLower(input.BindingID)
	encoded, err := json.Marshal(input)
	if err != nil {
		return receipt, err
	}
	fingerprint := sha256.Sum256(encoded)
	err = pgx.BeginFunc(ctx, store.pool, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, "SELECT pg_advisory_xact_lock(hashtextextended($1,0))", "memberid:enrollment:"+input.OrganizationID); err != nil {
			return err
		}
		var accepted []byte
		err := tx.QueryRow(ctx, "SELECT request_hash FROM organization_enrollments WHERE organization_id=$1", input.OrganizationID).Scan(&accepted)
		if err == nil {
			if !bytes.Equal(accepted, fingerprint[:]) {
				return ErrConflict
			}
			receipt, err = readEnrollment(tx.QueryRow(ctx, "SELECT "+enrollmentColumns+" FROM organization_enrollments WHERE organization_id=$1", input.OrganizationID))
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
		var created time.Time
		err = tx.QueryRow(ctx, "INSERT INTO organizations(id,name) VALUES($1,$2) ON CONFLICT(id) DO NOTHING RETURNING created_at", input.OrganizationID, input.Name).Scan(&created)
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrConflict
		}
		if err != nil {
			return storageError(err)
		}
		inserted, err := tx.Exec(ctx, "INSERT INTO members(id,organization_id,display_name) VALUES($1,$2,'Member') ON CONFLICT(id) DO NOTHING", input.MemberID, input.OrganizationID)
		if err != nil {
			return storageError(err)
		}
		if inserted.RowsAffected() != 1 {
			return ErrMemberIDConflict
		}
		if _, err := tx.Exec(ctx, "INSERT INTO member_auth_factor_bindings(id,member_id,organization_id,authentication_factor_id,factor_type) VALUES($1,$2,$3,$4,'phone')", input.BindingID, input.MemberID, input.OrganizationID, input.FactorID); err != nil {
			return storageError(err)
		}
		receipt, err = readEnrollment(tx.QueryRow(ctx, "INSERT INTO organization_enrollments(organization_id,member_id,binding_id,authentication_factor_id,request_hash,created_at) VALUES($1,$2,$3,$4,$5,$6) RETURNING "+enrollmentColumns, input.OrganizationID, input.MemberID, input.BindingID, input.FactorID, fingerprint[:], created))
		return err
	})
	return receipt, err
}
