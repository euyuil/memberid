package identity

import (
	"context"

	"github.com/jackc/pgx/v5"
)

// PhoneLinkTarget is an existing Member association proven by the source session.
// Account handlers supply it from a browser-bound request, never from a POST body.
type PhoneLinkTarget struct {
	OrganizationID, MemberID, SourceFactorID, SourceBindingID string
}

// LinkPhone participates in VerifyAndApply's transaction. The caller separately
// locks and validates its fresh session and single-use account request. This
// operation cannot replace an occupied slot, restore revocation, or merge Members.
func LinkPhone(ctx context.Context, tx pgx.Tx, verified Verification, target PhoneLinkTarget) error {
	if !ValidID(target.OrganizationID, OrganizationKind) || !ValidID(target.MemberID, MemberKind) || !ValidID(target.SourceFactorID, FactorKind) || !ValidUUID(target.SourceBindingID) || !ValidID(verified.Factor.ID, FactorKind) || verified.Method != "sms" || verified.Factor.Type != "phone" || verified.Factor.Namespace != "phone:e164" {
		return ErrInvalid
	}
	var id string
	if err := tx.QueryRow(ctx, "SELECT id FROM organizations WHERE id=$1 AND status='enabled' FOR SHARE", target.OrganizationID).Scan(&id); err != nil {
		return ErrIneligible
	}
	// Lock configured authorization so revocation cannot pass the final check.
	rows, err := tx.Query(ctx, "SELECT organization_id FROM dingtalk_applications WHERE organization_id=$1 FOR SHARE", target.OrganizationID)
	if err != nil {
		return err
	}
	for rows.Next() {
		if err := rows.Scan(&id); err != nil {
			rows.Close()
			return err
		}
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}
	if err := tx.QueryRow(ctx, "SELECT id FROM authentication_factors WHERE id=$1 AND status='active' FOR SHARE", target.SourceFactorID).Scan(&id); err != nil {
		return ErrIneligible
	}
	if err := tx.QueryRow(ctx, "SELECT id::text FROM member_auth_factor_bindings WHERE id=$1 AND member_id=$2 AND organization_id=$3 AND authentication_factor_id=$4 AND status='active' FOR SHARE", target.SourceBindingID, target.MemberID, target.OrganizationID, target.SourceFactorID).Scan(&id); err != nil {
		return ErrIneligible
	}
	if err := tx.QueryRow(ctx, "SELECT id FROM members WHERE id=$1 AND organization_id=$2 AND NOT manual_block AND NOT external_departure FOR UPDATE", target.MemberID, target.OrganizationID).Scan(&id); err != nil {
		return ErrIneligible
	}
	binding, err := MemberEvidence(ctx, tx, target.SourceFactorID, target.MemberID, target.OrganizationID)
	if err != nil || binding != target.SourceBindingID {
		return ErrIneligible
	}
	result, err := tx.Exec(ctx, "INSERT INTO member_auth_factor_bindings(member_id,organization_id,authentication_factor_id,factor_type) VALUES($1,$2,$3,'phone') ON CONFLICT DO NOTHING", target.MemberID, target.OrganizationID, verified.Factor.ID)
	if err != nil {
		return storageError(err)
	}
	if result.RowsAffected() != 1 {
		return ErrConflict
	}
	return nil
}
