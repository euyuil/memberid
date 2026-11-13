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

// MemberUpdateReceipt is the immutable result of one accepted update. Its Member
// snapshot is historical evidence, not a current eligibility observation.
type MemberUpdateReceipt struct {
	ID             string    `json:"id"`
	OrganizationID string    `json:"organizationId"`
	MemberID       string    `json:"memberId"`
	Member         Member    `json:"member"`
	CreatedAt      time.Time `json:"createdAt"`
}

func (store *Store) MemberUpdate(ctx context.Context, organizationID, memberID, updateID string) (MemberUpdateReceipt, error) {
	var receipt MemberUpdateReceipt
	if !ValidID(organizationID, OrganizationKind) || !ValidID(memberID, MemberKind) || !ValidUUID(updateID) {
		return receipt, ErrInvalid
	}
	var response []byte
	err := store.pool.QueryRow(ctx, "SELECT response FROM member_updates WHERE id=$1 AND organization_id=$2 AND member_id=$3", updateID, organizationID, memberID).Scan(&response)
	if err != nil {
		return receipt, storageError(err)
	}
	err = json.Unmarshal(response, &receipt)
	return receipt, err
}

// UpdateMemberOnce atomically records the result alongside the update. An exact
// retry returns the saved result without applying the change again, even after
// later updates or provider departure events.
func (store *Store) UpdateMemberOnce(ctx context.Context, organizationID, memberID, updateID string, change MemberChange) (MemberUpdateReceipt, bool, error) {
	var receipt MemberUpdateReceipt
	if !ValidID(organizationID, OrganizationKind) || !ValidID(memberID, MemberKind) || !ValidUUID(updateID) || !validMemberChange(change) {
		return receipt, false, ErrInvalid
	}
	updateID = strings.ToLower(updateID)
	input := struct {
		OrganizationID string       `json:"organizationId"`
		MemberID       string       `json:"memberId"`
		Change         MemberChange `json:"change"`
	}{organizationID, memberID, change}
	encoded, err := json.Marshal(input)
	if err != nil {
		return receipt, false, err
	}
	fingerprint := sha256.Sum256(encoded)
	created := false
	err = pgx.BeginFunc(ctx, store.pool, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, "SELECT pg_advisory_xact_lock(hashtextextended($1,0))", "memberid:member-update:"+updateID); err != nil {
			return err
		}
		var accepted, response []byte
		err := tx.QueryRow(ctx, "SELECT request_hash,response FROM member_updates WHERE id=$1", updateID).Scan(&accepted, &response)
		if err == nil {
			if !bytes.Equal(accepted, fingerprint[:]) {
				return ErrConflict
			}
			return json.Unmarshal(response, &receipt)
		}
		if !errors.Is(err, pgx.ErrNoRows) {
			return err
		}
		member, err := updateMember(ctx, tx, organizationID, memberID, change)
		if err != nil {
			return err
		}
		receipt = MemberUpdateReceipt{ID: updateID, OrganizationID: organizationID, MemberID: memberID, Member: member, CreatedAt: member.UpdatedAt}
		if err := managementEvent(ctx, tx, ManagementActor{}, organizationID, memberID, "member.update", change); err != nil {
			return err
		}
		response, err = json.Marshal(receipt)
		if err != nil {
			return err
		}
		_, err = tx.Exec(ctx, "INSERT INTO member_updates(id,organization_id,member_id,request_hash,response,created_at) VALUES($1,$2,$3,$4,$5,$6)", updateID, organizationID, memberID, fingerprint[:], response, receipt.CreatedAt)
		created = err == nil
		return storageError(err)
	})
	if err != nil {
		return MemberUpdateReceipt{}, false, err
	}
	return receipt, created, nil
}
