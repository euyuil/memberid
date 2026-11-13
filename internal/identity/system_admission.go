package identity

import (
	"context"

	"github.com/jackc/pgx/v5"
)

// PrepareSystemDingTalkAdmission is a trusted installation-operator operation.
// It authorizes one binding after fresh provider verification; it creates neither
// a verified factor nor management authority. Empty unionID cancels a pending target.
func (store *Store) PrepareSystemDingTalkAdmission(ctx context.Context, memberID, unionID string) error {
	if !ValidID(memberID, MemberKind) || unionID != "" && !validText(unionID, 512) {
		return ErrInvalid
	}
	return pgx.BeginFunc(ctx, store.pool, func(tx pgx.Tx) error {
		// Match the login transaction's organization-first lock order.
		var id string
		if err := tx.QueryRow(ctx, "SELECT id FROM organizations WHERE id=$1 FOR UPDATE", SystemOrganizationID).Scan(&id); err != nil {
			return err
		}
		if _, err := readMember(tx.QueryRow(ctx, "SELECT "+memberColumns+" FROM members WHERE id=$1 AND organization_id=$2", memberID, SystemOrganizationID)); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, "DELETE FROM system_dingtalk_admissions WHERE member_id=$1", memberID); err != nil {
			return err
		}
		if unionID != "" {
			var namespace string
			if err := tx.QueryRow(ctx, "SELECT namespace FROM dingtalk_applications WHERE organization_id=$1 AND authorization_status='active'", SystemOrganizationID).Scan(&namespace); err != nil {
				return ErrIneligible
			}
			var bound bool
			if err := tx.QueryRow(ctx, "SELECT EXISTS(SELECT 1 FROM member_auth_factor_bindings WHERE member_id=$1 AND factor_type='dingtalk')", memberID).Scan(&bound); err != nil {
				return err
			}
			if bound {
				return ErrConflict
			}
			if _, err := tx.Exec(ctx, "INSERT INTO system_dingtalk_admissions(member_id,namespace,union_id,expires_at) VALUES($1,$2,$3,clock_timestamp()+interval '24 hours')", memberID, namespace, unionID); err != nil {
				return storageError(err)
			}
		}
		return managementEvent(ctx, tx, ManagementActor{}, SystemOrganizationID, memberID, "dingtalk.admission", map[string]bool{"enabled": unionID != ""})
	})
}
