package identity

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/euyuil/memberid/internal/dingtalk"
	"github.com/jackc/pgx/v5"
)

var ErrSynchronizationIncomplete = errors.New("DingTalk directory synchronization incomplete")

type DingTalkReconciliation struct {
	Application DingTalkApplication `json:"application"`
	Checked     int                 `json:"checked"`
	Present     int                 `json:"present"`
	Departed    int                 `json:"departed"`
	Unavailable int                 `json:"unavailable"`
	Conflicts   int                 `json:"conflicts"`
}

// Reconcile refreshes existing admitted identities; it never discovers or provisions Members.
// Unknown directory failures preserve stored evidence and are reported as incomplete work.
func (directory *DingTalkDirectory) Reconcile(ctx context.Context, organizationID string) (DingTalkReconciliation, error) {
	var result DingTalkReconciliation
	app, err := directory.applications.SynchronizeAuthorization(ctx, organizationID)
	if err != nil {
		return result, err
	}
	result.Application = app
	if app.AuthorizationStatus == "revoked" {
		return result, nil
	}
	credentials, err := directory.applications.Load(ctx, organizationID)
	if err != nil {
		return result, err
	}
	if credentials.Revision != app.Revision || credentials.AuthorizationRevision != app.AuthorizationRevision {
		return result, ErrConflict
	}
	after := ""
	for {
		rows, err := directory.applications.store.pool.Query(ctx, `SELECT i.member_id FROM dingtalk_identities i
 JOIN member_auth_factor_bindings b ON b.member_id=i.member_id AND b.factor_type='dingtalk' AND b.status='active'
 WHERE i.organization_id=$1 AND i.member_id>$2 ORDER BY i.member_id LIMIT 100`, organizationID, after)
		if err != nil {
			return result, err
		}
		ids, err := pgx.CollectRows(rows, pgx.RowTo[string])
		if err != nil {
			return result, err
		}
		if len(ids) == 0 {
			break
		}
		for _, id := range ids {
			result.Checked++
			departed, err := directory.reconcileMember(ctx, credentials, id)
			switch {
			case ctx.Err() != nil:
				return result, ctx.Err()
			case errors.Is(err, dingtalk.ErrAuthorizationDenied):
				current, inspectErr := directory.applications.Inspect(ctx, organizationID)
				if inspectErr != nil {
					return result, inspectErr
				}
				result.Application = current
				if current.AuthorizationStatus != "revoked" {
					return result, ErrConflict
				}
				return result, nil
			case errors.Is(err, ErrProviderUnavailable):
				result.Unavailable++
			case errors.Is(err, ErrConflict) || errors.Is(err, ErrIneligible):
				result.Conflicts++
			case err != nil:
				return result, err
			case departed:
				result.Departed++
			default:
				result.Present++
			}
			after = id
		}
	}
	if result.Unavailable > 0 || result.Conflicts > 0 {
		return result, ErrSynchronizationIncomplete
	}
	return result, nil
}

func (directory *DingTalkDirectory) reconcileMember(ctx context.Context, app DingTalkCredentials, memberID string) (bool, error) {
	snapshot, err := readDirectorySnapshot(ctx, directory.applications.store.pool, app.OrganizationID, memberID)
	if err != nil {
		return false, err
	}
	if snapshot.applicationRevision != app.Revision || snapshot.authorizationRevision != app.AuthorizationRevision || snapshot.namespace != app.Namespace || snapshot.factorNamespace != app.Namespace || snapshot.bindingID == "" || snapshot.factorStatus != "active" || snapshot.unionID == "" || snapshot.employeeID == "" {
		return false, ErrConflict
	}
	check, cancel := context.WithTimeout(ctx, 15*time.Second)
	member, err := directory.provider.VerifyMember(check, app.CorpID, app.ClientID, app.Secret, snapshot.unionID)
	cancel()
	if errors.Is(err, dingtalk.ErrAuthorizationDenied) {
		if _, recordErr := directory.applications.recordAuthorization(ctx, app.DingTalkApplication, snapshot.organizationRevision, "revoked"); recordErr != nil {
			return false, recordErr
		}
		return false, dingtalk.ErrAuthorizationDenied
	}
	departed := errors.Is(err, dingtalk.ErrNotMember)
	if errors.Is(err, dingtalk.ErrIdentityConflict) {
		return false, ErrConflict
	}
	if err != nil && !departed {
		return false, ErrProviderUnavailable
	}
	if !departed && (member.UnionID != snapshot.unionID || member.UserID != snapshot.employeeID) {
		return false, ErrConflict
	}
	observedAt := directory.now()
	err = pgx.BeginFunc(ctx, directory.applications.store.pool, func(tx pgx.Tx) error {
		// Keep the admission lock order. Provider I/O has already completed.
		for _, lock := range []struct{ query, id string }{
			{"SELECT id FROM organizations WHERE id=$1 FOR UPDATE", app.OrganizationID},
			{"SELECT organization_id FROM dingtalk_applications WHERE organization_id=$1 FOR UPDATE", app.OrganizationID},
			{"SELECT member_id FROM dingtalk_identities WHERE member_id=$1 FOR UPDATE", memberID},
			{"SELECT id FROM authentication_factors WHERE id=$1 FOR UPDATE", snapshot.factorID},
			{"SELECT id::text FROM member_auth_factor_bindings WHERE id=$1 FOR UPDATE", snapshot.bindingID},
			{"SELECT id FROM members WHERE id=$1 FOR UPDATE", memberID},
		} {
			var id string
			if err := tx.QueryRow(ctx, lock.query, lock.id).Scan(&id); err != nil {
				return storageError(err)
			}
		}
		current, err := readDirectorySnapshot(ctx, tx, app.OrganizationID, memberID)
		if err != nil {
			return err
		}
		if current != snapshot || !observedAt.Add(time.Minute).After(directory.now()) {
			return ErrConflict
		}
		if _, err := tx.Exec(ctx, `UPDATE members SET external_departure=$2,eligibility_revision=eligibility_revision+1,
 updated_at=CASE WHEN external_departure<>$2 THEN clock_timestamp() ELSE updated_at END WHERE id=$1`, memberID, departed); err != nil {
			return err
		}
		if departed {
			return nil
		}
		var departments []byte
		if member.DepartmentIDs != nil {
			departments, err = json.Marshal(member.DepartmentIDs)
			if err != nil {
				return err
			}
		}
		_, err = tx.Exec(ctx, "UPDATE dingtalk_identities SET department_ids=COALESCE($2::jsonb,department_ids),verified_at=$3 WHERE member_id=$1", memberID, departments, observedAt)
		return err
	})
	return departed, err
}
