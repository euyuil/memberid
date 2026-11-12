package identity

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"slices"
	"time"

	"github.com/euyuil/memberid/internal/dingtalk"
	"github.com/jackc/pgx/v5"
)

// acceptDirectoryEvent runs only for a configured outbound provider stream. It
// commits both the replay receipt and a departure before the stream acknowledges.
func (directory *DingTalkDirectory) acceptDirectoryEvent(ctx context.Context, stream DingTalkApplication, event dingtalk.DirectoryEvent) error {
	if !validText(event.ID, 512) || event.CorpID != stream.CorpID || event.BornTime <= 0 || event.BornTime > directory.now().Add(5*time.Minute).UnixMilli() || len(event.UserIDs) == 0 || len(event.UserIDs) > 1000 {
		return ErrInvalid
	}
	switch event.Type {
	case "user_add_org", "user_modify_org", "user_leave_org":
	default:
		return ErrInvalid
	}
	ids := slices.Clone(event.UserIDs)
	for _, id := range ids {
		if !validText(id, 512) {
			return ErrInvalid
		}
	}
	slices.Sort(ids)
	event.UserIDs = slices.Compact(ids)
	canonical, _ := json.Marshal(event)
	digest := sha256.Sum256(canonical)
	return pgx.BeginFunc(ctx, directory.applications.store.pool, func(tx pgx.Tx) error {
		organization, err := readOrganization(tx.QueryRow(ctx, "SELECT "+organizationColumns+" FROM organizations WHERE id=$1 FOR UPDATE", stream.OrganizationID))
		if err != nil {
			return err
		}
		if organization.Status != "enabled" || organization.lifecycleRevision != stream.organizationRevision {
			return ErrConflict
		}
		app, _, err := readApplication(tx.QueryRow(ctx, "SELECT "+applicationColumns+" FROM dingtalk_applications WHERE organization_id=$1 FOR UPDATE", stream.OrganizationID))
		if err != nil {
			return err
		}
		// Routine authorization observations do not replace an active connection.
		if app.AuthorizationStatus != "active" || app.Revision != stream.Revision || app.Namespace != stream.Namespace || app.CorpID != stream.CorpID || app.ClientID != stream.ClientID {
			return ErrConflict
		}
		inserted, err := tx.Exec(ctx, `INSERT INTO dingtalk_events(organization_id,event_id,event_hash) VALUES($1,$2,$3) ON CONFLICT DO NOTHING`, app.OrganizationID, event.ID, digest[:])
		if err != nil {
			return err
		}
		if inserted.RowsAffected() == 0 {
			var previous []byte
			if err := tx.QueryRow(ctx, "SELECT event_hash FROM dingtalk_events WHERE organization_id=$1 AND event_id=$2", app.OrganizationID, event.ID).Scan(&previous); err != nil {
				return err
			}
			if !bytes.Equal(previous, digest[:]) {
				return ErrConflict
			}
			return nil
		}
		// Also fence first-time admissions: their subject is not known until provider I/O completes.
		if _, err := tx.Exec(ctx, "UPDATE dingtalk_applications SET directory_revision=directory_revision+1 WHERE organization_id=$1", app.OrganizationID); err != nil {
			return err
		}
		departed := event.Type == "user_leave_org"
		// Provider time orders provider events only. Equal-time departure wins;
		// a later positive event still needs an independent fresh directory check.
		rows, err := tx.Query(ctx, `UPDATE dingtalk_identities i SET last_event_time=$3,last_event_departure=$4
   FROM member_auth_factor_bindings b,authentication_factors f
   WHERE i.organization_id=$1 AND i.external_member_id=ANY($2) AND b.member_id=i.member_id
   AND b.factor_type='dingtalk' AND b.status='active' AND f.id=b.authentication_factor_id
   AND f.namespace=$5 AND f.subject=i.union_id
   AND (i.last_event_time<$3 OR (i.last_event_time=$3 AND $4 AND NOT i.last_event_departure))
   RETURNING i.member_id`, app.OrganizationID, event.UserIDs, event.BornTime, departed, app.Namespace)
		if err != nil {
			return err
		}
		members, err := pgx.CollectRows(rows, pgx.RowTo[string])
		if err != nil {
			return err
		}
		_, err = tx.Exec(ctx, `UPDATE members SET external_departure=external_departure OR $2,
   eligibility_revision=eligibility_revision+1,updated_at=CASE WHEN $2 AND NOT external_departure THEN clock_timestamp() ELSE updated_at END
   WHERE id=ANY($1)`, members, departed)
		return err
	})
}
