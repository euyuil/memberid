package identity

import (
	"context"
	"encoding/json"
	"time"

	"github.com/jackc/pgx/v5"
)

// ManagementEventSnapshot preserves readable names at the time of the write.
// It is display data, never an authority source or a live identity lookup.
type ManagementEventSnapshot struct {
	ActorName        string `json:"actorName"`
	OrganizationName string `json:"organizationName"`
	TargetName       string `json:"targetName"`
}

func managementEvent(ctx context.Context, tx pgx.Tx, principal Principal, organizationID, memberID, action string, changes any, previous map[string]any) error {
	actorID, err := principal.auditID()
	if err != nil {
		return err
	}
	data, err := json.Marshal(changes)
	if err != nil {
		return err
	}
	var snapshot ManagementEventSnapshot
	if err := tx.QueryRow(ctx, `SELECT o.name,CASE WHEN $4='provider.configure' THEN $5::jsonb->>'displayName'
 WHEN $4 LIKE 'saml.serviceProvider.%' THEN COALESCE(NULLIF($5::jsonb->>'displayName',''),$5::jsonb->>'id')
 WHEN $4 LIKE 'oidc.application.%' THEN $5::jsonb->>'displayName'
 ELSE COALESCE(m.display_name,o.name) END,COALESCE(a.display_name,'')
 FROM organizations o
 LEFT JOIN members m ON m.id=$2 AND m.organization_id=o.id
 LEFT JOIN members a ON a.id=$3
 WHERE o.id=$1`, organizationID, memberID, actorID, action, data).Scan(&snapshot.OrganizationName, &snapshot.TargetName, &snapshot.ActorName); err != nil {
		return err
	}
	contextData, err := json.Marshal(snapshot)
	if err != nil {
		return err
	}
	if previous == nil {
		previous = map[string]any{}
	}
	previousData, err := json.Marshal(previous)
	if err != nil {
		return err
	}
	_, err = tx.Exec(ctx, "INSERT INTO management_events(actor,organization_id,member_id,action,changes,snapshot,previous) VALUES($1,$2,NULLIF($3,''),$4,$5,$6,$7)", actorID, organizationID, memberID, action, data, contextData, previousData)
	return err
}

type ManagementEvent struct {
	ID             int64                   `json:"id"`
	Actor          string                  `json:"actor"`
	OrganizationID string                  `json:"organizationId"`
	MemberID       string                  `json:"memberId"`
	Action         string                  `json:"action"`
	Changes        json.RawMessage         `json:"changes"`
	Snapshot       ManagementEventSnapshot `json:"snapshot"`
	Previous       json.RawMessage         `json:"previous"`
	CreatedAt      time.Time               `json:"createdAt"`
}

func (store *Store) ManagementEvents(ctx context.Context, organizationID, memberID string, before int64) ([]ManagementEvent, error) {
	rows, err := store.pool.Query(ctx, `SELECT id,actor,organization_id,COALESCE(member_id,''),action,changes,snapshot,previous,created_at FROM management_events
 WHERE ($1='' OR organization_id=$1) AND ($2='' OR member_id=$2) AND ($3::bigint=0 OR id<$3) ORDER BY id DESC LIMIT 50`, organizationID, memberID, before)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := []ManagementEvent{}
	for rows.Next() {
		var v ManagementEvent
		if err := rows.Scan(&v.ID, &v.Actor, &v.OrganizationID, &v.MemberID, &v.Action, &v.Changes, &v.Snapshot, &v.Previous, &v.CreatedAt); err != nil {
			return nil, err
		}
		items = append(items, v)
	}
	return items, rows.Err()
}

// Capture previous editable values under the same locks as the mutation. Do not
// include credentials, binding proofs, or other unneeded identity attributes.
func managementPrevious(ctx context.Context, tx pgx.Tx, organizationID, memberID, action string) (map[string]any, error) {
	if action != "organization.update" && action != "member.update" {
		return nil, nil
	}
	if err := managementLock(ctx, tx); err != nil {
		return nil, err
	}
	if action == "organization.update" {
		var name, status string
		err := tx.QueryRow(ctx, "SELECT name,status FROM organizations WHERE id=$1 FOR UPDATE", organizationID).Scan(&name, &status)
		return map[string]any{"name": name, "status": status}, storageError(err)
	}
	var name string
	var blocked bool
	err := tx.QueryRow(ctx, "SELECT display_name,manual_block FROM members WHERE id=$1 AND organization_id=$2 FOR UPDATE", memberID, organizationID).Scan(&name, &blocked)
	return map[string]any{"displayName": name, "manualBlocked": blocked}, storageError(err)
}
