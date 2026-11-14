package identity

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
)

var (
	ErrForbidden         = errors.New("management access denied")
	ErrLastAdministrator = errors.New("the last available administrator must be retained")
)

// ManagementActor is the console presentation of a currently eligible administrator.
// Its display and role fields are not authority; mutations accept Principal instead.
type ManagementActor struct {
	MemberID       string `json:"memberId"`
	OrganizationID string `json:"organizationId"`
	DisplayName    string `json:"displayName"`
	GrantID        string `json:"-"`
	Platform       bool   `json:"platform"`
}

func (store *Store) ManagementActor(ctx context.Context, memberID, grantID string) (ManagementActor, error) {
	return managementActor(ctx, store.pool, memberID, grantID)
}

func managementActor(ctx context.Context, db queryer, memberID, grantID string) (ManagementActor, error) {
	var actor ManagementActor
	err := db.QueryRow(ctx, `SELECT m.id,m.organization_id,m.display_name`+eligibleBindings+`
 AND m.id=$1 AND EXISTS(SELECT 1 FROM administrators a WHERE a.member_id=m.id)
 AND EXISTS(SELECT 1 FROM oidc_grants g JOIN oidc_sessions s ON s.id=g.session_id
 WHERE g.id=$2 AND g.revoked_at IS NULL AND s.revoked_at IS NULL
 AND g.expires_at>clock_timestamp() AND g.absolute_expires_at>clock_timestamp()
 AND s.expires_at>clock_timestamp() AND s.absolute_expires_at>clock_timestamp()
 AND g.data->>'memberId'=m.id AND g.data->>'factorId'=f.id
 AND g.data->>'bindingId'=b.id::text)`, memberID, grantID).Scan(&actor.MemberID, &actor.OrganizationID, &actor.DisplayName)
	if errors.Is(err, pgx.ErrNoRows) {
		return actor, ErrForbidden
	}
	actor.Platform = actor.OrganizationID == SystemOrganizationID
	actor.GrantID = grantID
	return actor, err
}

func authorizeManagement(ctx context.Context, tx pgx.Tx, principal Principal, organizationID string, platformOnly bool) error {
	if principal.kind == operatorPrincipal {
		return nil
	}
	if principal.kind != memberPrincipal {
		return ErrForbidden
	}
	current, err := managementActor(ctx, tx, principal.memberID, principal.grantID)
	if err != nil {
		return err
	}
	if !current.Platform && (platformOnly || current.OrganizationID != organizationID || organizationID == SystemOrganizationID) {
		return ErrForbidden
	}
	return nil
}

// All manual eligibility and administrator changes share this lock. External
// departure evidence remains authoritative and is never suppressed by this guard.
func managementLock(ctx context.Context, tx pgx.Tx) error {
	_, err := tx.Exec(ctx, "SELECT pg_advisory_xact_lock(782348913)")
	return err
}

func availableAdministrators(ctx context.Context, db queryer, organizationID string) (int, error) {
	var count int
	err := db.QueryRow(ctx, "SELECT count(DISTINCT m.id)"+eligibleBindings+" AND m.organization_id=$1 AND EXISTS(SELECT 1 FROM administrators a WHERE a.member_id=m.id)", organizationID).Scan(&count)
	return count, err
}

func preserveAdministrators(ctx context.Context, tx pgx.Tx, organizationID string, before int) error {
	if before == 0 {
		return nil
	}
	after, err := availableAdministrators(ctx, tx, organizationID)
	if err != nil {
		return err
	}
	if after == 0 {
		return ErrLastAdministrator
	}
	return nil
}

func managementEvent(ctx context.Context, tx pgx.Tx, principal Principal, organizationID, memberID, action string, changes any) error {
	actorID, err := principal.auditID()
	if err != nil {
		return err
	}
	data, err := json.Marshal(changes)
	if err != nil {
		return err
	}
	_, err = tx.Exec(ctx, "INSERT INTO management_events(actor,organization_id,member_id,action,changes) VALUES($1,$2,NULLIF($3,''),$4,$5)", actorID, organizationID, memberID, action, data)
	return err
}

func (store *Store) SetAdministrator(ctx context.Context, principal Principal, organizationID, memberID string, enabled bool) error {
	if !ValidID(organizationID, OrganizationKind) || !ValidID(memberID, MemberKind) {
		return ErrInvalid
	}
	return pgx.BeginFunc(ctx, store.pool, func(tx pgx.Tx) error {
		if err := managementLock(ctx, tx); err != nil {
			return err
		}
		if err := authorizeManagement(ctx, tx, principal, organizationID, organizationID == SystemOrganizationID); err != nil {
			return err
		}
		if _, err := readMember(tx.QueryRow(ctx, "SELECT "+memberColumns+" FROM members WHERE id=$1 AND organization_id=$2", memberID, organizationID)); err != nil {
			return err
		}
		before, err := availableAdministrators(ctx, tx, organizationID)
		if err != nil {
			return err
		}
		if enabled {
			var eligible bool
			if err = tx.QueryRow(ctx, "SELECT EXISTS(SELECT 1"+eligibleBindings+" AND m.id=$1 AND m.organization_id=$2)", memberID, organizationID).Scan(&eligible); err != nil {
				return err
			}
			if !eligible {
				return ErrIneligible
			}
			_, err = tx.Exec(ctx, "INSERT INTO administrators(organization_id,member_id) VALUES($1,$2) ON CONFLICT DO NOTHING", organizationID, memberID)
		} else {
			_, err = tx.Exec(ctx, "DELETE FROM administrators WHERE member_id=$1 AND organization_id=$2", memberID, organizationID)
		}
		if err != nil {
			return err
		}
		if err = preserveAdministrators(ctx, tx, organizationID, before); err != nil {
			return err
		}
		return managementEvent(ctx, tx, principal, organizationID, memberID, "administrator.update", map[string]bool{"enabled": enabled})
	})
}

func (store *Store) AdministratorIDs(ctx context.Context, organizationID string) ([]string, error) {
	rows, err := store.pool.Query(ctx, "SELECT member_id FROM administrators WHERE organization_id=$1 ORDER BY member_id", organizationID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	ids := []string{}
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		ids = append(ids, id)
	}
	return ids, rows.Err()
}

type ManagementEvent struct {
	ID             int64           `json:"id"`
	Actor          string          `json:"actor"`
	OrganizationID string          `json:"organizationId"`
	MemberID       string          `json:"memberId"`
	Action         string          `json:"action"`
	Changes        json.RawMessage `json:"changes"`
	CreatedAt      time.Time       `json:"createdAt"`
}

func (store *Store) ManagementEvents(ctx context.Context, organizationID, memberID string, before int64) ([]ManagementEvent, error) {
	rows, err := store.pool.Query(ctx, `SELECT id,actor,organization_id,COALESCE(member_id,''),action,changes,created_at FROM management_events
 WHERE ($1='' OR organization_id=$1) AND ($2='' OR member_id=$2) AND ($3::bigint=0 OR id<$3) ORDER BY id DESC LIMIT 50`, organizationID, memberID, before)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := []ManagementEvent{}
	for rows.Next() {
		var v ManagementEvent
		if err := rows.Scan(&v.ID, &v.Actor, &v.OrganizationID, &v.MemberID, &v.Action, &v.Changes, &v.CreatedAt); err != nil {
			return nil, err
		}
		items = append(items, v)
	}
	return items, rows.Err()
}

// Manage performs a bounded console mutation with authorization and audit in
// the same transaction. Only this fixed action set is available to browsers.
func (store *Store) Manage(ctx context.Context, principal Principal, action, organizationID, memberID string, change ManagementChange) (any, error) {
	if principal.kind != memberPrincipal {
		return nil, ErrForbidden
	}
	var result any
	err := pgx.BeginFunc(ctx, store.pool, func(tx pgx.Tx) error {
		if err := managementLock(ctx, tx); err != nil {
			return err
		}
		if action == "organization.update" {
			requirements, err := organizationUpdateRequirements(organizationID, OrganizationChange{Name: change.Name, Status: change.Status})
			if err != nil {
				return err
			}
			if err := authorizeAll(ctx, tx, principal, requirements...); err != nil {
				return err
			}
		} else if err := authorizeManagement(ctx, tx, principal, organizationID, action == "organization.create" || change.Status != nil); err != nil {
			return err
		}
		var err error
		switch action {
		case "organization.create":
			if change.Name == nil || !validText(*change.Name, 128) {
				return ErrInvalid
			}
			organizationID, err = NewID(OrganizationKind)
			if err != nil {
				return err
			}
			result, err = readOrganization(tx.QueryRow(ctx, "INSERT INTO organizations(id,name) VALUES($1,$2) RETURNING "+organizationColumns, organizationID, *change.Name))
		case "organization.update":
			result, err = updateOrganization(ctx, tx, organizationID, OrganizationChange{Name: change.Name, Status: change.Status})
		case "member.create":
			if !ValidID(organizationID, OrganizationKind) || change.DisplayName == nil || !validText(*change.DisplayName, 128) {
				return ErrInvalid
			}
			memberID, err = NewID(MemberKind)
			if err != nil {
				return err
			}
			result, err = readMember(tx.QueryRow(ctx, "INSERT INTO members(id,organization_id,display_name) VALUES($1,$2,$3) RETURNING "+memberColumns, memberID, organizationID, *change.DisplayName))
		case "member.update":
			result, err = updateMember(ctx, tx, organizationID, memberID, MemberChange{DisplayName: change.DisplayName, ManualBlocked: change.ManualBlocked})
		default:
			return ErrInvalid
		}
		if err != nil {
			return storageError(err)
		}
		return managementEvent(ctx, tx, principal, organizationID, memberID, action, change)
	})
	return result, err
}

type ManagementChange struct {
	Name          *string `json:"name,omitempty"`
	Status        *string `json:"status,omitempty"`
	DisplayName   *string `json:"displayName,omitempty"`
	ManualBlocked *bool   `json:"manualBlocked,omitempty"`
}
