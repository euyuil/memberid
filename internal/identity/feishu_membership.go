package identity

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/zhizhun-tech/memberid/internal/feishu"
)

const FeishuMembershipBatchSize = 100
const FeishuMembershipInterval = time.Minute

type feishuMembershipSnapshot struct {
	organizationID, providerID, memberID, bindingID, bindingStatus                string
	factorID, factorStatus, openID, tenantKey, clientID                           string
	organizationRevision, memberRevision, providerRevision, authorizationRevision int64
	enabled                                                                       bool
	authorizationStatus                                                           string
}

func readFeishuMembership(ctx context.Context, db queryer, bindingID string, lock bool) (feishuMembershipSnapshot, error) {
	var value feishuMembershipSnapshot
	query := `SELECT o.id,a.namespace,m.id,b.id::text,b.status,f.id,f.status,f.subject,a.tenant_key,a.client_id,
 o.lifecycle_revision,m.eligibility_revision,a.revision,a.authorization_revision,a.enabled,a.authorization_status
 FROM member_auth_factor_bindings b
 JOIN members m ON m.id=b.member_id AND m.organization_id=b.organization_id
 JOIN organizations o ON o.id=m.organization_id
 JOIN authentication_factors f ON f.id=b.authentication_factor_id AND f.type='feishu'
 JOIN feishu_applications a ON a.organization_id=o.id AND a.namespace=f.namespace
 WHERE b.id=$1 AND b.factor_type='feishu' AND b.provider_namespace=a.namespace AND o.status='enabled'`
	if lock {
		query += " FOR UPDATE OF a,f,b,m"
	}
	err := db.QueryRow(ctx, query, bindingID).Scan(&value.organizationID, &value.providerID, &value.memberID, &value.bindingID, &value.bindingStatus,
		&value.factorID, &value.factorStatus, &value.openID, &value.tenantKey, &value.clientID,
		&value.organizationRevision, &value.memberRevision, &value.providerRevision, &value.authorizationRevision, &value.enabled, &value.authorizationStatus)
	return value, storageError(err)
}

// Each provider retains its own departure evidence, including after source
// disablement or binding revocation. Another source cannot erase that evidence.
const feishuDeparture = `EXISTS(SELECT 1 FROM feishu_memberships fm
 JOIN member_auth_factor_bindings fb ON fb.id=fm.binding_id
 WHERE fb.member_id=m.id AND fb.factor_type='feishu' AND fm.departed)`

const feishuMemberDeparture = `EXISTS(SELECT 1 FROM feishu_memberships fm
 JOIN member_auth_factor_bindings fb ON fb.id=fm.binding_id
 WHERE fb.member_id=members.id AND fb.factor_type='feishu' AND fm.departed)`

func (apps *FeishuApplications) observeMembership(ctx context.Context, snapshot feishuMembershipSnapshot) (feishuMembershipSnapshot, bool, error) {
	if !snapshot.enabled || snapshot.authorizationStatus != "active" || snapshot.factorStatus != "active" || snapshot.organizationID == apps.store.systemOrganizationID {
		return snapshot, false, ErrIneligible
	}
	// Persist retry ordering independently of authoritative membership evidence.
	if _, err := apps.store.pool.Exec(ctx, `INSERT INTO feishu_memberships(binding_id,attempted_at) VALUES($1,clock_timestamp())
 ON CONFLICT(binding_id) DO UPDATE SET attempted_at=EXCLUDED.attempted_at`, snapshot.bindingID); err != nil {
		return snapshot, false, err
	}
	app, err := apps.lookup(ctx, apps.store.pool, snapshot.organizationID, snapshot.providerID)
	if err != nil {
		return snapshot, false, err
	}
	if app.Revision != snapshot.providerRevision || app.authorizationRevision != snapshot.authorizationRevision || app.TenantID != snapshot.tenantKey || app.ClientID != snapshot.clientID {
		return snapshot, false, ErrConflict
	}
	secret, err := apps.secret(app)
	if err != nil {
		return snapshot, false, err
	}

	check, cancel := context.WithTimeout(ctx, 20*time.Second)
	departed, err := apps.provider.Membership(check, app.ClientID, secret, snapshot.openID)
	cancel()
	if errors.Is(err, feishu.ErrAuthorizationDenied) {
		// Confirm a source-level failure with the application credentials; it is
		// never an employee departure and cannot clear stored departure evidence.
		apps.checkAuthorization(ctx, app, secret, snapshot.organizationRevision)
		return snapshot, false, ErrProviderUnavailable
	}
	if err != nil {
		return snapshot, false, err
	}
	observedAt := time.Now().UTC()
	err = pgx.BeginFunc(ctx, apps.store.pool, func(tx pgx.Tx) error {
		var id string
		if err := tx.QueryRow(ctx, "SELECT id FROM organizations WHERE id=$1 FOR UPDATE", snapshot.organizationID).Scan(&id); err != nil {
			return storageError(err)
		}
		current, err := readFeishuMembership(ctx, tx, snapshot.bindingID, true)
		if err != nil {
			return err
		}
		if current != snapshot || !observedAt.Add(time.Minute).After(time.Now()) {
			return ErrConflict
		}
		var previous bool
		if err := tx.QueryRow(ctx, "SELECT departed FROM feishu_memberships WHERE binding_id=$1 FOR UPDATE", snapshot.bindingID).Scan(&previous); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `UPDATE feishu_memberships SET departed=$2,checked_at=$3 WHERE binding_id=$1`, snapshot.bindingID, departed, observedAt); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, "UPDATE members SET eligibility_revision=eligibility_revision+1,updated_at=CASE WHEN $2 THEN clock_timestamp() ELSE updated_at END WHERE id=$1", snapshot.memberID, previous != departed); err != nil {
			return err
		}
		snapshot.memberRevision++
		return nil
	})
	return snapshot, departed, err
}

type FeishuReconciliation struct {
	Checked          int `json:"checked"`
	Present          int `json:"present"`
	Departed         int `json:"departed"`
	Unavailable      int `json:"unavailable"`
	PermissionDenied int `json:"permissionDenied"`
	Unknown          int `json:"unknown"`
	Conflicts        int `json:"conflicts"`
}

var ErrFeishuReconciliationIncomplete = errors.New("Feishu membership reconciliation incomplete")

// ReconcileMemberships visits a bounded, oldest-attempted batch of existing
// bindings. Durable ordering resumes after a restart and prevents a failing
// identity from starving the rest. It performs no directory discovery/provisioning.
func (apps *FeishuApplications) ReconcileMemberships(ctx context.Context) (FeishuReconciliation, error) {
	var result FeishuReconciliation
	rows, err := apps.store.pool.Query(ctx, `SELECT b.id::text
 FROM member_auth_factor_bindings b
 JOIN authentication_factors f ON f.id=b.authentication_factor_id AND f.type='feishu' AND f.status='active'
 JOIN organizations o ON o.id=b.organization_id AND o.status='enabled'
 JOIN feishu_applications a ON a.organization_id=o.id AND a.namespace=f.namespace AND a.enabled AND a.authorization_status='active'
 LEFT JOIN feishu_memberships fm ON fm.binding_id=b.id
 WHERE b.factor_type='feishu'
 ORDER BY fm.attempted_at NULLS FIRST,b.id LIMIT $1`, FeishuMembershipBatchSize)
	if err != nil {
		return result, err
	}
	ids, err := pgx.CollectRows(rows, pgx.RowTo[string])
	if err != nil {
		return result, err
	}
	for _, id := range ids {
		if ctx.Err() != nil {
			return result, ctx.Err()
		}
		result.Checked++
		snapshot, err := readFeishuMembership(ctx, apps.store.pool, id, false)
		departed := false
		if err == nil {
			_, departed, err = apps.observeMembership(ctx, snapshot)
		}
		switch {
		case ctx.Err() != nil:
			return result, ctx.Err()
		case errors.Is(err, feishu.ErrPermissionDenied):
			result.PermissionDenied++
		case errors.Is(err, feishu.ErrMembershipUnknown):
			result.Unknown++
		case errors.Is(err, ErrConflict), errors.Is(err, ErrIneligible), errors.Is(err, ErrNotFound):
			result.Conflicts++
		case err != nil:
			result.Unavailable++
		case departed:
			result.Departed++
		default:
			result.Present++
		}
	}
	if result.Unavailable+result.PermissionDenied+result.Unknown+result.Conflicts > 0 {
		return result, ErrFeishuReconciliationIncomplete
	}
	return result, nil
}

// RunSynchronization checks immediately on startup, then one minute after each
// completed batch. Cancellation interrupts in-flight provider requests.
func (apps *FeishuApplications) RunSynchronization(ctx context.Context, report func(FeishuReconciliation, error)) {
	if apps == nil {
		return
	}
	for {
		applicationErr := apps.CheckApplications(ctx)
		result, membershipErr := apps.ReconcileMemberships(ctx)
		if ctx.Err() != nil {
			return
		}
		if report != nil {
			report(result, errors.Join(applicationErr, membershipErr))
		}
		timer := time.NewTimer(FeishuMembershipInterval)
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-timer.C:
		}
	}
}
