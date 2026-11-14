package identity

import (
	"context"
	"errors"

	"github.com/euyuil/memberid/internal/dingtalk"
	"github.com/jackc/pgx/v5"
)

// SynchronizeAuthorization checks the stored credentials, never an unaccepted candidate.
// Only a successful fresh token or an explicit authorization denial changes the observation.
func (applications *DingTalkApplications) SynchronizeAuthorization(ctx context.Context, organizationID string) (DingTalkApplication, error) {
	return applications.SynchronizeSource(ctx, organizationID, "")
}

func (applications *DingTalkApplications) SynchronizeSource(ctx context.Context, organizationID, namespace string) (DingTalkApplication, error) {
	organization, err := applications.store.Organization(ctx, organizationID)
	if err != nil {
		return DingTalkApplication{}, err
	}
	if organization.Status != "enabled" {
		return DingTalkApplication{}, ErrIneligible
	}
	app, err := applications.loadSource(ctx, organizationID, namespace)
	if err != nil {
		return DingTalkApplication{}, err
	}
	err = applications.checker.CheckAuthorization(ctx, app.CorpID, app.ClientID, app.Secret)
	status := "active"
	if errors.Is(err, dingtalk.ErrAuthorizationDenied) {
		status = "revoked"
	} else if err != nil {
		return DingTalkApplication{}, ErrProviderUnavailable
	}
	return applications.recordAuthorization(ctx, app.DingTalkApplication, organization.lifecycleRevision, status)
}

// Configuration, organization lifecycle, and observation revisions prevent delayed results from
// overwriting a newer decision. A conflict requires a new provider check, not a blind write retry.
func (applications *DingTalkApplications) recordAuthorization(ctx context.Context, observed DingTalkApplication, lifecycle int64, status string) (DingTalkApplication, error) {
	var result DingTalkApplication
	err := pgx.BeginFunc(ctx, applications.store.pool, func(tx pgx.Tx) error {
		organization, err := readOrganization(tx.QueryRow(ctx, "SELECT "+organizationColumns+" FROM organizations WHERE id=$1 FOR UPDATE", observed.OrganizationID))
		if err != nil {
			return err
		}
		if organization.Status != "enabled" || organization.lifecycleRevision != lifecycle {
			return ErrConflict
		}
		current, _, err := readApplication(tx.QueryRow(ctx, "SELECT "+applicationColumns+" FROM dingtalk_applications WHERE organization_id=$1 AND namespace=$2 FOR UPDATE", observed.OrganizationID, observed.Namespace))
		if err != nil {
			return err
		}
		if current.Revision != observed.Revision || current.AuthorizationRevision != observed.AuthorizationRevision || current.Namespace != observed.Namespace {
			return ErrConflict
		}
		result, _, err = readApplication(tx.QueryRow(ctx, "UPDATE dingtalk_applications SET authorization_status=$3,authorization_revision=authorization_revision+1,authorization_verified_at=clock_timestamp(),updated_at=CASE WHEN authorization_status<>$3 THEN clock_timestamp() ELSE updated_at END WHERE organization_id=$1 AND namespace=$2 RETURNING "+applicationColumns, observed.OrganizationID, observed.Namespace, status))
		return err
	})
	return result, err
}
