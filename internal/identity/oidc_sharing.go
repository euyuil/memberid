package identity

import (
	"context"

	"github.com/jackc/pgx/v5"
)

// Sharing writes take the same client row lock that fences code and refresh issuance.
func (service *ManagementService) changeOIDCSharing(ctx context.Context, principal Principal, organizationID, clientID, action string, enabled bool, change func(pgx.Tx, OIDCClientRegistration) (bool, error)) error {
	if !ValidID(organizationID, OrganizationKind) || !validOIDCClientID(clientID) {
		return ErrInvalid
	}
	return pgx.BeginFunc(ctx, service.store.pool, func(tx pgx.Tx) error {
		if err := managementLock(ctx, tx); err != nil {
			return err
		}
		if err := authorizeAll(ctx, tx, principal, organizationOIDCClientResource.require(action, organizationID, clientID)); err != nil {
			return err
		}
		app, err := scanOIDCClient(tx.QueryRow(ctx, "SELECT "+oidcClientColumns+" FROM oidc_clients WHERE client_id=$1 FOR UPDATE", clientID))
		if err != nil {
			return err
		}
		changed, err := change(tx, app)
		if err != nil || !changed {
			return err
		}
		return managementEvent(ctx, tx, principal, organizationID, "", "oidc.application."+action, map[string]any{
			"clientId": clientID, "displayName": app.DisplayName, "ownerOrganizationId": app.OwnerOrganizationID, "enabled": enabled,
		}, map[string]any{"enabled": !enabled})
	})
}

func (service *ManagementService) SetOIDCPublication(ctx context.Context, principal Principal, ownerID, clientID string, enabled bool) error {
	return service.changeOIDCSharing(ctx, principal, ownerID, clientID, "publication.update", enabled, func(tx pgx.Tx, app OIDCClientRegistration) (bool, error) {
		if app.OwnerOrganizationID != ownerID {
			return false, ErrNotFound
		}
		if app.System || app.Client.SubjectKind != "member" || app.Client.OrganizationID != ownerID {
			return false, ErrForbidden
		}
		if enabled == app.Published {
			return false, nil
		}
		if enabled && !app.Enabled {
			return false, ErrConflict
		}
		if _, err := tx.Exec(ctx, "UPDATE oidc_clients SET published=$2,revision=revision+1 WHERE client_id=$1", clientID, enabled); err != nil {
			return false, err
		}
		if !enabled {
			if _, err := tx.Exec(ctx, "DELETE FROM oidc_application_enablements WHERE client_id=$1", clientID); err != nil {
				return false, err
			}
			if _, err := tx.Exec(ctx, "UPDATE oidc_grants SET revoked_at=now() WHERE client_id=$1 AND data->>'organizationId' <> $2 AND revoked_at IS NULL", clientID, ownerID); err != nil {
				return false, err
			}
		}
		return true, nil
	})
}

func (service *ManagementService) SetOIDCEnablement(ctx context.Context, principal Principal, organizationID, clientID string, enabled bool) error {
	return service.changeOIDCSharing(ctx, principal, organizationID, clientID, "enablement.update", enabled, func(tx pgx.Tx, app OIDCClientRegistration) (bool, error) {
		if organizationID == app.OwnerOrganizationID || !app.Published {
			return false, ErrNotFound
		}
		if enabled {
			if !app.Enabled {
				return false, ErrConflict
			}
			tag, err := tx.Exec(ctx, "INSERT INTO oidc_application_enablements(client_id,organization_id) VALUES($1,$2) ON CONFLICT DO NOTHING", clientID, organizationID)
			return tag.RowsAffected() == 1, storageError(err)
		}
		tag, err := tx.Exec(ctx, "DELETE FROM oidc_application_enablements WHERE client_id=$1 AND organization_id=$2", clientID, organizationID)
		if err != nil || tag.RowsAffected() == 0 {
			return false, err
		}
		_, err = tx.Exec(ctx, "UPDATE oidc_grants SET revoked_at=now() WHERE client_id=$1 AND data->>'organizationId'=$2 AND revoked_at IS NULL", clientID, organizationID)
		return true, err
	})
}
