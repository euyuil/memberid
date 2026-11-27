package identity

import (
	"context"
	"errors"

	"github.com/jackc/pgx/v5"
)

func (sp SAMLServiceProvider) LoginOrganizationID() string {
	if sp.Published {
		return ""
	}
	return sp.OrganizationID
}

// OrganizationActivation identifies the uninterrupted enrollment selected for this login.
func (sp SAMLServiceProvider) OrganizationActivation(ctx context.Context, db queryer, organizationID string) (string, error) {
	if organizationID == sp.OrganizationID {
		return "", nil
	}
	if !sp.Published {
		return "", ErrIneligible
	}
	var activation string
	err := db.QueryRow(ctx, "SELECT activation_id::text FROM saml_application_enablements WHERE service_provider_id=$1 AND organization_id=$2", sp.ID, organizationID).Scan(&activation)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", ErrIneligible
	}
	return activation, err
}

func (sp SAMLServiceProvider) CheckActivation(ctx context.Context, db queryer, organizationID, expected string) error {
	current, err := sp.OrganizationActivation(ctx, db, organizationID)
	if err == nil && current != expected {
		return ErrIneligible
	}
	return err
}

func (service *ManagementService) SetSAMLEnablement(ctx context.Context, principal Principal, organizationID, id string, enabled bool) error {
	return service.store.SetSAMLEnablement(ctx, principal, organizationID, id, enabled)
}

// Both the consumer transition and final assertion issuance lock the registration.
func (store *Store) SetSAMLEnablement(ctx context.Context, principal Principal, organizationID, id string, enabled bool) error {
	if !ValidID(organizationID, OrganizationKind) || !validSAMLServiceProviderID(id) {
		return ErrInvalid
	}
	return pgx.BeginFunc(ctx, store.pool, func(tx pgx.Tx) error {
		if err := managementLock(ctx, tx); err != nil {
			return err
		}
		if err := authorizeAll(ctx, tx, principal, samlServiceProviderResource.require("enablement.update", organizationID, id)); err != nil {
			return err
		}
		sp, err := readSAMLProvider(tx.QueryRow(ctx, "SELECT data,revision,retired_at IS NOT NULL FROM saml_service_providers WHERE id=$1 FOR UPDATE", id))
		if err != nil {
			return err
		}
		if !sp.Published || sp.Retired || sp.OrganizationID == organizationID {
			return ErrNotFound
		}
		query := "DELETE FROM saml_application_enablements WHERE service_provider_id=$1 AND organization_id=$2"
		if enabled {
			if !sp.Enabled {
				return ErrConflict
			}
			query = "INSERT INTO saml_application_enablements(service_provider_id,organization_id) VALUES($1,$2) ON CONFLICT DO NOTHING"
		}
		tag, err := tx.Exec(ctx, query, id, organizationID)
		if err != nil || tag.RowsAffected() == 0 {
			return storageError(err)
		}
		return managementEvent(ctx, tx, principal, organizationID, "", "saml.serviceProvider.enablement.update", map[string]any{
			"id": id, "displayName": sp.DisplayName, "ownerOrganizationId": sp.OrganizationID, "enabled": enabled,
		}, map[string]any{"enabled": !enabled})
	})
}

type SAMLApplicationUse struct {
	ApplicationID       string `json:"applicationId"`
	DisplayName         string `json:"displayName"`
	OwnerOrganizationID string `json:"ownerOrganizationId"`
	OwnerName           string `json:"ownerName"`
	Enabled             bool   `json:"enabled"`
	Use                 string `json:"use"`
}

func (service *ManagementService) SAMLApplicationUses(ctx context.Context, principal Principal, organizationID, id string) ([]SAMLApplicationUse, error) {
	if !ValidID(organizationID, OrganizationKind) || id != "" && !validSAMLServiceProviderID(id) {
		return nil, ErrInvalid
	}
	if err := service.store.authorizeManagementRead(ctx, principal, samlServiceProvidersResource.require(actionList, organizationID)); err != nil {
		return nil, err
	}
	rows, err := service.store.pool.Query(ctx, `SELECT s.id,COALESCE(NULLIF(s.data->>'displayName',''),s.id),o.id,o.name,(s.data->>'enabled')::boolean,
		CASE WHEN s.organization_id=$1 THEN 'included' WHEN e.activation_id IS NOT NULL THEN 'enabled'
		     WHEN (SELECT m.changes->>'enabled' FROM management_events m WHERE m.organization_id=$1 AND m.action='saml.serviceProvider.enablement.update'
		           AND m.changes->>'id'=s.id ORDER BY m.id DESC LIMIT 1)='false' THEN 'withdrawn' ELSE 'available' END
		FROM saml_service_providers s JOIN organizations o ON o.id=s.organization_id
		LEFT JOIN saml_application_enablements e ON e.service_provider_id=s.id AND e.organization_id=$1
		WHERE s.retired_at IS NULL AND ($2::text='' OR s.id=$2) AND
		(s.organization_id=$1 OR (s.data @> '{"published":true}' AND ($2<>'' OR e.activation_id IS NOT NULL))) ORDER BY 2,1`, organizationID, id)
	if err != nil {
		return nil, err
	}
	items, err := pgx.CollectRows(rows, pgx.RowToStructByPos[SAMLApplicationUse])
	if err == nil && id != "" && len(items) == 0 {
		return nil, ErrNotFound
	}
	return items, err
}
