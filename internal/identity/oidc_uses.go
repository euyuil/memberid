package identity

import (
	"context"

	"github.com/jackc/pgx/v5"
)

// OIDCApplicationUse is the consumer's view of one registration.
type OIDCApplicationUse struct {
	ClientID            string `json:"clientId"`
	DisplayName         string `json:"displayName"`
	OwnerOrganizationID string `json:"ownerOrganizationId"`
	OwnerName           string `json:"ownerName"`
	Enabled             bool   `json:"enabled"`
	Use                 string `json:"use"`
}

func (service *ManagementService) OIDCApplicationUses(ctx context.Context, principal Principal, organizationID, clientID string) ([]OIDCApplicationUse, error) {
	if !ValidID(organizationID, OrganizationKind) || clientID != "" && !validOIDCClientID(clientID) {
		return nil, ErrInvalid
	}
	if err := service.store.authorizeManagementRead(ctx, principal, organizationOIDCClientsResource.require(actionList, organizationID)); err != nil {
		return nil, err
	}
	// Preserve operator-managed unrestricted and single-organization admission in
	// the used directory. Only published apps can acquire an explicit enablement.
	rows, err := service.store.pool.Query(ctx, `WITH uses AS (
		SELECT c.client_id, c.display_name, o.id, o.name, c.enabled,
			CASE WHEN e.client_id IS NOT NULL THEN 'enabled'
				WHEN c.published AND c.owner_organization_id=$1 THEN 'included'
				WHEN NOT c.published AND COALESCE(NULLIF(c.registration->>'organizationId',''),$1)=$1 THEN 'included'
				WHEN c.published AND $2<>'' AND (
					SELECT m.changes->>'enabled' FROM management_events m
					WHERE m.organization_id=$1 AND m.action='oidc.application.enablement.update'
					AND m.changes->>'clientId'=c.client_id ORDER BY m.id DESC LIMIT 1)='false' THEN 'withdrawn'
				WHEN c.published THEN 'available' END AS use
		FROM oidc_clients c JOIN organizations o ON o.id=c.owner_organization_id
		LEFT JOIN oidc_application_enablements e ON e.client_id=c.client_id AND e.organization_id=$1
		WHERE c.registration->>'subjectKind'='member' AND ($2::text='' OR c.client_id=$2)
	) SELECT * FROM uses WHERE use IS NOT NULL AND ($2<>'' OR use<>'available') ORDER BY display_name,client_id`, organizationID, clientID)
	if err != nil {
		return nil, err
	}
	items, err := pgx.CollectRows(rows, pgx.RowToStructByPos[OIDCApplicationUse])
	if err == nil && clientID != "" && len(items) == 0 {
		return nil, ErrNotFound
	}
	return items, err
}
