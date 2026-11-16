package identity

import "context"

// SAMLServiceProviderInput is a full replacement of the editable registration.
// Ownership comes from the route; retirement has a separate explicit operation.
type SAMLServiceProviderInput struct {
	ID                    string   `json:"id"`
	DisplayName           string   `json:"displayName"`
	EntityID              string   `json:"entityId"`
	ACSURL                string   `json:"acsUrl"`
	NameIDFormat          string   `json:"nameIdFormat"`
	Enabled               bool     `json:"enabled"`
	AllowUnsignedRequests bool     `json:"allowUnsignedRequests"`
	SigningCertificates   []string `json:"signingCertificates"`
	Preauthorized         bool     `json:"preauthorized"`
	Attributes            []string `json:"attributes"`
	Revision              int64    `json:"revision"`
}

func (input SAMLServiceProviderInput) Registration(organizationID string) SAMLServiceProvider {
	return SAMLServiceProvider{
		ID: input.ID, DisplayName: input.DisplayName, EntityID: input.EntityID,
		OrganizationID: organizationID, ACSURL: input.ACSURL, Enabled: input.Enabled, NameIDFormat: input.NameIDFormat,
		AllowUnsignedRequests: input.AllowUnsignedRequests, SigningCertificates: input.SigningCertificates,
		Preauthorized: input.Preauthorized, Attributes: input.Attributes, Revision: input.Revision,
	}
}

// Organization reads constrain ownership in SQL, including when a caller knows
// an identifier from another organization. Installation interfaces authenticate separately.
func (store *Store) OrganizationSAMLServiceProvider(ctx context.Context, organizationID, id string) (SAMLServiceProvider, error) {
	if !ValidID(organizationID, OrganizationKind) || !validSAMLServiceProviderID(id) {
		return SAMLServiceProvider{}, ErrInvalid
	}
	return readSAMLProvider(store.pool.QueryRow(ctx, "SELECT data,revision,retired_at IS NOT NULL FROM saml_service_providers WHERE organization_id=$1 AND id=$2", organizationID, id))
}

func (store *Store) OrganizationSAMLServiceProviders(ctx context.Context, organizationID, after string, limit int) (Page[SAMLServiceProvider], error) {
	page := Page[SAMLServiceProvider]{Items: []SAMLServiceProvider{}}
	if !ValidID(organizationID, OrganizationKind) || after != "" && !validSAMLServiceProviderID(after) || limit < 1 || limit > 100 {
		return page, ErrInvalid
	}
	if _, err := store.Organization(ctx, organizationID); err != nil {
		return page, err
	}
	rows, err := store.pool.Query(ctx, "SELECT data,revision,retired_at IS NOT NULL FROM saml_service_providers WHERE organization_id=$1 AND id>$2 ORDER BY id LIMIT $3", organizationID, after, limit+1)
	if err != nil {
		return page, err
	}
	defer rows.Close()
	for rows.Next() {
		item, err := readSAMLProvider(rows)
		if err != nil {
			return page, err
		}
		if len(page.Items) == limit {
			page.NextAfter = page.Items[limit-1].ID
			break
		}
		page.Items = append(page.Items, item)
	}
	return page, rows.Err()
}

func (service *ManagementService) SAMLServiceProviders(ctx context.Context, principal Principal, organizationID, after string, limit int) (Page[SAMLServiceProvider], error) {
	if err := service.store.authorizeManagementRead(ctx, principal, samlServiceProvidersResource.require(actionList, organizationID)); err != nil {
		return Page[SAMLServiceProvider]{}, err
	}
	return service.store.OrganizationSAMLServiceProviders(ctx, organizationID, after, limit)
}

func (service *ManagementService) SAMLServiceProvider(ctx context.Context, principal Principal, organizationID, id string) (SAMLServiceProvider, error) {
	if err := service.store.authorizeManagementRead(ctx, principal, samlServiceProviderResource.require(actionGet, organizationID, id)); err != nil {
		return SAMLServiceProvider{}, err
	}
	return service.store.OrganizationSAMLServiceProvider(ctx, organizationID, id)
}

func (service *ManagementService) PutSAMLServiceProvider(ctx context.Context, principal Principal, sp SAMLServiceProvider) (SAMLServiceProvider, error) {
	if principal.kind != memberPrincipal {
		return SAMLServiceProvider{}, ErrForbidden
	}
	if sp.Retired {
		return SAMLServiceProvider{}, ErrInvalid
	}
	// HTTP management accepts HTTPS recipients only. The operator CLI retains
	// the explicitly configured loopback-development exception.
	return service.store.putSAMLServiceProvider(ctx, principal, sp, false)
}

func (service *ManagementService) RetireSAMLServiceProvider(ctx context.Context, principal Principal, organizationID, id string, revision int64) (SAMLServiceProvider, error) {
	if principal.kind != memberPrincipal {
		return SAMLServiceProvider{}, ErrForbidden
	}
	return service.store.mutateSAMLServiceProvider(ctx, principal, organizationID, id, revision, nil)
}

func (store *Store) RetireSAMLServiceProvider(ctx context.Context, principal Principal, organizationID, id string, revision int64) (SAMLServiceProvider, error) {
	if !principal.installation() {
		return SAMLServiceProvider{}, ErrForbidden
	}
	return store.mutateSAMLServiceProvider(ctx, principal, organizationID, id, revision, nil)
}
