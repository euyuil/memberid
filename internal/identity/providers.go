package identity

import (
	"context"
	"math"
	"time"

	"github.com/jackc/pgx/v5"
)

type Provider struct {
	ID                  string    `json:"id"`
	Type                string    `json:"type"`
	DisplayName         string    `json:"displayName"`
	TenantID            string    `json:"tenantId"`
	ClientID            string    `json:"clientId"`
	Enabled             bool      `json:"enabled"`
	AuthorizationStatus string    `json:"authorizationStatus"`
	Revision            int64     `json:"revision"`
	CreatedAt           time.Time `json:"createdAt"`
}

type ProviderInput struct {
	DisplayName      string `json:"displayName"`
	TenantID         string `json:"tenantId"`
	ClientID         string `json:"clientId"`
	ClientSecret     string `json:"clientSecret"`
	Enabled          *bool  `json:"enabled"`
	ExpectedRevision int64  `json:"expectedRevision"`
}

func ConfigureProvider(ctx context.Context, principal Principal, organizationID, kind, id string, input ProviderInput, dingTalk *DingTalkApplications, feishu *FeishuApplications) (Provider, error) {
	if principal.kind != memberPrincipal {
		return Provider{}, ErrForbidden
	}
	var store *Store
	switch kind {
	case "dingtalk":
		store = dingTalk.store
	case "feishu":
		store = feishu.store
	default:
		return Provider{}, ErrInvalid
	}
	current, err := managementActor(ctx, store.pool, principal.memberID, principal.grantID)
	if err != nil {
		return Provider{}, err
	}
	if !current.Platform && current.OrganizationID != organizationID {
		return Provider{}, ErrForbidden
	}
	switch kind {
	case "dingtalk":
		app, err := dingTalk.configure(ctx, principal, organizationID, id, input)
		return app.Provider(), err
	case "feishu":
		return feishu.configure(ctx, principal, organizationID, id, input)
	default:
		return Provider{}, ErrInvalid
	}
}

func validProviderInput(organizationID, namespace string, input ProviderInput, console bool) bool {
	return ValidID(organizationID, OrganizationKind) && (namespace == "" || validText(namespace, 128)) &&
		input.ExpectedRevision >= 0 && input.ExpectedRevision < math.MaxInt64 &&
		(!console || validText(input.DisplayName, 128) && input.Enabled != nil)
}

func (app DingTalkApplication) Provider() Provider {
	return Provider{app.Namespace, "dingtalk", app.DisplayName, app.CorpID, app.ClientID, app.Enabled, app.AuthorizationStatus, app.Revision, app.CreatedAt}
}

func (store *Store) Providers(ctx context.Context, organizationID string) ([]Provider, error) {
	if _, err := store.Organization(ctx, organizationID); err != nil {
		return nil, err
	}
	rows, err := store.pool.Query(ctx, `SELECT namespace,type,display_name,tenant_id,client_id,enabled,authorization_status,revision,created_at
 FROM (
 SELECT namespace,'dingtalk' AS type,display_name,corp_id AS tenant_id,client_id,enabled,authorization_status,revision,created_at
 FROM dingtalk_applications WHERE organization_id=$1
 UNION ALL
 SELECT namespace,'feishu',display_name,tenant_key,client_id,enabled,authorization_status,revision,created_at
 FROM feishu_applications WHERE organization_id=$1
 ) providers ORDER BY type,display_name,namespace`, organizationID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := []Provider{}
	for rows.Next() {
		var item Provider
		if err := rows.Scan(&item.ID, &item.Type, &item.DisplayName, &item.TenantID, &item.ClientID, &item.Enabled, &item.AuthorizationStatus, &item.Revision, &item.CreatedAt); err != nil {
			return nil, err
		}
		items = append(items, item)
	}
	return items, rows.Err()
}

func lockProviderManagement(ctx context.Context, tx pgx.Tx, principal Principal, observed Organization, disabling bool) (int, error) {
	if principal.kind != memberPrincipal && !principal.installation() {
		return 0, ErrForbidden
	}
	if principal.kind == memberPrincipal {
		if err := managementLock(ctx, tx); err != nil {
			return 0, err
		}
		if err := authorizeManagement(ctx, tx, principal, observed.ID, false); err != nil {
			return 0, err
		}
	}
	current, err := readOrganization(tx.QueryRow(ctx, "SELECT "+organizationColumns+" FROM organizations WHERE id=$1 FOR UPDATE", observed.ID))
	if err != nil {
		return 0, err
	}
	if current.Status != "enabled" || current.lifecycleRevision != observed.lifecycleRevision {
		return 0, ErrIneligible
	}
	if disabling {
		return availableAdministrators(ctx, tx, observed.ID)
	}
	return 0, nil
}

func finishProviderManagement(ctx context.Context, tx pgx.Tx, principal Principal, kind, organizationID, namespace, name string, enabled bool, before int) error {
	if principal.kind != memberPrincipal {
		return nil
	}
	if err := preserveAdministrators(ctx, tx, organizationID, before); err != nil {
		return err
	}
	return managementEvent(ctx, tx, principal, organizationID, "", "provider.configure", map[string]any{
		"providerId": namespace, "type": kind, "displayName": name, "enabled": enabled,
	})
}
