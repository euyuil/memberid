package identity

import "context"

// ManagementBinding exposes source identity metadata, never provider secrets,
// password verifiers, or a shared phone factor's contact value.
type ManagementBinding struct {
	Binding
	ProviderID       string `json:"providerId,omitempty"`
	ProviderName     string `json:"providerName,omitempty"`
	ClientID         string `json:"clientId,omitempty"`
	TenantID         string `json:"tenantId,omitempty"`
	ExternalSubject  string `json:"externalSubject,omitempty"`
	ExternalMemberID string `json:"externalMemberId,omitempty"`
}

func (store *Store) managementBindings(ctx context.Context, organizationID, memberID string) ([]ManagementBinding, error) {
	rows, err := store.pool.Query(ctx, `SELECT b.id::text,b.member_id,b.organization_id,b.authentication_factor_id,b.factor_type,b.status,b.created_at,b.revoked_at,
 CASE WHEN f.type IN ('feishu','dingtalk') THEN f.namespace ELSE '' END,
 COALESCE(fa.display_name,da.display_name,''),COALESCE(fa.client_id,da.client_id,''),COALESCE(fa.tenant_key,da.corp_id,''),
 CASE WHEN f.type IN ('feishu','dingtalk') THEN f.subject ELSE '' END,COALESCE(di.external_member_id,'')
 FROM member_auth_factor_bindings b JOIN authentication_factors f ON f.id=b.authentication_factor_id
 LEFT JOIN feishu_applications fa ON f.type='feishu' AND fa.namespace=f.namespace AND fa.organization_id=b.organization_id
 LEFT JOIN dingtalk_applications da ON f.type='dingtalk' AND da.namespace=f.namespace AND da.organization_id=b.organization_id
 LEFT JOIN dingtalk_identities di ON f.type='dingtalk' AND di.member_id=b.member_id AND di.organization_id=b.organization_id AND di.namespace=f.namespace AND di.union_id=f.subject
 WHERE b.organization_id=$1 AND b.member_id=$2 ORDER BY b.factor_type,f.namespace,b.id`, organizationID, memberID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := []ManagementBinding{}
	for rows.Next() {
		var item ManagementBinding
		if err := rows.Scan(&item.ID, &item.MemberID, &item.OrganizationID, &item.FactorID, &item.FactorType, &item.Status, &item.CreatedAt, &item.RevokedAt, &item.ProviderID, &item.ProviderName, &item.ClientID, &item.TenantID, &item.ExternalSubject, &item.ExternalMemberID); err != nil {
			return nil, err
		}
		item.CreatedAt = item.CreatedAt.UTC()
		items = append(items, item)
	}
	return items, rows.Err()
}
