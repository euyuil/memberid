package identity

import (
	"context"
	"time"
)

// MemberGrant describes persisted OIDC grant lifecycle only. It does not expose
// token credentials or shared session/factor IDs, or assert current app access.
type MemberGrant struct {
	ID              string    `json:"id"`
	ClientID        string    `json:"clientId"`
	ClientName      string    `json:"clientName"`
	Scopes          []string  `json:"scopes"`
	AuthenticatedAt time.Time `json:"authenticatedAt"`
	ExpiresAt       time.Time `json:"expiresAt"`
	State           string    `json:"state"`
}

func (service *ManagementService) MemberGrants(ctx context.Context, principal Principal, organizationID, memberID, after string, limit int) (Page[MemberGrant], error) {
	page := Page[MemberGrant]{Items: []MemberGrant{}}
	if limit < 1 || limit > 100 || after != "" && !validText(after, 128) {
		return page, ErrInvalid
	}
	if err := service.store.authorizeManagementRead(ctx, principal, memberResource.require(actionGet, organizationID, memberID), memberGrantsResource.require(actionList, organizationID, memberID)); err != nil {
		return page, err
	}
	// Validate ownership even when there are no grants; the query cannot widen a
	// Member subject into the shared authentication factor's other identities.
	if _, err := service.store.Member(ctx, organizationID, memberID); err != nil {
		return page, err
	}
	rows, err := service.store.pool.Query(ctx, `SELECT g.id,g.client_id,COALESCE(c.display_name,NULLIF(g.data->>'clientName',''),g.client_id),
 COALESCE(g.data->'scopes','[]'::jsonb),(g.data->>'authTime')::timestamptz,
 LEAST(g.expires_at,g.absolute_expires_at,s.absolute_expires_at),
 CASE WHEN g.revoked_at IS NOT NULL OR s.revoked_at IS NOT NULL THEN 'revoked'
 WHEN LEAST(g.expires_at,g.absolute_expires_at,s.absolute_expires_at)<=clock_timestamp() THEN 'expired' ELSE 'active' END
 FROM oidc_grants g JOIN authentication_sessions s ON s.id=g.session_id
 LEFT JOIN oidc_clients c ON c.client_id=g.client_id
 WHERE g.data->>'organizationId'=$1 AND g.data->>'memberId'=$2 AND g.id>$3
 ORDER BY g.id LIMIT $4`, organizationID, memberID, after, limit+1)
	if err != nil {
		return page, err
	}
	defer rows.Close()
	for rows.Next() {
		var item MemberGrant
		if err := rows.Scan(&item.ID, &item.ClientID, &item.ClientName, &item.Scopes, &item.AuthenticatedAt, &item.ExpiresAt, &item.State); err != nil {
			return page, err
		}
		if len(page.Items) == limit {
			page.NextAfter = page.Items[limit-1].ID
			break
		}
		if item.Scopes == nil {
			item.Scopes = []string{}
		}
		item.AuthenticatedAt, item.ExpiresAt = item.AuthenticatedAt.UTC(), item.ExpiresAt.UTC()
		page.Items = append(page.Items, item)
	}
	return page, rows.Err()
}
