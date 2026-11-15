package identity

import (
	"context"
	"time"
)

// ManagementService exposes only authorized Member management operations.
// It does not embed Store or expose raw queries, provider credentials or SQL.
type ManagementService struct {
	store                        *Store
	dingTalk                     *DingTalkApplications
	feishu                       *FeishuApplications
	authenticationEventRetention time.Duration
}

// NewManagementService wires the management boundary from installation-owned
// dependencies. Nil provider adapters leave that provider unavailable.
func NewManagementService(store *Store, dingTalk *DingTalkApplications, feishu *FeishuApplications, authenticationEventRetention time.Duration) *ManagementService {
	return &ManagementService{store: store, dingTalk: dingTalk, feishu: feishu, authenticationEventRetention: authenticationEventRetention}
}

func (service *ManagementService) Actor(ctx context.Context, memberID, grantID string) (ManagementActor, error) {
	return managementActor(ctx, service.store.pool, memberID, grantID)
}

func (service *ManagementService) SetAdministrator(ctx context.Context, principal Principal, organizationID, memberID string, enabled bool) error {
	if principal.kind != memberPrincipal {
		return ErrForbidden
	}
	return service.store.setAdministrator(ctx, principal, organizationID, memberID, enabled)
}
