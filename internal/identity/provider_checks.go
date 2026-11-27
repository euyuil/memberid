package identity

import (
	"context"
	"errors"
	"time"

	"github.com/zhizhun-tech/memberid/internal/dingtalk"
	"github.com/zhizhun-tech/memberid/internal/feishu"
)

type ProviderCredentialCheck struct {
	Status    string    `json:"status"`
	Revision  int64     `json:"revision"`
	CheckedAt time.Time `json:"checkedAt"`
}

// CheckProviderCredentials discards the upstream token and never updates local
// authorization, membership evidence or configuration. It does not prove that
// directory permissions, user visibility or callback registration are correct.
func (service *ManagementService) CheckProviderCredentials(ctx context.Context, principal Principal, organizationID, kind, id string) (ProviderCredentialCheck, error) {
	requirement := providerResource.require("credential.check", organizationID, kind, id)
	if err := service.store.authorizeManagementRead(ctx, principal, requirement); err != nil {
		return ProviderCredentialCheck{}, err
	}
	timeout, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	var revision int64
	var checked error
	switch kind {
	case "feishu":
		if service.feishu == nil {
			return ProviderCredentialCheck{}, ErrProviderUnavailable
		}
		app, err := service.feishu.lookup(ctx, service.store.pool, organizationID, id)
		if err != nil {
			return ProviderCredentialCheck{}, err
		}
		secret, err := service.feishu.secret(app)
		if err != nil {
			return ProviderCredentialCheck{}, err
		}
		revision = app.Revision
		checked = service.feishu.provider.CheckAuthorization(timeout, app.ClientID, secret)
	case "dingtalk":
		if service.dingTalk == nil {
			return ProviderCredentialCheck{}, ErrProviderUnavailable
		}
		app, err := service.dingTalk.loadSource(ctx, organizationID, id)
		if err != nil {
			return ProviderCredentialCheck{}, err
		}
		revision = app.Revision
		checked = service.dingTalk.checker.CheckAuthorization(timeout, app.CorpID, app.ClientID, app.Secret)
	default:
		return ProviderCredentialCheck{}, ErrInvalid
	}
	// Recheck current authority after network I/O, and reject an obsolete result.
	if err := service.store.authorizeManagementRead(ctx, principal, requirement); err != nil {
		return ProviderCredentialCheck{}, err
	}
	providers, err := service.store.Providers(ctx, organizationID)
	if err != nil {
		return ProviderCredentialCheck{}, err
	}
	for _, provider := range providers {
		if provider.Type != kind || provider.ID != id {
			continue
		}
		if provider.Revision != revision {
			return ProviderCredentialCheck{}, ErrConflict
		}
		status := "accepted"
		if errors.Is(checked, feishu.ErrAuthorizationDenied) || errors.Is(checked, dingtalk.ErrAuthorizationDenied) {
			status = "denied"
		} else if checked != nil {
			status = "unavailable"
		}
		return ProviderCredentialCheck{status, revision, time.Now().UTC()}, nil
	}
	return ProviderCredentialCheck{}, ErrNotFound
}
