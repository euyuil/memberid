package oidcprovider

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/zhizhun-tech/memberid/internal/config"
	"github.com/zitadel/oidc/v3/pkg/oidc"
)

const oidcLoginLifetime = 10 * time.Minute
const oidcLoginPrefix = "oidc."

// Request is a snapshot of the validated authorization input. Only navigation
// choices and the identifier of the SSO session shown may change before storage.
type oidcLoginEntry struct {
	Issuer    string               `json:"issuer"`
	ExpiresAt time.Time            `json:"expiresAt"`
	Request   authorizationRequest `json:"request"`
}

func (service *Service) sealLoginEntry(request *authorizationRequest) error {
	entry := request.entry
	entry.Request.ProviderOrganizationID = request.ProviderOrganizationID
	entry.Request.SessionID = request.SessionID
	entry.Request.Fresh = request.Fresh
	data, err := json.Marshal(entry)
	if err != nil {
		return err
	}
	sealed, err := service.protocol.Crypto().Encrypt("oidc-login:" + string(data))
	if err == nil {
		request.entryToken = oidcLoginPrefix + sealed
	}
	return err
}

func (service *Service) readLoginEntry(ctx context.Context, token string) (*authorizationRequest, error) {
	data, err := service.protocol.Crypto().Decrypt(strings.TrimPrefix(token, oidcLoginPrefix))
	payload, ok := strings.CutPrefix(data, "oidc-login:")
	var entry oidcLoginEntry
	if err != nil || !ok || json.Unmarshal([]byte(payload), &entry) != nil ||
		entry.Issuer != service.configuration.Issuer || !entry.ExpiresAt.After(service.now()) {
		return nil, oidc.ErrInvalidRequest()
	}
	request := entry.Request
	browser, _ := ctx.Value(browserKey{}).(string)
	if browser == "" || !sameSecret(request.BrowserHash, config.SecretHash(browser)) {
		return nil, oidc.ErrInvalidRequest()
	}
	// An older link may be reopened after authentication has started. Its
	// snapshot must never replace the current state or select another organization.
	stored, err := service.storage.loginRequestByID(ctx, request.ID)
	if err == nil {
		if stored.ProviderOrganizationID != request.ProviderOrganizationID {
			return nil, oidc.ErrInvalidRequest()
		}
		return stored, nil
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return nil, err
	}
	request.entry, request.entryToken = &entry, token
	return &request, nil
}

func (service *Service) saveLoginNavigation(ctx context.Context, request *authorizationRequest) error {
	if request.entry != nil {
		return service.sealLoginEntry(request)
	}
	return service.storage.saveRequest(ctx, request)
}

func (s *storage) insertLoginEntry(ctx context.Context, request *authorizationRequest) error {
	data, err := json.Marshal(request)
	if err != nil {
		return err
	}
	result, err := s.service.store.Database().Exec(ctx, `INSERT INTO authentication_requests(id,client_id,data,expires_at)
		SELECT $1,$2,$3,$4::timestamptz WHERE $4 > $5::timestamptz ON CONFLICT (id) DO NOTHING`,
		request.ID, request.ClientID, data, request.entry.ExpiresAt, s.service.now())
	if err != nil {
		return err
	}
	if result.RowsAffected() != 1 {
		return oidc.ErrInvalidRequest()
	}
	request.entry, request.entryToken, request.Revision = nil, "", 1
	return nil
}
