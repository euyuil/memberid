package oidcprovider

import (
	"context"
	"encoding/json"
	"errors"
	"slices"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/zhizhun-tech/memberid/internal/authevent"
	"github.com/zhizhun-tech/memberid/internal/config"
	"github.com/zitadel/oidc/v3/pkg/oidc"
	"github.com/zitadel/oidc/v3/pkg/op"
)

type refreshRequest struct {
	grant
	tokenID    string
	secretHash string
}

func (s *storage) TokenRequestByRefreshToken(ctx context.Context, secret string) (op.RefreshTokenRequest, error) {
	if len(secret) != 43 {
		return nil, oidc.ErrInvalidGrant()
	}
	request := &refreshRequest{secretHash: config.SecretHash(secret)}
	var data []byte
	// Retain consumed-token lookup until the family expires. Revocation happens only
	// after the protocol layer has authenticated and matched the owning client.
	if err := s.service.store.Database().QueryRow(ctx, "SELECT id,data FROM oidc_refresh_tokens WHERE secret_hash=$1", request.secretHash).Scan(&request.tokenID, &data); err != nil {
		return nil, oidc.ErrInvalidGrant()
	}
	if json.Unmarshal(data, &request.grant) != nil {
		return nil, oidc.ErrServerError()
	}
	return request, nil
}

func (s *storage) CreateAccessAndRefreshTokens(ctx context.Context, input op.TokenRequest, secret string) (string, string, time.Time, error) {
	switch request := input.(type) {
	case *authorizationRequest:
		registered, err := s.client(ctx, request.ClientID)
		if err != nil || !registered.registration.Refresh || !slices.Contains(request.Scopes, "offline_access") || secret != "" {
			return "", "", time.Time{}, oidc.ErrInvalidGrant()
		}
		return s.createCodeTokens(ctx, request, true)
	case *refreshRequest:
		return s.rotateRefresh(ctx, request, secret)
	default:
		return "", "", time.Time{}, oidc.ErrInvalidGrant()
	}
}

func (s *storage) persistTokens(ctx context.Context, tx pgx.Tx, g *grant, accessID, refreshSecret string, expiry time.Time) error {
	data, err := json.Marshal(g)
	if err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, "INSERT INTO oidc_access_tokens(id,grant_id,data,expires_at) VALUES($1,$2,$3,$4)", accessID, g.ID, data, expiry); err != nil {
		return err
	}
	if refreshSecret != "" {
		_, err = tx.Exec(ctx, "INSERT INTO oidc_refresh_tokens(id,secret_hash,grant_id,data,created_at) VALUES($1,$2,$3,$4,$5)", newID(), config.SecretHash(refreshSecret), g.ID, data, s.service.now())
	}
	return err
}

func (s *storage) rotateRefresh(ctx context.Context, request *refreshRequest, secret string) (string, string, time.Time, error) {
	if !sameSecret(request.secretHash, config.SecretHash(secret)) {
		return "", "", time.Time{}, oidc.ErrInvalidGrant()
	}
	now := s.service.now()
	accessID, nextSecret := newID(), config.RandomSecret()
	expiry := minimum(now.Add(accessLifetime), request.AbsoluteExpiry)
	replayed, revoked, commitReady := false, false, false
	var reuse authevent.Event
	observation, observationErr := s.observeDirectory(ctx, &request.grant)
	err := pgx.BeginFunc(ctx, s.service.store.Database(), func(tx pgx.Tx) error {
		registered, err := s.issuanceClient(ctx, tx, request.ClientID)
		if err != nil {
			return err
		}
		if !registered.registration.Refresh {
			return oidc.ErrInvalidGrant()
		}
		var sessionID string
		// A refresh does not depend on a browser cookie or the browser SSO idle deadline.
		// Lock sessions before grants, matching code issuance and RP-initiated logout.
		if err := tx.QueryRow(ctx, "SELECT id FROM authentication_sessions WHERE id=$1 AND revoked_at IS NULL AND absolute_expires_at>$2 FOR UPDATE", request.SessionID, now).Scan(&sessionID); err != nil {
			return grantEligibilityError(err)
		}
		var grantID string
		if err := tx.QueryRow(ctx, "SELECT id FROM oidc_grants WHERE id=$1 AND client_id=$2 AND session_id=$3 AND revoked_at IS NULL AND expires_at>$4 AND absolute_expires_at>$4 FOR UPDATE", request.ID, request.ClientID, sessionID, now).Scan(&grantID); err != nil {
			return grantEligibilityError(err)
		}
		var consumed *time.Time
		if err := tx.QueryRow(ctx, "SELECT consumed_at FROM oidc_refresh_tokens WHERE id=$1 AND grant_id=$2 AND secret_hash=$3 FOR UPDATE", request.tokenID, grantID, request.secretHash).Scan(&consumed); err != nil {
			return grantEligibilityError(err)
		}
		if consumed != nil {
			replayed = true
			reuse = grantEvent(ctx, &request.grant)
			reuse.EventID, reuse.Type, reuse.Outcome = authevent.NewID(), "oidc.refreshToken.reuse", "detected"
			reuse.Actor = authevent.Actor{Kind: "client", ID: request.ClientID}
			reuse.OccurredAt = s.service.now().UTC()
			changed, err := tx.Exec(ctx, "UPDATE oidc_grants SET revoked_at=$2 WHERE id=$1 AND revoked_at IS NULL", grantID, now)
			revoked, commitReady = changed.RowsAffected() == 1, err == nil
			return err
		}
		if !request.AbsoluteExpiry.After(now.Add(5 * time.Minute)) {
			return oidc.ErrInvalidGrant()
		}
		if err := s.validateDirectory(ctx, tx, observation, observationErr); err != nil {
			return err
		}
		if err := s.lockMemberOrganization(ctx, tx, &request.grant); err != nil {
			return err
		}
		if err := s.eligible(ctx, tx, &request.grant); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, "UPDATE oidc_refresh_tokens SET consumed_at=$2 WHERE id=$1", request.tokenID, now); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, "UPDATE oidc_grants SET expires_at=$2 WHERE id=$1", grantID, minimum(now.Add(sessionIdleLifetime), request.AbsoluteExpiry)); err != nil {
			return err
		}
		return s.persistTokens(ctx, tx, &request.grant, accessID, nextSecret, expiry)
	})
	if replayed {
		s.recordReuse(reuse, revoked, err, commitReady)
	}
	if err != nil {
		return "", "", time.Time{}, err
	}
	if replayed {
		return "", "", time.Time{}, oidc.ErrInvalidGrant()
	}
	return accessID, nextSecret, expiry, nil
}

func (s *storage) GetRefreshTokenInfo(ctx context.Context, clientID, secret string) (string, string, error) {
	if len(secret) != 43 {
		return "", "", op.ErrInvalidRefreshToken
	}
	var id string
	var data []byte
	err := s.service.store.Database().QueryRow(ctx, "SELECT r.id,r.data FROM oidc_refresh_tokens r JOIN oidc_grants g ON g.id=r.grant_id WHERE r.secret_hash=$1 AND g.client_id=$2", config.SecretHash(secret), clientID).Scan(&id, &data)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", "", op.ErrInvalidRefreshToken
	}
	if err != nil {
		return "", "", err
	}
	var g grant
	if json.Unmarshal(data, &g) != nil {
		return "", "", oidc.ErrServerError()
	}
	return g.GetSubject(), id, nil
}
