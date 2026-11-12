package oidcprovider

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"time"

	"github.com/euyuil/memberid/internal/config"
	"github.com/euyuil/memberid/internal/identity"
	"github.com/jackc/pgx/v5"
	"github.com/zitadel/oidc/v3/pkg/oidc"
	"github.com/zitadel/oidc/v3/pkg/op"
)

func (s *storage) CreateAuthRequest(ctx context.Context, input *oidc.AuthRequest, _ string) (op.AuthRequest, error) {
	registered, err := s.client(input.ClientID)
	if err != nil {
		return nil, err
	}
	challenge, err := base64.RawURLEncoding.DecodeString(input.CodeChallenge)
	if err != nil || len(challenge) != 32 || input.CodeChallengeMethod != oidc.CodeChallengeMethodS256 {
		return nil, oidc.ErrInvalidRequest().WithDescription("PKCE S256 is required")
	}
	if !slices.Contains(input.Scopes, "openid") {
		return nil, oidc.ErrInvalidScope()
	}
	for _, scope := range input.Scopes {
		if !slices.Contains([]string{"openid", "profile", "email", "phone"}, scope) && !registered.IsScopeAllowed(scope) {
			return nil, oidc.ErrInvalidScope()
		}
	}
	for _, prompt := range input.Prompt {
		if !slices.Contains([]string{"none", "login", "consent", "select_account"}, prompt) {
			return nil, oidc.ErrInvalidRequest()
		}
	}
	browser, _ := ctx.Value(browserKey{}).(string)
	if browser == "" {
		return nil, oidc.ErrServerError()
	}
	audience := s.service.configuration.Issuer + "/oauth/userinfo"
	if registered.registration.EvidenceScope != "" && slices.Contains(input.Scopes, registered.registration.EvidenceScope) {
		audience = registered.registration.EvidenceAudience
	}
	request := &authorizationRequest{grant: grant{ID: newID(), ClientID: input.ClientID, Scopes: input.Scopes, Audience: []string{audience}}, Input: *input, BrowserHash: config.SecretHash(browser), CSRF: config.RandomSecret()}
	data, err := json.Marshal(request)
	if err != nil {
		return nil, err
	}
	_, err = s.service.store.Database().Exec(ctx, "INSERT INTO oidc_authorization_requests(id,client_id,data,expires_at) VALUES($1,$2,$3,$4)", request.ID, request.ClientID, data, s.service.now().Add(10*time.Minute))
	return request, err
}

func (s *storage) loadRequest(ctx context.Context, column string, value any) (*authorizationRequest, error) {
	var data []byte
	var revision int64
	if err := s.service.store.Database().QueryRow(ctx, "SELECT data,revision FROM oidc_authorization_requests WHERE "+column+"=$1 AND expires_at>$2", value, s.service.now()).Scan(&data, &revision); err != nil {
		return nil, oidc.ErrInvalidGrant()
	}
	result := &authorizationRequest{Revision: revision}
	if err := json.Unmarshal(data, result); err != nil {
		return nil, oidc.ErrServerError()
	}
	return result, nil
}
func (s *storage) AuthRequestByID(ctx context.Context, id string) (op.AuthRequest, error) {
	request, err := s.loadRequest(ctx, "id", id)
	if err != nil {
		return nil, err
	}
	browser, _ := ctx.Value(browserKey{}).(string)
	if !sameSecret(request.BrowserHash, config.SecretHash(browser)) {
		return nil, oidc.ErrInvalidRequest()
	}
	return request, nil
}
func (s *storage) AuthRequestByCode(ctx context.Context, code string) (op.AuthRequest, error) {
	return s.loadRequest(ctx, "code_hash", config.SecretHash(code))
}
func (s *storage) SaveAuthCode(ctx context.Context, id, code string) error {
	result, err := s.service.store.Database().Exec(ctx, "UPDATE oidc_authorization_requests SET code_hash=$2,expires_at=LEAST(expires_at,$3) WHERE id=$1 AND code_hash IS NULL AND consumed_at IS NULL AND expires_at>$4", id, config.SecretHash(code), s.service.now().Add(time.Minute), s.service.now())
	if err != nil {
		return err
	}
	if result.RowsAffected() != 1 {
		return oidc.ErrInvalidGrant()
	}
	return nil
}
func (s *storage) DeleteAuthRequest(context.Context, string) error { return nil }

func (s *storage) saveRequest(ctx context.Context, request *authorizationRequest) error {
	data, err := json.Marshal(request)
	if err != nil {
		return err
	}
	result, err := s.service.store.Database().Exec(ctx, "UPDATE oidc_authorization_requests SET data=$2,revision=revision+1 WHERE id=$1 AND code_hash IS NULL AND consumed_at IS NULL AND expires_at>$3 AND revision=$4", request.ID, data, s.service.now(), request.Revision)
	if err != nil {
		return err
	}
	if result.RowsAffected() != 1 {
		return oidc.ErrInvalidRequest()
	}
	request.Revision++
	return nil
}

type databaseReader interface {
	QueryRow(context.Context, string, ...any) pgx.Row
}

func (s *storage) eligible(ctx context.Context, database databaseReader, g *grant) error {
	if g.FactorID == "" || !g.AbsoluteExpiry.After(s.service.now()) {
		return oidc.ErrInvalidGrant()
	}
	registered, err := s.client(g.ClientID)
	if err != nil {
		return err
	}
	var factorType string
	if err := database.QueryRow(ctx, "SELECT type FROM authentication_factors WHERE id=$1 AND status='active'", g.FactorID).Scan(&factorType); err != nil || factorType != g.FactorType {
		return oidc.ErrInvalidGrant()
	}
	if g.MemberID == "" {
		if registered.registration.SubjectKind != "factor" || g.FactorType != "phone" {
			return oidc.ErrInvalidGrant()
		}
		return nil
	}
	if registered.registration.SubjectKind != "member" || registered.registration.OrganizationID != "" && registered.registration.OrganizationID != g.OrganizationID {
		return oidc.ErrInvalidGrant()
	}
	binding, err := identity.MemberEvidence(ctx, database, g.FactorID, g.MemberID, g.OrganizationID)
	if err != nil || g.BindingID != "" && binding != g.BindingID {
		return oidc.ErrInvalidGrant()
	}
	g.BindingID = binding
	return nil
}

func (s *storage) CreateAccessToken(ctx context.Context, input op.TokenRequest) (string, time.Time, error) {
	request, ok := input.(*authorizationRequest)
	if !ok || !request.Complete {
		return "", time.Time{}, oidc.ErrInvalidGrant()
	}
	now := s.service.now()
	expiry := minimum(now.Add(accessLifetime), request.AbsoluteExpiry)
	tokenID := newID()
	replayed := false
	err := pgx.BeginFunc(ctx, s.service.store.Database(), func(tx pgx.Tx) error {
		var sessionID string
		var sessionExpiry time.Time
		if err := tx.QueryRow(ctx, "SELECT id,expires_at FROM oidc_sessions WHERE id=$1 AND revoked_at IS NULL AND expires_at>$2 AND absolute_expires_at>$2 FOR UPDATE", request.SessionID, now).Scan(&sessionID, &sessionExpiry); err != nil {
			return oidc.ErrInvalidGrant()
		}
		expiry = minimum(expiry, sessionExpiry)
		if err := s.eligible(ctx, tx, &request.grant); err != nil {
			return err
		}
		consumed, err := tx.Exec(ctx, "UPDATE oidc_authorization_requests SET consumed_at=$2 WHERE id=$1 AND consumed_at IS NULL AND code_hash IS NOT NULL AND expires_at>$2", request.ID, now)
		if err != nil {
			return err
		}
		if consumed.RowsAffected() != 1 {
			replayed = true
			_, err := tx.Exec(ctx, "UPDATE oidc_grants SET revoked_at=$2 WHERE id=$1", request.ID, now)
			return err
		}
		data, err := json.Marshal(&request.grant)
		if err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, "INSERT INTO oidc_grants(id,client_id,session_id,data,expires_at,absolute_expires_at) VALUES($1,$2,$3,$4,$5,$6)", request.ID, request.ClientID, request.SessionID, data, minimum(now.Add(sessionIdleLifetime), request.AbsoluteExpiry), request.AbsoluteExpiry); err != nil {
			return err
		}
		_, err = tx.Exec(ctx, "INSERT INTO oidc_access_tokens(id,grant_id,data,expires_at) VALUES($1,$2,$3,$4)", tokenID, request.ID, data, expiry)
		return err
	})
	if err != nil {
		return "", time.Time{}, err
	}
	if replayed {
		return "", time.Time{}, oidc.ErrInvalidGrant()
	}
	return tokenID, expiry, nil
}

func (s *storage) accessGrant(ctx context.Context, id, subject string) (*grant, error) {
	var data []byte
	err := s.service.store.Database().QueryRow(ctx, `SELECT a.data FROM oidc_access_tokens a JOIN oidc_grants g ON g.id=a.grant_id JOIN oidc_sessions s ON s.id=g.session_id
        WHERE a.id=$1 AND a.expires_at>$2 AND g.expires_at>$2 AND g.revoked_at IS NULL AND s.revoked_at IS NULL AND s.absolute_expires_at>$2`, id, s.service.now()).Scan(&data)
	if err != nil {
		return nil, &oidc.Error{ErrorType: "invalid_token"}
	}
	result := new(grant)
	if json.Unmarshal(data, result) != nil || result.GetSubject() != subject {
		return nil, &oidc.Error{ErrorType: "invalid_token"}
	}
	if err := s.eligible(ctx, s.service.store.Database(), result); err != nil {
		return nil, &oidc.Error{ErrorType: "invalid_token"}
	}
	return result, nil
}
func (s *storage) GetPrivateClaimsFromScopes(context.Context, string, string, []string) (map[string]any, error) {
	return nil, errors.New("request-bound claims required")
}
func (s *storage) GetPrivateClaimsFromRequest(_ context.Context, input op.TokenRequest, _ []string) (map[string]any, error) {
	g, err := requestGrant(input)
	if err != nil {
		return nil, err
	}
	claims := map[string]any{"scope": strings.Join(g.Scopes, " "), "tokenUse": "access", "auth_time": g.AuthTime.Unix(), "amr": g.GetAMR()}
	registered, err := s.client(g.ClientID)
	if err != nil {
		return nil, err
	}
	if registered.registration.EvidenceScope != "" && slices.Contains(g.Scopes, registered.registration.EvidenceScope) {
		evidence := map[string]any{"factorId": g.FactorID, "factorType": g.FactorType, "method": g.Method, "authenticatedAt": g.AuthTime.Unix(), "expiresAt": g.AbsoluteExpiry.Unix()}
		claims["authentication"] = evidence
		if g.MemberID != "" {
			claims["organizationId"] = g.OrganizationID
			claims["memberId"] = g.MemberID
			claims["bindingId"] = g.BindingID
		}
	}
	return claims, nil
}
func (s *storage) SetUserinfoFromScopes(context.Context, *oidc.UserInfo, string, string, []string) error {
	return nil
}
func (s *storage) SetUserinfoFromRequest(ctx context.Context, info *oidc.UserInfo, input op.IDTokenRequest, scopes []string) error {
	g, err := requestGrant(input)
	if err != nil {
		return err
	}
	info.AppendClaims("sid", g.SessionID)
	return s.userinfo(ctx, info, g, scopes)
}
func (s *storage) userinfo(ctx context.Context, info *oidc.UserInfo, g *grant, scopes []string) error {
	info.Subject = g.GetSubject()
	if g.MemberID != "" && slices.Contains(scopes, "profile") {
		member, err := s.service.store.Member(ctx, g.OrganizationID, g.MemberID)
		if err != nil {
			return err
		}
		info.Name = member.DisplayName
		info.PreferredUsername = g.MemberID
	}
	if g.FactorType == "phone" && slices.Contains(scopes, "phone") {
		factor, err := s.service.store.Factor(ctx, g.FactorID)
		if err != nil {
			return err
		}
		info.PhoneNumber = factor.Subject
		info.PhoneNumberVerified = true
	}
	return nil
}
func (s *storage) SetUserinfoFromToken(ctx context.Context, info *oidc.UserInfo, id, subject, _ string) error {
	g, err := s.accessGrant(ctx, id, subject)
	if err != nil {
		return err
	}
	return s.userinfo(ctx, info, g, g.Scopes)
}
func (s *storage) SetIntrospectionFromToken(ctx context.Context, info *oidc.IntrospectionResponse, id, subject, clientID string) error {
	g, err := s.accessGrant(ctx, id, subject)
	if err != nil {
		return err
	}
	if g.ClientID != clientID {
		return oidc.ErrInvalidClient()
	}
	info.Active = true
	info.Subject = subject
	info.ClientID = g.ClientID
	info.Audience = g.Audience
	info.Scope = g.Scopes
	return nil
}
func (s *storage) RevokeToken(ctx context.Context, id, subject, clientID string) *oidc.Error {
	_, err := s.service.store.Database().Exec(ctx, "UPDATE oidc_grants SET revoked_at=$3 WHERE client_id=$1 AND id IN (SELECT grant_id FROM oidc_access_tokens WHERE id=$2)", clientID, id, s.service.now())
	if err != nil {
		return oidc.ErrServerError()
	}
	return nil
}
func (s *storage) TerminateSession(context.Context, string, string) error {
	return oidc.ErrInvalidRequest().WithDescription("id_token_hint is required")
}
func (s *storage) TerminateSessionFromRequest(ctx context.Context, input *op.EndSessionRequest) (string, error) {
	if input.IDTokenHintClaims == nil || input.IDTokenHintClaims.SessionID == "" {
		return "", oidc.ErrInvalidRequest()
	}
	sessionID := input.IDTokenHintClaims.SessionID
	logout, ok := ctx.Value(logoutKey{}).(logoutContext)
	if !ok {
		return "", oidc.ErrInvalidRequest()
	}
	err := pgx.BeginFunc(ctx, s.service.store.Database(), func(tx pgx.Tx) error {
		var expected string
		err := tx.QueryRow(ctx, "SELECT secret_hash FROM oidc_sessions WHERE id=$1 FOR UPDATE", sessionID).Scan(&expected)
		if errors.Is(err, pgx.ErrNoRows) {
			return nil
		}
		if err != nil {
			return err
		}
		if logout.secret != "" && !sameSecret(expected, config.SecretHash(logout.secret)) {
			return oidc.ErrInvalidRequest()
		}
		var issued bool
		if err := tx.QueryRow(ctx, "SELECT EXISTS(SELECT 1 FROM oidc_grants WHERE session_id=$1 AND client_id=$2 AND COALESCE(NULLIF(data->>'memberId',''),data->>'factorId')=$3)", sessionID, input.ClientID, input.UserID).Scan(&issued); err != nil {
			return err
		}
		if !issued {
			return oidc.ErrInvalidRequest()
		}
		if _, err := tx.Exec(ctx, "UPDATE oidc_sessions SET revoked_at=$2 WHERE id=$1", sessionID, s.service.now()); err != nil {
			return err
		}
		_, err = tx.Exec(ctx, "UPDATE oidc_grants SET revoked_at=$2 WHERE session_id=$1", sessionID, s.service.now())
		return err
	})
	if err == nil {
		logout.clear()
	}
	return input.RedirectURI, err
}
