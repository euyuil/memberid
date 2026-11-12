package oidcprovider

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"net/url"
	"time"

	"github.com/euyuil/memberid/internal/config"
	"github.com/euyuil/memberid/internal/identity"
	jose "github.com/go-jose/go-jose/v4"
	"github.com/zitadel/oidc/v3/pkg/oidc"
	"github.com/zitadel/oidc/v3/pkg/op"
)

const accessLifetime = 10 * time.Minute
const sessionIdleLifetime = 7 * 24 * time.Hour
const maximumLifetime = 365 * 24 * time.Hour

type client struct {
	registration config.Client
	loopback     bool
}

func (c client) GetID() string                       { return c.registration.ID }
func (c client) RedirectURIs() []string              { return c.registration.RedirectURIs }
func (c client) PostLogoutRedirectURIs() []string    { return c.registration.PostLogoutRedirectURIs }
func (c client) ApplicationType() op.ApplicationType { return op.ApplicationTypeWeb }
func (c client) AuthMethod() oidc.AuthMethod         { return oidc.AuthMethodBasic }
func (c client) ResponseTypes() []oidc.ResponseType {
	return []oidc.ResponseType{oidc.ResponseTypeCode}
}
func (c client) GrantTypes() []oidc.GrantType        { return []oidc.GrantType{oidc.GrantTypeCode} }
func (c client) LoginURL(id string) string           { return "/login?request=" + url.QueryEscape(id) }
func (c client) AccessTokenType() op.AccessTokenType { return op.AccessTokenTypeJWT }
func (c client) IDTokenLifetime() time.Duration      { return 5 * time.Minute }
func (c client) DevMode() bool                       { return c.loopback }
func (c client) RestrictAdditionalIdTokenScopes() func([]string) []string {
	return func(scopes []string) []string { return scopes }
}
func (c client) RestrictAdditionalAccessTokenScopes() func([]string) []string {
	return func(scopes []string) []string { return scopes }
}
func (c client) IsScopeAllowed(scope string) bool {
	return c.registration.EvidenceScope != "" && scope == c.registration.EvidenceScope
}
func (c client) IDTokenUserinfoClaimsAssertion() bool { return false }
func (c client) ClockSkew() time.Duration             { return 0 }

type grant struct {
	ID             string    `json:"id"`
	ClientID       string    `json:"clientId"`
	SessionID      string    `json:"sessionId"`
	FactorID       string    `json:"factorId"`
	FactorType     string    `json:"factorType"`
	MemberID       string    `json:"memberId,omitempty"`
	OrganizationID string    `json:"organizationId,omitempty"`
	BindingID      string    `json:"bindingId,omitempty"`
	Method         string    `json:"method"`
	AuthTime       time.Time `json:"authTime"`
	AbsoluteExpiry time.Time `json:"absoluteExpiry"`
	Scopes         []string  `json:"scopes"`
	Audience       []string  `json:"audience"`
}

func (g *grant) GetAMR() []string       { return []string{g.Method} }
func (g *grant) GetAudience() []string  { return g.Audience }
func (g *grant) GetAuthTime() time.Time { return g.AuthTime }
func (g *grant) GetClientID() string    { return g.ClientID }
func (g *grant) GetScopes() []string    { return g.Scopes }
func (g *grant) GetSubject() string {
	if g.MemberID != "" {
		return g.MemberID
	}
	return g.FactorID
}
func (g *grant) SetCurrentScopes(scopes []string) { g.Scopes = scopes }

type authorizationRequest struct {
	Revision int64 `json:"-"`
	grant
	Input        oidc.AuthRequest       `json:"input"`
	BrowserHash  string                 `json:"browserHash"`
	CSRF         string                 `json:"csrf"`
	PhoneNumber  string                 `json:"phoneNumber,omitempty"`
	ChallengeID  string                 `json:"challengeId,omitempty"`
	Verification *identity.Verification `json:"verification,omitempty"`
	Fresh        bool                   `json:"fresh"`
	Complete     bool                   `json:"complete"`
}

func (r *authorizationRequest) GetID() string  { return r.ID }
func (r *authorizationRequest) GetACR() string { return "" }
func (r *authorizationRequest) GetCodeChallenge() *oidc.CodeChallenge {
	return &oidc.CodeChallenge{Challenge: r.Input.CodeChallenge, Method: r.Input.CodeChallengeMethod}
}
func (r *authorizationRequest) GetNonce() string                   { return r.Input.Nonce }
func (r *authorizationRequest) GetRedirectURI() string             { return r.Input.RedirectURI }
func (r *authorizationRequest) GetResponseType() oidc.ResponseType { return r.Input.ResponseType }
func (r *authorizationRequest) GetResponseMode() oidc.ResponseMode { return r.Input.ResponseMode }
func (r *authorizationRequest) GetState() string                   { return r.Input.State }
func (r *authorizationRequest) Done() bool                         { return r.Complete }

func newID() string {
	var value [16]byte
	if _, err := rand.Read(value[:]); err != nil {
		panic(err)
	}
	value[6] = value[6]&15 | 64
	value[8] = value[8]&63 | 128
	return fmt.Sprintf("%x-%x-%x-%x-%x", value[:4], value[4:6], value[6:8], value[8:10], value[10:])
}
func sameSecret(a, b string) bool { return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1 }
func minimum(a, b time.Time) time.Time {
	if a.Before(b) {
		return a
	}
	return b
}
func requestGrant(request op.TokenRequest) (*grant, error) {
	switch value := request.(type) {
	case *authorizationRequest:
		return &value.grant, nil
	case *grant:
		return value, nil
	}
	return nil, oidc.ErrUnsupportedGrantType()
}

type signingKey struct {
	id  string
	key *rsa.PrivateKey
}

func (k signingKey) ID() string                                  { return k.id }
func (k signingKey) Key() any                                    { return k.key }
func (k signingKey) SignatureAlgorithm() jose.SignatureAlgorithm { return jose.RS256 }

type publicKey struct {
	id  string
	key *rsa.PublicKey
}

func (k publicKey) ID() string                         { return k.id }
func (k publicKey) Key() any                           { return k.key }
func (k publicKey) Algorithm() jose.SignatureAlgorithm { return jose.RS256 }
func (k publicKey) Use() string                        { return "sig" }

type storage struct{ service *Service }

func (s *storage) client(id string) (client, error) {
	for _, entry := range s.service.configuration.Clients {
		if entry.ID == id {
			return client{entry, s.service.configuration.AllowLoopbackHTTP}, nil
		}
	}
	return client{}, oidc.ErrInvalidClient()
}
func (s *storage) GetClientByClientID(_ context.Context, id string) (op.Client, error) {
	return s.client(id)
}
func (s *storage) AuthorizeClientIDSecret(_ context.Context, id, secret string) error {
	entry, err := s.client(id)
	if err != nil {
		return err
	}
	expected, err := hex.DecodeString(entry.registration.SecretSHA256)
	actual, _ := hex.DecodeString(config.SecretHash(secret))
	if err != nil || subtle.ConstantTimeCompare(expected, actual) != 1 {
		return oidc.ErrInvalidClient()
	}
	return nil
}
func (s *storage) Health(ctx context.Context) error { return s.service.store.Database().Ping(ctx) }
func (s *storage) SigningKey(context.Context) (op.SigningKey, error) {
	return signingKey{s.service.configuration.KeyID, s.service.configuration.SigningKey}, nil
}
func (s *storage) SignatureAlgorithms(context.Context) ([]jose.SignatureAlgorithm, error) {
	return []jose.SignatureAlgorithm{jose.RS256}, nil
}
func (s *storage) KeySet(context.Context) ([]op.Key, error) {
	keys := []op.Key{}
	for id, key := range s.service.configuration.PublicKeys {
		keys = append(keys, publicKey{id, key})
	}
	return keys, nil
}
func (s *storage) GetKeyByIDAndClientID(context.Context, string, string) (*jose.JSONWebKey, error) {
	return nil, errors.New("client JWT authentication is not enabled")
}
func (s *storage) ValidateJWTProfileScopes(context.Context, string, []string) ([]string, error) {
	return nil, oidc.ErrUnsupportedGrantType()
}
func (s *storage) CreateAccessAndRefreshTokens(context.Context, op.TokenRequest, string) (string, string, time.Time, error) {
	return "", "", time.Time{}, oidc.ErrUnsupportedGrantType()
}
func (s *storage) TokenRequestByRefreshToken(context.Context, string) (op.RefreshTokenRequest, error) {
	return nil, oidc.ErrUnsupportedGrantType()
}
func (s *storage) GetRefreshTokenInfo(context.Context, string, string) (string, string, error) {
	return "", "", op.ErrInvalidRefreshToken
}
