package oidcprovider

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"slices"
	"time"

	jose "github.com/go-jose/go-jose/v4"
	"github.com/jackc/pgx/v5"
	"github.com/zhizhun-tech/memberid/internal/browserauth"
	"github.com/zhizhun-tech/memberid/internal/config"
	"github.com/zhizhun-tech/memberid/internal/identity"
	"github.com/zhizhun-tech/memberid/internal/samlprovider"
	"github.com/zitadel/oidc/v3/pkg/oidc"
	"github.com/zitadel/oidc/v3/pkg/op"
)

const accessLifetime = 10 * time.Minute
const sessionIdleLifetime = 7 * 24 * time.Hour
const maximumLifetime = 365 * 24 * time.Hour

type client struct {
	registration config.Client
	sharedOwner  string
	displayName  string
	revision     int64
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
func (c client) GrantTypes() []oidc.GrantType {
	grants := []oidc.GrantType{oidc.GrantTypeCode}
	if c.registration.Refresh {
		grants = append(grants, oidc.GrantTypeRefreshToken)
	}
	return grants
}
func organizationLoginURL(organizationID, requestID string) string {
	path := "/login"
	if organizationID != "" {
		path += "/" + organizationID
	}
	return path + "?request=" + url.QueryEscape(requestID)
}

func requestLoginURL(request *authorizationRequest) string {
	return organizationLoginURL(request.ProviderOrganizationID, request.GetID())
}

func (c client) LoginURL(id string) string {
	return organizationLoginURL(c.registration.OrganizationID, id)
}
func (c client) AccessTokenType() op.AccessTokenType { return op.AccessTokenTypeJWT }
func (c client) IDTokenLifetime() time.Duration      { return 5 * time.Minute }
func (c client) DevMode() bool                       { return c.loopback }
func (c client) RestrictAdditionalIdTokenScopes() func([]string) []string {
	return func(scopes []string) []string {
		// A refreshed ID Token retains core session claims even when access scopes narrow.
		if slices.Contains(scopes, "openid") {
			return scopes
		}
		return append(slices.Clone(scopes), "openid")
	}
}
func (c client) RestrictAdditionalAccessTokenScopes() func([]string) []string {
	return func(scopes []string) []string { return scopes }
}
func (c client) IsScopeAllowed(scope string) bool {
	return c.registration.EvidenceScope != "" && scope == c.registration.EvidenceScope
}
func (c client) IDTokenUserinfoClaimsAssertion() bool { return false }
func (c client) ClockSkew() time.Duration             { return 0 }

// Stored grants, tokens and pending logins can predate the retirement of the
// organization scope. Drop only that scope before consent or eligibility checks.
type grantScopes []string

func (scopes *grantScopes) UnmarshalJSON(data []byte) error {
	var stored []string
	if err := json.Unmarshal(data, &stored); err != nil {
		return err
	}
	*scopes = slices.DeleteFunc(stored, func(scope string) bool { return scope == "memberid.organization" })
	return nil
}

type grant struct {
	InteractionID  string      `json:"interactionId,omitempty"`
	ID             string      `json:"id"`
	ClientID       string      `json:"clientId"`
	ClientName     string      `json:"clientName,omitempty"`
	SessionID      string      `json:"sessionId"`
	FactorID       string      `json:"factorId"`
	FactorType     string      `json:"factorType"`
	MemberID       string      `json:"memberId,omitempty"`
	OrganizationID string      `json:"organizationId,omitempty"`
	EnablementID   string      `json:"enablementId,omitempty"`
	BindingID      string      `json:"bindingId,omitempty"`
	Method         string      `json:"method"`
	AuthTime       time.Time   `json:"authTime"`
	AbsoluteExpiry time.Time   `json:"absoluteExpiry"`
	Scopes         grantScopes `json:"scopes"`
	Audience       []string    `json:"audience"`
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
	browserauth.Interaction
	grant
	entry          *oidcLoginEntry
	entryToken     string
	ClientRevision int64                     `json:"clientRevision,omitempty"`
	Input          oidc.AuthRequest          `json:"input,omitempty"`
	HintSubject    string                    `json:"hintSubject,omitempty"`
	SAML           *samlprovider.Transaction `json:"saml,omitempty"`
}

func (r *authorizationRequest) externalPending() bool { return r.DingTalk != nil || r.Feishu != nil }

func (r *authorizationRequest) GetID() string {
	if r.entryToken != "" {
		return r.entryToken
	}
	return r.ID
}
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
	case *refreshRequest:
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

type authenticatedClientKey struct{}

type authenticatedClient struct {
	id, verifier string
}

func (s *storage) client(ctx context.Context, id string) (client, error) {
	return s.clientAt(ctx, s.service.store.Database(), id)
}

func (s *storage) clientAt(ctx context.Context, db databaseReader, id string) (client, error) {
	return s.registeredClient(identity.ReadOIDCClient(ctx, db, id))
}

func (s *storage) registeredClient(registration identity.OIDCClientRegistration, err error) (client, error) {
	if errors.Is(err, identity.ErrNotFound) || err == nil && !registration.Enabled {
		return client{}, oidc.ErrInvalidClient()
	}
	if err != nil {
		return client{}, oidc.ErrServerError()
	}
	var sharedOwner string
	if registration.Published {
		sharedOwner = registration.OwnerOrganizationID
		registration.Client.OrganizationID = ""
	}
	return client{
		sharedOwner: sharedOwner, registration: registration.Client, displayName: registration.DisplayName,
		revision: registration.Revision, loopback: s.service.configuration.AllowLoopbackHTTP,
	}, nil
}

// An activation identifies one uninterrupted period of consumer enablement.
func (c client) organizationActivation(ctx context.Context, db databaseReader, organizationID string) (string, error) {
	if c.registration.OrganizationID != "" && c.registration.OrganizationID != organizationID {
		return "", identity.ErrIneligible
	}
	if c.sharedOwner == "" || organizationID == c.sharedOwner {
		return "", nil
	}
	var activation string
	err := db.QueryRow(ctx, "SELECT activation_id::text FROM oidc_application_enablements WHERE client_id=$1 AND organization_id=$2", c.GetID(), organizationID).Scan(&activation)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", identity.ErrIneligible
	}
	return activation, err
}

func (c client) checkActivation(ctx context.Context, db databaseReader, organizationID, expected string) error {
	current, err := c.organizationActivation(ctx, db, organizationID)
	if err == nil && current != expected {
		return identity.ErrIneligible
	}
	return err
}

func (s *storage) issuanceClient(ctx context.Context, tx pgx.Tx, id string) (client, error) {
	registered, err := s.registeredClient(identity.LockOIDCClient(ctx, tx, id))
	if err != nil {
		return client{}, err
	}
	if authenticated, ok := ctx.Value(authenticatedClientKey{}).(*authenticatedClient); ok &&
		(authenticated.id != id || !sameSecret(authenticated.verifier, registered.registration.SecretSHA256)) {
		return client{}, oidc.ErrInvalidClient()
	}
	return registered, nil
}

func (request *authorizationRequest) permitsClient(registered client) bool {
	revision := request.ClientRevision
	if revision == 0 {
		revision = 1 // Pre-upgrade pending requests were created from the imported policy.
	}
	return registered.revision == revision && slices.Contains(registered.registration.RedirectURIs, request.Input.RedirectURI)
}

func (s *storage) GetClientByClientID(ctx context.Context, id string) (op.Client, error) {
	return s.client(ctx, id)
}

func (s *storage) AuthorizeClientIDSecret(ctx context.Context, id, secret string) error {
	entry, err := s.client(ctx, id)
	if err != nil {
		return err
	}
	expected, err := hex.DecodeString(entry.registration.SecretSHA256)
	actual, _ := hex.DecodeString(config.SecretHash(secret))
	if err != nil || subtle.ConstantTimeCompare(expected, actual) != 1 {
		return oidc.ErrInvalidClient()
	}
	if authenticated, ok := ctx.Value(authenticatedClientKey{}).(*authenticatedClient); ok {
		*authenticated = authenticatedClient{id, entry.registration.SecretSHA256}
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

func validTokenID(value string) bool { return identity.ValidUUID(value) }
