package console

import (
	"context"
	"encoding/base64"
	"errors"
	"io/fs"
	"net"
	"net/http"
	"net/url"
	"slices"
	"time"

	"github.com/euyuil/memberid/internal/config"
	"github.com/euyuil/memberid/internal/consolestate"
	"github.com/euyuil/memberid/internal/identity"
	"github.com/zitadel/oidc/v3/pkg/client/rp"
	"golang.org/x/oauth2"
)

// New wires protected management operations and bounded session persistence.
func New(ctx context.Context, store *identity.Store, installation *config.Loaded, settings Settings, secret string, dingTalk identity.DingTalkAuthorizationChecker, feishu identity.FeishuProvider) (*Service, error) {
	u, err := url.Parse(settings.Origin)
	if err != nil || u.Host == "" || u.User != nil || u.Path != "" || u.RawQuery != "" || u.Fragment != "" || u.ForceQuery {
		return nil, errors.New("console origin must be an exact HTTPS origin")
	}
	if u.Scheme != "https" && !(installation.AllowLoopbackHTTP && u.Scheme == "http" && net.ParseIP(u.Hostname()).IsLoopback()) {
		return nil, errors.New("console HTTP requires explicit loopback development configuration")
	}
	registered, err := store.OIDCClient(ctx, settings.ClientID)
	client := registered.Client
	if err != nil || !registered.Enabled || !registered.System || client.SubjectKind != "member" ||
		client.OrganizationID != "" || client.SecretSHA256 != config.SecretHash(secret) ||
		!slices.Contains(client.RedirectURIs, settings.Origin+"/auth/callback") {
		return nil, errors.New("console requires its own protected all-organization Member client and exact callback")
	}
	party, err := rp.NewRelyingPartyOIDC(ctx, installation.Issuer, settings.ClientID, secret, settings.Origin+"/auth/callback", []string{"openid", "profile"}, rp.WithHTTPClient(&http.Client{Timeout: 15 * time.Second}), rp.WithAuthStyle(oauth2.AuthStyleInHeader), rp.WithVerifierOpts(rp.WithNonce(func(ctx context.Context) string { value, _ := ctx.Value(nonceKey{}).(string); return value }), rp.WithSupportedSigningAlgorithms("RS256")))
	if err != nil {
		return nil, err
	}
	key, err := base64.StdEncoding.DecodeString(installation.Secrets.ProviderKey)
	if err != nil {
		return nil, err
	}
	dingTalkApps, err := identity.NewDingTalkApplications(store, key, dingTalk)
	if err != nil {
		return nil, err
	}
	feishuApps, err := identity.NewFeishuApplications(store, key, feishu)
	if err != nil {
		return nil, err
	}
	s := &Service{management: identity.NewManagementService(store, dingTalkApps, feishuApps, installation.AuthenticationEventRetention()), sessions: consolestate.New(store.Database()), origin: settings.Origin, clientID: settings.ClientID, party: party, routes: http.NewServeMux()}
	s.issuer = installation.Issuer
	s.routes.HandleFunc("GET /auth/login", s.login)
	s.routes.HandleFunc("GET /auth/callback", s.callback)
	s.routes.HandleFunc("POST /api/logout", s.logout)
	s.routes.HandleFunc("GET /api/identities", s.identities)
	s.routes.HandleFunc("POST /api/identity-switch", s.switchIdentity)
	s.routes.HandleFunc("POST /api/account-link", s.beginAccountLink)
	s.routes.HandleFunc("GET /api/session", func(w http.ResponseWriter, r *http.Request) {
		v := r.Context().Value(sessionKey{}).(session)
		actor, err := s.management.Actor(r.Context(), v.memberID, v.grantID)
		respond(w, map[string]any{"actor": actor, "csrf": v.csrf}, err)
	})
	s.routes.HandleFunc("GET /api/organizations", s.organizations)
	s.routes.HandleFunc("POST /api/organizations", s.mutate)
	s.routes.HandleFunc("GET /api/organizations/{organizationId}", func(w http.ResponseWriter, r *http.Request) {
		v, e := s.management.Organization(r.Context(), r.Context().Value(sessionKey{}).(session).principal(), r.PathValue("organizationId"))
		respond(w, v, e)
	})
	s.routes.HandleFunc("PATCH /api/organizations/{organizationId}", s.mutate)
	s.routes.HandleFunc("GET /api/members", s.allOrganizationMembers)
	s.routes.HandleFunc("GET /api/organizations/{organizationId}/members", s.members)
	s.routes.HandleFunc("POST /api/organizations/{organizationId}/members", s.mutate)
	s.routes.HandleFunc("GET /api/organizations/{organizationId}/members/{memberId}", s.member)
	s.routes.HandleFunc("GET /api/organizations/{organizationId}/members/{memberId}/grants", s.memberGrants)
	s.routes.HandleFunc("PATCH /api/organizations/{organizationId}/members/{memberId}", s.mutate)
	s.routes.HandleFunc("PUT /api/organizations/{organizationId}/members/{memberId}/email", s.putMemberEmail)
	s.routes.HandleFunc("PUT /api/organizations/{organizationId}/members/{memberId}/administrator", s.administrator)
	s.routes.HandleFunc("POST /api/organizations/{organizationId}/members/{memberId}/password", s.createMemberPassword)
	s.routes.HandleFunc("PATCH /api/organizations/{organizationId}/members/{memberId}/password", s.renameMemberPassword)
	s.routes.HandleFunc("POST /api/organizations/{organizationId}/members/{memberId}/password/reset", s.resetMemberPassword)
	s.routes.HandleFunc("GET /api/events", s.events)
	s.routes.HandleFunc("GET /api/authentication-events", s.authenticationEvents)
	s.routes.HandleFunc("GET /api/authentication-events/{eventId}", s.authenticationEvent)
	s.routes.HandleFunc("GET /api/organizations/{organizationId}/authentication-events", s.authenticationEvents)
	s.routes.HandleFunc("GET /api/organizations/{organizationId}/authentication-events/{eventId}", s.authenticationEvent)
	s.registerProviderRoutes(installation)
	s.registerSAMLRoutes()
	s.registerSAMLIdentityProviderRoute(installation.Issuer)
	s.registerOIDCApplicationRoutes(installation)
	static, _ := fs.Sub(assets, "static")
	registerPages(s.routes, static)
	return s, nil
}
