package oidcprovider

import (
	"context"
	"encoding/base64"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/euyuil/memberid/internal/config"
	"github.com/euyuil/memberid/internal/identity"
	"github.com/rs/cors"
	"github.com/zitadel/oidc/v3/pkg/oidc"
	"github.com/zitadel/oidc/v3/pkg/op"
)

type Service struct {
	configuration *config.Loaded
	store         *identity.Store
	phone         *identity.PhoneVerifier
	protocol      *op.Provider
	storage       *storage
	now           func() time.Time
}

type browserKey struct{}
type logoutKey struct{}
type logoutContext struct {
	secret string
	clear  func()
}

func New(configuration *config.Loaded, store *identity.Store, phone *identity.PhoneVerifier) (*Service, error) {
	if configuration == nil || store == nil || phone == nil || configuration.SigningKey == nil || len(configuration.PublicKeys) == 0 {
		return nil, errors.New("OIDC requires a configured store, signing key, and enabled authentication provider")
	}
	if err := configuration.Installation.Validate(); err != nil {
		return nil, err
	}
	if err := configuration.Secrets.Validate(); err != nil {
		return nil, err
	}
	if err := config.ValidateClients(configuration.Clients, configuration.AllowLoopbackHTTP); err != nil {
		return nil, err
	}
	service := &Service{configuration: configuration, store: store, phone: phone, now: time.Now}
	service.storage = &storage{service: service}
	var key [32]byte
	decoded, _ := base64.StdEncoding.DecodeString(configuration.Secrets.ProtocolKey)
	copy(key[:], decoded)
	scopes := []string{"openid", "profile", "email", "phone"}
	seen := map[string]bool{}
	for _, client := range configuration.Clients {
		if client.EvidenceScope != "" && !seen[client.EvidenceScope] {
			scopes = append(scopes, client.EvidenceScope)
			seen[client.EvidenceScope] = true
		}
	}
	options := []op.Option{
		op.WithCORSOptions(&cors.Options{AllowedOrigins: []string{configuration.Issuer}, AllowedMethods: []string{"GET", "POST"}, AllowedHeaders: []string{"Authorization", "Content-Type"}}),
		op.WithCustomAuthEndpoint(op.NewEndpoint("/oauth/authorize")), op.WithCustomUserinfoEndpoint(op.NewEndpoint("/oauth/userinfo")),
		op.WithCustomRevocationEndpoint(op.NewEndpoint("/oauth/revoke")), op.WithCustomEndSessionEndpoint(op.NewEndpoint("/oauth/logout")),
		op.WithCustomKeysEndpoint(op.NewEndpoint("/.well-known/jwks.json")),
	}
	if configuration.AllowLoopbackHTTP {
		options = append(options, op.WithAllowInsecure())
	}
	provider, err := op.NewProvider(&op.Config{CryptoKey: key, CodeMethodS256: true, SupportedScopes: scopes, SupportedClaims: []string{"iss", "sub", "aud", "exp", "iat", "auth_time", "nonce", "amr", "at_hash", "c_hash", "client_id", "azp", "sid", "name", "preferred_username", "phone_number", "phone_number_verified"}, DefaultLogoutRedirectURI: configuration.Issuer + "/signed-out"}, service.storage, op.StaticIssuer(configuration.Issuer), options...)
	if err != nil {
		return nil, err
	}
	service.protocol = provider
	return service, nil
}

func (service *Service) cookieName(kind string) string {
	if strings.HasPrefix(service.configuration.Issuer, "https://") {
		return "__Host-memberid_" + kind
	}
	return "memberid_" + kind
}
func (service *Service) cookie(w http.ResponseWriter, kind, value string, lifetime time.Duration) {
	http.SetCookie(w, &http.Cookie{Name: service.cookieName(kind), Value: value, Path: "/", Secure: strings.HasPrefix(service.configuration.Issuer, "https://"), HttpOnly: true, SameSite: http.SameSiteLaxMode, MaxAge: int(lifetime.Seconds())})
}
func (service *Service) cookieValue(r *http.Request, kind string) string {
	cookies := r.CookiesNamed(service.cookieName(kind))
	if len(cookies) != 1 {
		return ""
	}
	return cookies[0].Value
}

type userinfoWriter struct{ http.ResponseWriter }

func (w userinfoWriter) WriteHeader(status int) {
	if status == http.StatusForbidden {
		status = http.StatusUnauthorized
	}
	if status == http.StatusUnauthorized {
		w.Header().Set("WWW-Authenticate", `Bearer error="invalid_token"`)
	}
	w.ResponseWriter.WriteHeader(status)
}

func (service *Service) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("X-Frame-Options", "DENY")
	if len(r.URL.RawQuery) > 32<<10 {
		http.Error(w, "Request is too large", http.StatusBadRequest)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 32<<10)
	if err := r.ParseForm(); err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}
	for _, values := range r.Form {
		if len(values) != 1 {
			http.Error(w, "Repeated parameter", http.StatusBadRequest)
			return
		}
	}
	browser := service.cookieValue(r, "browser")
	interactive := r.URL.Path == "/login" || strings.HasPrefix(r.URL.Path, "/oauth/authorize")
	if interactive && len(browser) != 43 {
		browser = config.RandomSecret()
		service.cookie(w, "browser", browser, sessionIdleLifetime)
	}
	ctx := context.WithValue(r.Context(), browserKey{}, browser)
	ctx = context.WithValue(ctx, logoutKey{}, logoutContext{secret: service.cookieValue(r, "session"), clear: func() { service.cookie(w, "session", "", -time.Second) }})
	r = r.WithContext(ctx)
	switch r.URL.Path {
	case "/.well-known/openid-configuration":
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			w.Header().Set("Allow", "GET, HEAD")
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}
		metadata := op.CreateDiscoveryConfig(op.ContextWithIssuer(r.Context(), service.configuration.Issuer), service.protocol, service.storage)
		// The library defaults include flows that this deployment profile does not enable.
		metadata.ResponseTypesSupported = []string{"code"}
		metadata.GrantTypesSupported = []oidc.GrantType{oidc.GrantTypeCode}
		metadata.TokenEndpointAuthMethodsSupported = []oidc.AuthMethod{oidc.AuthMethodBasic}
		metadata.RevocationEndpointAuthMethodsSupported = []oidc.AuthMethod{oidc.AuthMethodBasic}
		metadata.DeviceAuthorizationEndpoint = ""
		op.Discover(w, metadata)
		return
	case "/login":
		service.login(w, r)
		return
	case "/signed-out":
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		_, _ = w.Write([]byte("Signed out of MemberID. You may close this page.\n"))
		return
	}
	if r.URL.Path == "/oauth/authorize" && (r.Form.Has("resource") || r.Form.Has("audience")) {
		http.Error(w, "Resource selection is not supported", http.StatusBadRequest)
		return
	}
	if r.URL.Path == "/oauth/userinfo" {
		w = userinfoWriter{w}
	}
	service.protocol.ServeHTTP(w, r)
}

func (service *Service) Cleanup(ctx context.Context) error {
	for _, table := range []string{"oidc_access_tokens", "oidc_authorization_requests", "oidc_grants", "oidc_sessions"} {
		if _, err := service.store.Database().Exec(ctx, "DELETE FROM "+table+" WHERE expires_at<$1", service.now()); err != nil {
			return err
		}
	}
	return service.store.CleanupPhoneChallenges(ctx)
}
