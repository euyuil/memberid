package oidcprovider

import (
	"context"
	"encoding/base64"
	"errors"
	"mime"
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
	dingtalk      *identity.DingTalkVerifier
	directory     *identity.DingTalkDirectory
	protocol      *op.Provider
	storage       *storage
	now           func() time.Time
}

type browserKey struct{}

func New(configuration *config.Loaded, store *identity.Store, phone *identity.PhoneVerifier, dingtalk *identity.DingTalkVerifier, directory *identity.DingTalkDirectory) (*Service, error) {
	if configuration == nil || store == nil || dingtalk != nil && directory == nil || phone == nil && dingtalk == nil || configuration.SigningKey == nil || len(configuration.PublicKeys) == 0 {
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
	service := &Service{configuration: configuration, store: store, phone: phone, dingtalk: dingtalk, directory: directory, now: time.Now}
	service.storage = &storage{service: service}
	var key [32]byte
	decoded, _ := base64.StdEncoding.DecodeString(configuration.Secrets.ProtocolKey)
	copy(key[:], decoded)
	scopes := []string{"openid", "profile", "email", "phone"}
	refreshEnabled := false
	seen := map[string]bool{}
	for _, client := range configuration.Clients {
		refreshEnabled = refreshEnabled || client.Refresh
		if client.EvidenceScope != "" && !seen[client.EvidenceScope] {
			scopes = append(scopes, client.EvidenceScope)
			seen[client.EvidenceScope] = true
		}
	}
	if refreshEnabled {
		scopes = append(scopes, "offline_access")
	}
	options := []op.Option{
		// MemberID has no legacy opaque ciphertext requiring unauthenticated fallback.
		op.WithCrypto(op.NewAES256GCMCrypto(key, "")),
		op.WithCORSOptions(&cors.Options{AllowedOrigins: []string{configuration.Issuer}, AllowedMethods: []string{"GET", "POST"}, AllowedHeaders: []string{"Authorization", "Content-Type"}}),
		op.WithCustomAuthEndpoint(op.NewEndpoint("/oauth/authorize")), op.WithCustomUserinfoEndpoint(op.NewEndpoint("/oauth/userinfo")),
		op.WithCustomRevocationEndpoint(op.NewEndpoint("/oauth/revoke")), op.WithCustomEndSessionEndpoint(op.NewEndpoint("/oauth/logout")),
		op.WithCustomKeysEndpoint(op.NewEndpoint("/.well-known/jwks.json")),
	}
	if configuration.AllowLoopbackHTTP {
		options = append(options, op.WithAllowInsecure())
	}
	provider, err := op.NewProvider(&op.Config{CryptoKey: key, CodeMethodS256: true, GrantTypeRefreshToken: refreshEnabled, SupportedScopes: scopes, SupportedClaims: []string{"iss", "sub", "aud", "exp", "iat", "auth_time", "nonce", "amr", "at_hash", "c_hash", "client_id", "azp", "sid", "name", "preferred_username", "phone_number", "phone_number_verified"}, DefaultLogoutRedirectURI: configuration.Issuer + "/signed-out"}, service.storage, op.StaticIssuer(configuration.Issuer), options...)
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
	// Preserve Origin on same-origin form POSTs without sending cross-origin referrers.
	w.Header().Set("Referrer-Policy", "same-origin")
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
	if r.URL.Path == "/oauth/token" || r.URL.Path == "/oauth/introspect" || r.URL.Path == "/oauth/revoke" {
		if r.Method != http.MethodPost {
			w.Header().Set("Allow", "POST")
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}
		mediaType, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
		if err != nil || mediaType != "application/x-www-form-urlencoded" || r.URL.RawQuery != "" {
			op.RequestError(w, r, oidc.ErrInvalidRequest().WithDescription("Use a form-encoded POST body"), nil)
			return
		}
		if _, _, ok := r.BasicAuth(); !ok {
			w.Header().Set("WWW-Authenticate", `Basic realm="MemberID"`)
			op.RequestError(w, r, oidc.ErrInvalidClient().WithDescription("client_secret_basic is required"), nil)
			return
		}
		if r.Form.Has("client_secret") || r.Form.Has("client_assertion") {
			op.RequestError(w, r, oidc.ErrInvalidRequest().WithDescription("Use one registered client authentication method"), nil)
			return
		}
	}
	if r.URL.Path == "/oauth/revoke" {
		if r.Form.Get("token") == "" {
			op.RequestError(w, r, oidc.ErrInvalidRequest().WithDescription("token is required"), nil)
			return
		}
		// A hint must not prevent lookup of another supported token type (RFC 7009).
		r.Form.Del("token_type_hint")
		r.PostForm.Del("token_type_hint")
	}
	browser := service.cookieValue(r, "browser")
	interactive := r.URL.Path == "/account/link/dingtalk" || r.URL.Path == "/login" || r.URL.Path == "/oauth/logout" || strings.HasPrefix(r.URL.Path, "/oauth/authorize")
	if interactive && len(browser) != 43 {
		browser = config.RandomSecret()
		service.cookie(w, "browser", browser, sessionIdleLifetime)
	}
	ctx := context.WithValue(r.Context(), browserKey{}, browser)
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
		if service.protocol.GrantTypeRefreshTokenSupported() {
			metadata.GrantTypesSupported = append(metadata.GrantTypesSupported, oidc.GrantTypeRefreshToken)
		}
		metadata.TokenEndpointAuthMethodsSupported = []oidc.AuthMethod{oidc.AuthMethodBasic}
		metadata.RevocationEndpointAuthMethodsSupported = []oidc.AuthMethod{oidc.AuthMethodBasic}
		metadata.DeviceAuthorizationEndpoint = ""
		op.Discover(w, metadata)
		return
	case "/account/link/phone":
		service.accountPhone(w, r)
		return
	case "/account/link/dingtalk":
		service.accountDingTalk(w, r)
		return
	case "/account/dingtalk/callback":
		service.accountDingTalkCallback(w, r)
		return
	case "/login/dingtalk/callback":
		service.dingTalkCallback(w, r)
		return
	case "/login":
		service.login(w, r)
		return
	case "/oauth/logout":
		service.logout(w, r)
		return
	case "/logout/confirm":
		service.confirmLogout(w, r)
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
	if r.URL.Path == "/oauth/authorize" && r.Form.Get("request_uri") != "" {
		service.rejectAuthorization(w, r, &oidc.Error{ErrorType: "request_uri_not_supported"})
		return
	}
	if r.URL.Path == "/oauth/userinfo" {
		w = userinfoWriter{w}
	}
	service.protocol.ServeHTTP(w, r)
}

func (service *Service) rejectAuthorization(w http.ResponseWriter, r *http.Request, protocolError error) {
	request, err := op.ParseAuthorizeRequest(r, service.protocol.Decoder())
	if err != nil {
		op.AuthRequestError(w, r, nil, err, service.protocol)
		return
	}
	registered, err := service.storage.client(request.ClientID)
	if err != nil {
		op.AuthRequestError(w, r, nil, oidc.ErrInvalidRequest(), service.protocol)
		return
	}
	if err := op.ValidateAuthReqRedirectURI(registered, request.RedirectURI, request.ResponseType); err != nil {
		protocolError = err
	}
	op.AuthRequestError(w, r, request, protocolError, service.protocol)
}

func (service *Service) Cleanup(ctx context.Context) error {
	for _, table := range []string{"account_link_requests", "oidc_access_tokens", "oidc_authorization_requests", "oidc_grants"} {
		if _, err := service.store.Database().Exec(ctx, "DELETE FROM "+table+" WHERE expires_at<$1", service.now()); err != nil {
			return err
		}
	}
	// Expired browser SSO does not end an actively renewed client grant.
	if _, err := service.store.Database().Exec(ctx, "DELETE FROM oidc_sessions s WHERE s.absolute_expires_at<$1 OR (s.expires_at<$1 AND NOT EXISTS(SELECT 1 FROM oidc_grants g WHERE g.session_id=s.id))", service.now()); err != nil {
		return err
	}
	return service.store.CleanupPhoneChallenges(ctx)
}
