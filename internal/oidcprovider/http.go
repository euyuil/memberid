package oidcprovider

import (
	"context"
	"encoding/base64"
	"errors"
	"mime"
	"net/http"
	"strings"
	"time"

	"github.com/rs/cors"
	"github.com/zhizhun-tech/memberid/internal/authevent"
	"github.com/zhizhun-tech/memberid/internal/config"
	"github.com/zhizhun-tech/memberid/internal/identity"
	"github.com/zhizhun-tech/memberid/internal/samlprovider"
	"github.com/zitadel/oidc/v3/pkg/oidc"
	"github.com/zitadel/oidc/v3/pkg/op"
)

type Service struct {
	saml          *samlprovider.Provider
	events        *authevent.Recorder
	configuration *config.Loaded
	store         *identity.Store
	phone         *identity.PhoneVerifier
	dingtalk      *identity.DingTalkVerifier
	feishu        *identity.FeishuApplications
	directory     *identity.DingTalkDirectory
	protocol      *op.Provider
	storage       *storage
	now           func() time.Time
	passwordWork  chan struct{}
	directStarts  directLoginQuota
}

type browserKey struct{}

func New(configuration *config.Loaded, store *identity.Store, phone *identity.PhoneVerifier, dingtalk *identity.DingTalkVerifier, directory *identity.DingTalkDirectory, feishu *identity.FeishuApplications) (*Service, error) {
	if configuration == nil || store == nil || dingtalk != nil && directory == nil || configuration.SigningKey == nil || len(configuration.PublicKeys) == 0 {
		return nil, errors.New("OIDC requires a configured store and signing keys")
	}
	if err := configuration.Installation.Validate(); err != nil {
		return nil, err
	}
	if err := configuration.Secrets.Validate(); err != nil {
		return nil, err
	}
	service := &Service{configuration: configuration, store: store, phone: phone, dingtalk: dingtalk, feishu: feishu, directory: directory, now: time.Now, passwordWork: make(chan struct{}, 4)}
	service.storage = &storage{service: service}
	if configuration.SAML != nil && configuration.SAML.Enabled {
		var err error
		service.saml, err = samlprovider.New(configuration.Issuer, configuration.SAMLSigning)
		if err != nil {
			return nil, err
		}
	}
	var key [32]byte
	decoded, _ := base64.StdEncoding.DecodeString(configuration.Secrets.ProtocolKey)
	copy(key[:], decoded)
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
	provider, err := op.NewProvider(&op.Config{CryptoKey: key, CodeMethodS256: true, GrantTypeRefreshToken: true, SupportedScopes: []string{"openid", "profile", "email", "phone", "offline_access"}, SupportedClaims: []string{"iss", "sub", "aud", "exp", "iat", "auth_time", "nonce", "amr", "at_hash", "c_hash", "client_id", "azp", "sid", "name", "preferred_username", "phone_number", "phone_number_verified"}, DefaultLogoutRedirectURI: configuration.Issuer + "/signed-out"}, service.storage, op.StaticIssuer(configuration.Issuer), options...)
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

type clientAuthWriter struct{ http.ResponseWriter }

func (w clientAuthWriter) WriteHeader(status int) {
	if status == http.StatusUnauthorized {
		w.Header().Set("WWW-Authenticate", `Basic realm="MemberID"`)
	}
	w.ResponseWriter.WriteHeader(status)
}

func (service *Service) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	r = r.WithContext(authevent.RequestContext(r.Context()))
	w.Header().Set("Cache-Control", "no-store")
	// Preserve Origin on same-origin form POSTs without sending cross-origin referrers.
	w.Header().Set("Referrer-Policy", "same-origin")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("X-Frame-Options", "DENY")
	clientEndpoint := r.URL.Path == "/oauth/token" || r.URL.Path == "/oauth/introspect" || r.URL.Path == "/oauth/revoke"
	invalidRequest := func(description string) {
		if clientEndpoint {
			op.RequestError(w, r, oidc.ErrInvalidRequest().WithDescription("%s", description), nil)
			return
		}
		http.Error(w, description, http.StatusBadRequest)
	}
	const formLimit = 32 << 10
	limit := formLimit
	if r.URL.Path == "/login" || strings.HasPrefix(r.URL.Path, "/login/") {
		// JSON escaping and JWE encoding can expand a valid authorization request.
		limit = 512 << 10
	}
	if len(r.URL.RawQuery) > limit {
		invalidRequest("Request is too large")
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, int64(limit))
	if err := r.ParseForm(); err != nil {
		invalidRequest("Invalid request")
		return
	}
	formSize := 0
	for key, values := range r.Form {
		if len(values) != 1 {
			invalidRequest("Repeated parameter")
			return
		}
		if limit > formLimit && !(key == "request" && strings.HasPrefix(values[0], oidcLoginPrefix)) {
			formSize += len(key) + len(values[0])
		}
	}
	if formSize > formLimit {
		invalidRequest("Request is too large")
		return
	}
	if clientEndpoint {
		w = clientAuthWriter{w}
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
	interactive := r.URL.Path == "/account" || (r.URL.Path == accountPath || r.URL.Path == feishuAccountPath) || r.URL.Path == "/login" || strings.HasPrefix(r.URL.Path, "/login/org_") || r.URL.Path == "/oauth/logout" || strings.HasPrefix(r.URL.Path, "/oauth/authorize")
	if interactive && len(browser) != 43 {
		browser = config.RandomSecret()
		service.cookie(w, "browser", browser, sessionIdleLifetime)
	}
	ctx := context.WithValue(r.Context(), browserKey{}, browser)
	if r.URL.Path == "/oauth/token" {
		ctx = context.WithValue(ctx, authenticatedClientKey{}, &authenticatedClient{})
	}
	r = r.WithContext(ctx)
	switch r.URL.Path {
	case samlprovider.MetadataPath:
		if service.saml == nil {
			http.NotFound(w, r)
		} else {
			service.saml.Metadata(w, r)
		}
		return
	case samlprovider.SSOPath:
		service.samlSSO(w, r)
		return
	case "/.well-known/openid-configuration":
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			w.Header().Set("Allow", "GET, HEAD")
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}
		metadata := op.CreateDiscoveryConfig(op.ContextWithIssuer(r.Context(), service.configuration.Issuer), service.protocol, service.storage)
		// The library defaults include flows that this deployment profile does not enable.
		metadata.ResponseTypesSupported = []string{"code"}
		metadata.ResponseModesSupported = []string{"query", "fragment"}
		metadata.GrantTypesSupported = []oidc.GrantType{oidc.GrantTypeCode}
		capabilities, err := service.store.OIDCClientCapabilities(r.Context())
		if err != nil {
			http.Error(w, "OIDC client registry unavailable", http.StatusServiceUnavailable)
			return
		}
		metadata.ScopesSupported = append([]string{"openid", "profile", "email", "phone"}, capabilities.EvidenceScopes...)
		if capabilities.OrganizationScope {
			metadata.ScopesSupported = append(metadata.ScopesSupported, identity.OrganizationScope)
			metadata.ClaimsSupported = append(metadata.ClaimsSupported, "organizationId")
		}
		if capabilities.Refresh {
			metadata.ScopesSupported = append(metadata.ScopesSupported, "offline_access")
			metadata.GrantTypesSupported = append(metadata.GrantTypesSupported, oidc.GrantTypeRefreshToken)
		}
		metadata.TokenEndpointAuthMethodsSupported = []oidc.AuthMethod{oidc.AuthMethodBasic}
		metadata.RevocationEndpointAuthMethodsSupported = []oidc.AuthMethod{oidc.AuthMethodBasic}
		metadata.DeviceAuthorizationEndpoint = ""
		op.Discover(w, metadata)
		return
	case "/account":
		service.accountHome(w, r)
		return
	case "/account/link/phone":
		service.accountPhone(w, r)
		return
	case "/account/link/dingtalk":
		service.accountExternal(w, r, "dingtalk")
		return
	case "/account/dingtalk/callback":
		service.accountExternalCallback(w, r, "dingtalk")
		return
	case feishuAccountPath:
		service.accountExternal(w, r, "feishu")
		return
	case feishuAccountCallbackPath:
		service.accountExternalCallback(w, r, "feishu")
		return
	case feishuCallbackPath:
		service.feishuCallback(w, r)
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
	if strings.HasPrefix(r.URL.Path, "/login/") {
		if slug := strings.TrimPrefix(r.URL.Path, "/login/"); identity.ValidOrganizationSlug(slug) {
			service.organizationSlugLogin(w, r, slug)
			return
		}
		service.login(w, r)
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
	registered, err := service.storage.client(r.Context(), request.ClientID)
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
	for _, table := range []string{"account_link_requests", "oidc_access_tokens", "oidc_grants", "password_attempt_windows"} {
		if _, err := service.store.Database().Exec(ctx, "DELETE FROM "+table+" WHERE expires_at<$1", service.now()); err != nil {
			return err
		}
	}
	// Code issuance shortens expires_at. Keep the unique request ID until
	// every browser-held copy of the original interaction has expired.
	now := service.now()
	if _, err := service.store.Database().Exec(ctx, "DELETE FROM authentication_requests WHERE expires_at<$1 AND (code_hash IS NULL OR expires_at<$2)", now, now.Add(-oidcLoginLifetime)); err != nil {
		return err
	}
	// Expired browser SSO does not end an actively renewed client grant.
	if _, err := service.store.Database().Exec(ctx, "DELETE FROM authentication_sessions s WHERE s.absolute_expires_at<$1 OR (s.expires_at<$1 AND NOT EXISTS(SELECT 1 FROM oidc_grants g WHERE g.session_id=s.id))", service.now()); err != nil {
		return err
	}
	return service.store.CleanupPhoneChallenges(ctx)
}

// SetEventRecorder must be called before serving requests.
func (service *Service) SetEventRecorder(recorder *authevent.Recorder) {
	service.events = recorder
	if service.phone != nil {
		service.phone.SetEventRecorder(recorder)
	}
}
