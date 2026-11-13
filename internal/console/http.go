// Package console serves the personal, organization-scoped management console.
package console

import (
	"context"
	"crypto/subtle"
	"embed"
	"encoding/json"
	"errors"
	"io/fs"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/euyuil/memberid/internal/config"
	"github.com/euyuil/memberid/internal/identity"
	"github.com/euyuil/memberid/internal/management"
	"github.com/zitadel/oidc/v3/pkg/client/rp"
	"github.com/zitadel/oidc/v3/pkg/oidc"
	"golang.org/x/oauth2"
)

//go:embed all:static
var assets embed.FS

// AssetsReady lets the executable reject an incomplete source-only console build.
func AssetsReady() bool {
	_, err := assets.ReadFile("static/index.html")
	return err == nil
}

type Settings struct {
	Origin           string `json:"origin"`
	ClientID         string `json:"clientId"`
	ClientSecretFile string `json:"clientSecretFile"`
}

type Service struct {
	store    *identity.Store
	origin   string
	clientID string
	party    rp.RelyingParty
	routes   *http.ServeMux
}

type nonceKey struct{}
type sessionKey struct{}
type session struct {
	actor  identity.ManagementActor
	csrf   string
	secret string
}

func New(ctx context.Context, store *identity.Store, installation *config.Loaded, settings Settings, secret string) (*Service, error) {
	u, err := url.Parse(settings.Origin)
	if err != nil || u.Host == "" || u.User != nil || u.Path != "" || u.RawQuery != "" || u.Fragment != "" || u.ForceQuery {
		return nil, errors.New("console origin must be an exact HTTPS origin")
	}
	if u.Scheme != "https" && !(installation.AllowLoopbackHTTP && u.Scheme == "http" && net.ParseIP(u.Hostname()).IsLoopback()) {
		return nil, errors.New("console HTTP requires explicit loopback development configuration")
	}
	registered := false
	for _, c := range installation.Clients {
		if c.ID == settings.ClientID && c.SubjectKind == "member" && c.OrganizationID == "" && c.SecretSHA256 == config.SecretHash(secret) {
			for _, redirect := range c.RedirectURIs {
				if redirect == settings.Origin+"/auth/callback" {
					registered = true
				}
			}
		}
	}
	if !registered {
		return nil, errors.New("console requires its own registered all-organization Member client and exact callback")
	}
	party, err := rp.NewRelyingPartyOIDC(ctx, installation.Issuer, settings.ClientID, secret, settings.Origin+"/auth/callback", []string{"openid", "profile"}, rp.WithHTTPClient(&http.Client{Timeout: 15 * time.Second}), rp.WithAuthStyle(oauth2.AuthStyleInHeader), rp.WithVerifierOpts(rp.WithNonce(func(ctx context.Context) string { value, _ := ctx.Value(nonceKey{}).(string); return value }), rp.WithSupportedSigningAlgorithms("RS256")))
	if err != nil {
		return nil, err
	}
	s := &Service{store: store, origin: settings.Origin, clientID: settings.ClientID, party: party, routes: http.NewServeMux()}
	s.routes.HandleFunc("GET /auth/login", s.login)
	s.routes.HandleFunc("GET /auth/callback", s.callback)
	s.routes.HandleFunc("POST /api/logout", s.logout)
	s.routes.HandleFunc("GET /api/session", func(w http.ResponseWriter, r *http.Request) {
		v := r.Context().Value(sessionKey{}).(session)
		respond(w, map[string]any{"actor": v.actor, "csrf": v.csrf}, nil)
	})
	s.routes.HandleFunc("GET /api/organizations", s.organizations)
	s.routes.HandleFunc("POST /api/organizations", s.mutate)
	s.routes.HandleFunc("GET /api/organizations/{organizationId}", func(w http.ResponseWriter, r *http.Request) {
		v, e := s.store.Organization(r.Context(), r.PathValue("organizationId"))
		respond(w, v, e)
	})
	s.routes.HandleFunc("PATCH /api/organizations/{organizationId}", s.mutate)
	s.routes.HandleFunc("GET /api/organizations/{organizationId}/members", s.members)
	s.routes.HandleFunc("POST /api/organizations/{organizationId}/members", s.mutate)
	s.routes.HandleFunc("GET /api/organizations/{organizationId}/members/{memberId}", s.member)
	s.routes.HandleFunc("PATCH /api/organizations/{organizationId}/members/{memberId}", s.mutate)
	s.routes.HandleFunc("PUT /api/organizations/{organizationId}/members/{memberId}/administrator", s.administrator)
	s.routes.HandleFunc("GET /api/events", s.events)
	static, _ := fs.Sub(assets, "static")
	s.routes.Handle("GET /", http.FileServer(http.FS(static)))
	return s, nil
}

func (s *Service) cookieName(kind string) string {
	if strings.HasPrefix(s.origin, "https:") {
		return "__Host-memberid_console_" + kind
	}
	return "memberid_console_" + kind
}
func (s *Service) cookie(w http.ResponseWriter, kind, value string, maxAge int) {
	http.SetCookie(w, &http.Cookie{Name: s.cookieName(kind), Value: value, Path: "/", Secure: strings.HasPrefix(s.origin, "https:"), HttpOnly: true, SameSite: http.SameSiteLaxMode, MaxAge: maxAge})
}
func (s *Service) cookieValue(r *http.Request, kind string) string {
	v := r.CookiesNamed(s.cookieName(kind))
	if len(v) != 1 {
		return ""
	}
	return v[0].Value
}

func (s *Service) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("X-Frame-Options", "DENY")
	w.Header().Set("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'")
	r.Body = http.MaxBytesReader(w, r.Body, 32<<10)
	if strings.HasPrefix(r.URL.Path, "/api/") {
		v, err := s.session(r)
		if err != nil {
			problem(w, 401, "sign_in_required")
			return
		}
		if r.Method != http.MethodGet && (r.Header.Get("Origin") != s.origin || subtle.ConstantTimeCompare([]byte(r.Header.Get("X-CSRF-Token")), []byte(v.csrf)) != 1) {
			problem(w, 403, "invalid_csrf")
			return
		}
		// Resolve the route before applying organization scope. Query/body values
		// never establish the actor or widen an organization administrator's scope.
		_, pattern := s.routes.Handler(r)
		if pattern == "" {
			http.NotFound(w, r)
			return
		}
		parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
		if len(parts) >= 3 && parts[1] == "organizations" && !v.actor.Platform && parts[2] != v.actor.OrganizationID {
			problem(w, 403, "forbidden")
			return
		}
		r = r.WithContext(context.WithValue(r.Context(), sessionKey{}, v))
	}
	s.routes.ServeHTTP(w, r)
}

func (s *Service) session(r *http.Request) (session, error) {
	v := session{secret: s.cookieValue(r, "session")}
	if len(v.secret) != 43 {
		return v, identity.ErrForbidden
	}
	var memberID, grantID string
	err := s.store.Database().QueryRow(r.Context(), `UPDATE console_sessions SET expires_at=LEAST(absolute_expires_at,clock_timestamp()+interval '30 minutes')
 WHERE secret_hash=$1 AND expires_at>clock_timestamp() AND absolute_expires_at>clock_timestamp() RETURNING member_id,grant_id,csrf`, config.SecretHash(v.secret)).Scan(&memberID, &grantID, &v.csrf)
	if err != nil {
		return v, err
	}
	v.actor, err = s.store.ManagementActor(r.Context(), memberID, grantID)
	return v, err
}

func (s *Service) login(w http.ResponseWriter, r *http.Request) {
	state, browser, nonce, verifier := config.RandomSecret(), config.RandomSecret(), config.RandomSecret(), oauth2.GenerateVerifier()
	_, err := s.store.Database().Exec(r.Context(), "DELETE FROM console_logins WHERE expires_at<clock_timestamp()")
	if err == nil {
		_, err = s.store.Database().Exec(r.Context(), "DELETE FROM console_sessions WHERE expires_at<clock_timestamp() OR absolute_expires_at<clock_timestamp()")
	}
	if err == nil {
		_, err = s.store.Database().Exec(r.Context(), "INSERT INTO console_logins(state_hash,browser_hash,verifier,nonce,expires_at) VALUES($1,$2,$3,$4,clock_timestamp()+interval '5 minutes')", config.SecretHash(state), config.SecretHash(browser), verifier, nonce)
	}
	if err != nil {
		problem(w, 503, "login_unavailable")
		return
	}
	s.cookie(w, "login", browser, 300)
	http.Redirect(w, r, s.party.OAuthConfig().AuthCodeURL(state, oauth2.S256ChallengeOption(verifier), oauth2.SetAuthURLParam("nonce", nonce), oauth2.SetAuthURLParam("max_age", "28800")), http.StatusSeeOther)
}

func (s *Service) callback(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	for _, v := range q {
		if len(v) != 1 {
			problem(w, 400, "invalid_callback")
			return
		}
	}
	state, browser := q.Get("state"), s.cookieValue(r, "login")
	if len(state) != 43 || len(browser) != 43 {
		problem(w, 400, "invalid_callback")
		return
	}
	var verifier, nonce string
	err := s.store.Database().QueryRow(r.Context(), "DELETE FROM console_logins WHERE state_hash=$1 AND browser_hash=$2 AND expires_at>clock_timestamp() RETURNING verifier,nonce", config.SecretHash(state), config.SecretHash(browser)).Scan(&verifier, &nonce)
	if err != nil {
		problem(w, 400, "invalid_callback")
		return
	}
	s.cookie(w, "login", "", -1)
	if q.Get("error") != "" || q.Get("code") == "" {
		http.Redirect(w, r, "/?error=login_failed", 303)
		return
	}
	tokens, err := rp.CodeExchange[*oidc.IDTokenClaims](context.WithValue(r.Context(), nonceKey{}, nonce), q.Get("code"), s.party, rp.WithCodeVerifier(verifier))
	if err != nil {
		http.Redirect(w, r, "/?error=login_failed", 303)
		return
	}
	claims := tokens.IDTokenClaims
	// CodeExchange verifies the signed ID Token and its at_hash. Require that
	// binding before using the access token's identifier to select the exact grant.
	var access oidc.AccessTokenClaims
	if claims.AccessTokenHash == "" {
		http.Redirect(w, r, "/?error=login_failed", 303)
		return
	}
	if _, err = oidc.ParseToken(tokens.AccessToken, &access); err != nil {
		http.Redirect(w, r, "/?error=login_failed", 303)
		return
	}
	var grantID string
	err = s.store.Database().QueryRow(r.Context(), `SELECT g.id FROM oidc_grants g JOIN oidc_access_tokens a ON a.grant_id=g.id
 WHERE a.id=$4 AND a.expires_at>clock_timestamp() AND g.session_id=$1 AND g.client_id=$2
 AND g.data->>'memberId'=$3 AND g.revoked_at IS NULL AND g.expires_at>clock_timestamp()`, claims.SessionID, s.clientID, claims.Subject, access.JWTID).Scan(&grantID)
	if err != nil {
		http.Redirect(w, r, "/?error=login_failed", 303)
		return
	}
	if _, err = s.store.ManagementActor(r.Context(), claims.Subject, grantID); err != nil {
		http.Redirect(w, r, "/?error=not_administrator", 303)
		return
	}
	absolute := claims.AuthTime.AsTime().Add(8 * time.Hour)
	if !absolute.After(time.Now()) {
		http.Redirect(w, r, "/?error=login_failed", 303)
		return
	}
	secret, csrf := config.RandomSecret(), config.RandomSecret()
	_, err = s.store.Database().Exec(r.Context(), `INSERT INTO console_sessions(secret_hash,grant_id,member_id,csrf,expires_at,absolute_expires_at) VALUES($1,$2,$3,$4,LEAST($5,clock_timestamp()+interval '30 minutes'),$5)`, config.SecretHash(secret), grantID, claims.Subject, csrf, absolute)
	if err != nil {
		problem(w, 503, "login_unavailable")
		return
	}
	// Rotate the browser's console session without retaining bearer tokens.
	if old := s.cookieValue(r, "session"); old != "" {
		_, _ = s.store.Database().Exec(r.Context(), "DELETE FROM console_sessions WHERE secret_hash=$1", config.SecretHash(old))
	}
	s.cookie(w, "session", secret, int(time.Until(absolute).Seconds()))
	http.Redirect(w, r, "/", 303)
}

func (s *Service) logout(w http.ResponseWriter, r *http.Request) {
	v := r.Context().Value(sessionKey{}).(session)
	_, err := s.store.Database().Exec(r.Context(), "DELETE FROM console_sessions WHERE secret_hash=$1", config.SecretHash(v.secret))
	s.cookie(w, "session", "", -1)
	respond(w, map[string]bool{"signedOut": true}, err)
}
func (s *Service) organizations(w http.ResponseWriter, r *http.Request) {
	a := r.Context().Value(sessionKey{}).(session).actor
	if !a.Platform {
		v, e := s.store.Organization(r.Context(), a.OrganizationID)
		respond(w, identity.Page[identity.Organization]{Items: []identity.Organization{v}}, e)
		return
	}
	v, e := s.store.Organizations(r.Context(), r.URL.Query().Get("after"), 50)
	respond(w, v, e)
}
func (s *Service) members(w http.ResponseWriter, r *http.Request) {
	org := r.PathValue("organizationId")
	v, e := s.store.Members(r.Context(), org, r.URL.Query().Get("after"), 50)
	if e != nil {
		respond(w, nil, e)
		return
	}
	ids, e := s.store.AdministratorIDs(r.Context(), org)
	respond(w, map[string]any{"items": v.Items, "nextAfter": v.NextAfter, "administratorIds": ids}, e)
}
func (s *Service) member(w http.ResponseWriter, r *http.Request) {
	org, id := r.PathValue("organizationId"), r.PathValue("memberId")
	v, e := s.store.Member(r.Context(), org, id)
	if e != nil {
		respond(w, nil, e)
		return
	}
	bindings, e := s.store.Bindings(r.Context(), org, id)
	if e != nil {
		respond(w, nil, e)
		return
	}
	ids, e := s.store.AdministratorIDs(r.Context(), org)
	respond(w, map[string]any{"member": v, "bindings": bindings, "administratorIds": ids}, e)
}
func (s *Service) mutate(w http.ResponseWriter, r *http.Request) {
	org, id := r.PathValue("organizationId"), r.PathValue("memberId")
	var change identity.ManagementChange
	// Distinct request shapes prevent silently ignored or privilege-bearing fields.
	action := ""
	switch {
	case org == "":
		var v struct {
			Name *string `json:"name"`
		}
		if !management.DecodeRequest(w, r, &v) {
			return
		}
		change.Name = v.Name
		action = "organization.create"
	case id != "":
		var v identity.MemberChange
		if !management.DecodeRequest(w, r, &v) {
			return
		}
		change.DisplayName = v.DisplayName
		change.ManualBlocked = v.ManualBlocked
		action = "member.update"
	case strings.HasSuffix(r.URL.Path, "/members"):
		var v struct {
			DisplayName *string `json:"displayName"`
		}
		if !management.DecodeRequest(w, r, &v) {
			return
		}
		change.DisplayName = v.DisplayName
		action = "member.create"
	default:
		var v identity.OrganizationChange
		if !management.DecodeRequest(w, r, &v) {
			return
		}
		change.Name = v.Name
		change.Status = v.Status
		action = "organization.update"
	}
	v, e := s.store.Manage(r.Context(), r.Context().Value(sessionKey{}).(session).actor, action, org, id, change)
	respond(w, v, e)
}
func (s *Service) administrator(w http.ResponseWriter, r *http.Request) {
	var v struct {
		Enabled *bool `json:"enabled"`
	}
	if !management.DecodeRequest(w, r, &v) {
		return
	}
	if v.Enabled == nil {
		problem(w, 400, "invalid_request")
		return
	}
	e := s.store.SetAdministrator(r.Context(), r.Context().Value(sessionKey{}).(session).actor, r.PathValue("organizationId"), r.PathValue("memberId"), *v.Enabled)
	respond(w, map[string]bool{"enabled": *v.Enabled}, e)
}
func (s *Service) events(w http.ResponseWriter, r *http.Request) {
	a := r.Context().Value(sessionKey{}).(session).actor
	q := r.URL.Query()
	org := q.Get("organizationId")
	if !a.Platform {
		if org != "" && org != a.OrganizationID {
			problem(w, 403, "forbidden")
			return
		}
		org = a.OrganizationID
	}
	before := int64(0)
	if q.Get("before") != "" {
		v, e := strconv.ParseInt(q.Get("before"), 10, 64)
		if e != nil || v <= 0 {
			problem(w, 400, "invalid_request")
			return
		}
		before = v
	}
	v, e := s.store.ManagementEvents(r.Context(), org, q.Get("memberId"), before)
	respond(w, map[string]any{"items": v}, e)
}
func problem(w http.ResponseWriter, status int, code string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": code})
}
func respond(w http.ResponseWriter, value any, err error) {
	if err != nil {
		switch {
		case errors.Is(err, identity.ErrForbidden), errors.Is(err, identity.ErrIneligible):
			problem(w, 403, "forbidden")
		case errors.Is(err, identity.ErrLastAdministrator):
			problem(w, 409, "last_administrator")
		case errors.Is(err, identity.ErrNotFound):
			problem(w, 404, "not_found")
		case errors.Is(err, identity.ErrInvalid):
			problem(w, 400, "invalid_request")
		case errors.Is(err, identity.ErrConflict):
			problem(w, 409, "conflict")
		default:
			problem(w, 500, "internal_error")
		}
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(value)
}
