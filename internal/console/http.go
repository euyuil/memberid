// Package console serves the personal, organization-scoped management console.
package console

import (
	"context"
	"crypto/subtle"
	"embed"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/euyuil/memberid/internal/config"
	"github.com/euyuil/memberid/internal/consolestate"
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
	management *identity.ManagementService
	sessions   *consolestate.Store
	origin     string
	clientID   string
	party      rp.RelyingParty
	routes     *http.ServeMux
}

type nonceKey struct{}
type sessionKey struct{}
type session struct {
	memberID, grantID string
	csrf, secret      string
}

func (v session) principal() identity.Principal {
	return identity.ManagementPrincipal(v.memberID, v.grantID)
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
		// Resolve supported API routes. Resource authorization is enforced by
		// the operation services using the authenticated principal.
		_, pattern := s.routes.Handler(r)
		if pattern == "" {
			http.NotFound(w, r)
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
	stored, err := s.sessions.Session(r.Context(), v.secret)
	v.memberID, v.grantID, v.csrf = stored.MemberID, stored.GrantID, stored.CSRF
	// The cookie identifies the caller. Resource services resolve current
	// administrator authority once, at the operation's authorization boundary.
	return v, err
}

func (s *Service) login(w http.ResponseWriter, r *http.Request) {
	query, err := url.ParseQuery(r.URL.RawQuery)
	returnTo := query.Get("returnTo")
	if !query.Has("returnTo") {
		returnTo = "/"
	}
	if err != nil || len(query["returnTo"]) > 1 || !validReturnTo(returnTo) {
		problem(w, 400, "invalid_request")
		return
	}
	address, err := s.beginLogin(w, r, consolestate.Login{ReturnTo: returnTo})
	if err != nil {
		problem(w, 503, "login_unavailable")
		return
	}
	http.Redirect(w, r, address, http.StatusSeeOther)
}

func (s *Service) beginLogin(w http.ResponseWriter, r *http.Request, login consolestate.Login, options ...oauth2.AuthCodeOption) (string, error) {
	state, browser := config.RandomSecret(), config.RandomSecret()
	login.Nonce, login.Verifier = config.RandomSecret(), oauth2.GenerateVerifier()
	if err := s.sessions.BeginLogin(r.Context(), state, browser, login); err != nil {
		return "", err
	}
	s.cookie(w, "login", browser, 300)
	options = append(options, oauth2.S256ChallengeOption(login.Verifier), oauth2.SetAuthURLParam("nonce", login.Nonce), oauth2.SetAuthURLParam("max_age", "28800"))
	return s.party.OAuthConfig().AuthCodeURL(state, options...), nil
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
	login, err := s.sessions.ConsumeLogin(r.Context(), state, browser)
	verifier, nonce, returnTo := login.Verifier, login.Nonce, login.ReturnTo
	if err != nil {
		problem(w, 400, "invalid_callback")
		return
	}
	s.cookie(w, "login", "", -1)
	failure := "login_failed"
	var source session
	if login.SwitchMemberID != "" {
		failure = "identity_switch_failed"
		if config.SecretHash(s.cookieValue(r, "session")) != login.SourceSessionHash {
			loginFailure(w, r, returnTo, failure)
			return
		}
		source, err = s.session(r)
		if err != nil {
			loginFailure(w, r, returnTo, failure)
			return
		}
	}
	if q.Get("error") != "" || q.Get("code") == "" {
		loginFailure(w, r, returnTo, failure)
		return
	}
	tokens, err := rp.CodeExchange[*oidc.IDTokenClaims](context.WithValue(r.Context(), nonceKey{}, nonce), q.Get("code"), s.party, rp.WithCodeVerifier(verifier))
	if err != nil {
		loginFailure(w, r, returnTo, failure)
		return
	}
	claims := tokens.IDTokenClaims
	if login.SwitchMemberID != "" && claims.Subject != login.SwitchMemberID {
		loginFailure(w, r, returnTo, failure)
		return
	}
	// CodeExchange verifies the signed ID Token and its at_hash. Require that
	// binding before using the access token's identifier to select the exact grant.
	var access oidc.AccessTokenClaims
	if claims.AccessTokenHash == "" {
		loginFailure(w, r, returnTo, failure)
		return
	}
	if _, err = oidc.ParseToken(tokens.AccessToken, &access); err != nil {
		loginFailure(w, r, returnTo, failure)
		return
	}
	grantID, err := s.sessions.Grant(r.Context(), claims.SessionID, s.clientID, claims.Subject, access.JWTID)
	if err != nil {
		loginFailure(w, r, returnTo, failure)
		return
	}
	if login.SwitchMemberID != "" {
		if err := s.management.CheckConsoleIdentity(r.Context(), source.principal(), claims.Subject, grantID); err != nil {
			loginFailure(w, r, returnTo, failure)
			return
		}
	} else if _, err = s.management.Actor(r.Context(), claims.Subject, grantID); err != nil {
		loginFailure(w, r, returnTo, "not_administrator")
		return
	}
	absolute := claims.AuthTime.AsTime().Add(8 * time.Hour)
	if !absolute.After(time.Now()) {
		loginFailure(w, r, returnTo, failure)
		return
	}
	secret, csrf := config.RandomSecret(), config.RandomSecret()
	next := consolestate.Session{MemberID: claims.Subject, GrantID: grantID, CSRF: csrf}
	if login.SwitchMemberID != "" {
		err = s.sessions.SwitchSession(r.Context(), source.secret, secret, next, absolute)
	} else {
		err = s.sessions.CreateSession(r.Context(), secret, next, absolute)
	}
	if err != nil {
		if login.SwitchMemberID != "" {
			loginFailure(w, r, returnTo, failure)
		} else {
			problem(w, 503, "login_unavailable")
		}
		return
	}
	// Rotate the browser's console session without retaining bearer tokens.
	if old := s.cookieValue(r, "session"); old != "" && login.SwitchMemberID == "" {
		_ = s.sessions.DeleteSession(r.Context(), old)
	}
	s.cookie(w, "session", secret, int(time.Until(absolute).Seconds()))
	if login.SwitchMemberID != "" {
		returnTo = "/"
	}
	http.Redirect(w, r, returnTo, 303)
}

func (s *Service) logout(w http.ResponseWriter, r *http.Request) {
	v := r.Context().Value(sessionKey{}).(session)
	if _, err := s.management.Actor(r.Context(), v.memberID, v.grantID); err != nil {
		respond(w, nil, err)
		return
	}
	err := s.sessions.DeleteSession(r.Context(), v.secret)
	s.cookie(w, "session", "", -1)
	respond(w, map[string]bool{"signedOut": true}, err)
}
func (s *Service) organizations(w http.ResponseWriter, r *http.Request) {
	v, e := s.management.Organizations(r.Context(), r.Context().Value(sessionKey{}).(session).principal(), r.URL.Query().Get("after"), 50)
	respond(w, v, e)
}
func memberDirectoryFilter(q url.Values) identity.MemberDirectoryFilter {
	return identity.MemberDirectoryFilter{
		Query:         q.Get("q"),
		Status:        q.Get("status"),
		Administrator: q.Get("administrator"),
	}
}
func (s *Service) allOrganizationMembers(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	page, err := s.management.MemberDirectory(r.Context(), r.Context().Value(sessionKey{}).(session).principal(), q.Get("after"), 50, memberDirectoryFilter(q))
	respond(w, page, err)
}
func (s *Service) members(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	page, err := s.management.Members(r.Context(), r.Context().Value(sessionKey{}).(session).principal(), r.PathValue("organizationId"), q.Get("after"), 50, memberDirectoryFilter(q))
	respond(w, page, err)
}
func (s *Service) member(w http.ResponseWriter, r *http.Request) {
	detail, err := s.management.Member(r.Context(), r.Context().Value(sessionKey{}).(session).principal(), r.PathValue("organizationId"), r.PathValue("memberId"))
	respond(w, detail, err)
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
	v, e := s.management.Manage(r.Context(), r.Context().Value(sessionKey{}).(session).principal(), action, org, id, change)
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
	e := s.management.SetAdministrator(r.Context(), r.Context().Value(sessionKey{}).(session).principal(), r.PathValue("organizationId"), r.PathValue("memberId"), *v.Enabled)
	respond(w, map[string]bool{"enabled": *v.Enabled}, e)
}
func (s *Service) createMemberPassword(w http.ResponseWriter, r *http.Request) {
	var input struct {
		Username *string `json:"username"`
	}
	if !management.DecodeRequest(w, r, &input) {
		return
	}
	if input.Username == nil {
		problem(w, 400, "invalid_request")
		return
	}
	s.generateMemberPassword(w, r, input.Username)
}
func (s *Service) resetMemberPassword(w http.ResponseWriter, r *http.Request) {
	var input struct{}
	if !management.DecodeRequest(w, r, &input) {
		return
	}
	s.generateMemberPassword(w, r, nil)
}
func (s *Service) renameMemberPassword(w http.ResponseWriter, r *http.Request) {
	var input struct {
		ExpectedUsername string `json:"expectedUsername"`
		Username         string `json:"username"`
	}
	if !management.DecodeRequest(w, r, &input) {
		return
	}
	principal := r.Context().Value(sessionKey{}).(session).principal()
	err := s.management.RenameMemberPassword(r.Context(), principal, r.PathValue("organizationId"), r.PathValue("memberId"), input.ExpectedUsername, input.Username)
	respond(w, map[string]string{"username": input.Username}, err)
}
func (s *Service) generateMemberPassword(w http.ResponseWriter, r *http.Request, username *string) {
	value, err := s.management.GenerateMemberPassword(r.Context(), r.Context().Value(sessionKey{}).(session).principal(), r.PathValue("organizationId"), r.PathValue("memberId"), username)
	respond(w, value, err)
}
func (s *Service) events(w http.ResponseWriter, r *http.Request) {
	v := r.Context().Value(sessionKey{}).(session)
	q := r.URL.Query()
	org := q.Get("organizationId")
	before := int64(0)
	if q.Get("before") != "" {
		v, e := strconv.ParseInt(q.Get("before"), 10, 64)
		if e != nil || v <= 0 {
			problem(w, 400, "invalid_request")
			return
		}
		before = v
	}
	items, err := s.management.History(r.Context(), v.principal(), org, q.Get("memberId"), before)
	respond(w, map[string]any{"items": items}, err)
}

func (s *Service) putMemberEmail(w http.ResponseWriter, r *http.Request) {
	input, ok := management.DecodeMemberEmail(w, r)
	if !ok {
		return
	}
	value, err := s.management.PutMemberEmail(r.Context(), r.Context().Value(sessionKey{}).(session).principal(), r.PathValue("organizationId"), r.PathValue("memberId"), input)
	respond(w, value, err)
}

func problem(w http.ResponseWriter, status int, code string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": code})
}
func respond(w http.ResponseWriter, value any, err error) {
	if err != nil {
		switch {
		case errors.Is(err, identity.ErrManagementSession):
			problem(w, 401, "sign_in_required")
		case errors.Is(err, identity.ErrForbidden), errors.Is(err, identity.ErrIneligible):
			problem(w, 403, "forbidden")
		case errors.Is(err, identity.ErrLastAdministrator):
			problem(w, 409, "last_administrator")
		case errors.Is(err, identity.ErrNotFound):
			problem(w, 404, "not_found")
		case errors.Is(err, identity.ErrProviderUnavailable):
			problem(w, 503, "provider_unavailable")
		case errors.Is(err, identity.ErrInvalid):
			problem(w, 400, "invalid_request")
		case errors.Is(err, identity.ErrPasswordUsernameTaken):
			problem(w, 409, "username_taken")
		case errors.Is(err, identity.ErrMemberEmailTaken):
			problem(w, 409, "email_taken")
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
