//go:build integration

package oidcprovider

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"html"
	"io"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/euyuil/memberid/internal/config"
	"github.com/euyuil/memberid/internal/identity"
	"github.com/euyuil/memberid/internal/testdb"
	jose "github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
)

type testSender struct {
	mu   sync.Mutex
	code string
}

func (s *testSender) Send(_ context.Context, _, code string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.code = code
	return nil
}
func (s *testSender) latest() string { s.mu.Lock(); defer s.mu.Unlock(); return s.code }

type fixture struct {
	t                   *testing.T
	server              *httptest.Server
	service             *Service
	store               *identity.Store
	sender              *testSender
	browser             *http.Client
	member, otherMember identity.Member
	secret              string
}
type reply struct {
	status int
	header http.Header
	body   string
}

const callback = "http://127.0.0.1:8484/callback"

func browserClient() *http.Client {
	jar, _ := cookiejar.New(nil)
	return &http.Client{Jar: jar, Timeout: 10 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
}
func newFixture(t *testing.T) *fixture { t.Helper(); return newConfiguredFixture(t, false) }
func newConfiguredFixture(t *testing.T, refreshEnabled bool) *fixture {
	t.Helper()
	database := testdb.Create(t)
	if err := identity.Initialize(t.Context(), database); err != nil {
		t.Fatal(err)
	}
	store, err := identity.Open(t.Context(), database)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(store.Close)
	server := httptest.NewUnstartedServer(nil)
	issuer := "http://" + server.Listener.Addr().String()
	directory := filepath.Join(t.TempDir(), "installation")
	if err := config.Initialize(directory, issuer, true); err != nil {
		t.Fatal(err)
	}
	configuration, err := config.Load(directory)
	if err != nil {
		t.Fatal(err)
	}
	secret := config.RandomSecret()
	organization, err := store.CreateOrganization(t.Context(), "", "Example Team")
	if err != nil {
		t.Fatal(err)
	}
	member, err := store.CreateMember(t.Context(), organization.ID, "", "Example Member")
	if err != nil {
		t.Fatal(err)
	}
	other, err := store.CreateOrganization(t.Context(), "", "Second Team")
	if err != nil {
		t.Fatal(err)
	}
	otherMember, err := store.CreateMember(t.Context(), other.ID, "", "Example Member")
	if err != nil {
		t.Fatal(err)
	}
	factor, err := store.EnsureFactor(t.Context(), "phone", "phone:e164", "+8619900000001")
	if err != nil {
		t.Fatal(err)
	}
	for _, m := range []identity.Member{member, otherMember} {
		if _, err := store.BindFactor(t.Context(), m.OrganizationID, m.ID, factor.ID); err != nil {
			t.Fatal(err)
		}
	}
	configuration.Clients = []config.Client{
		{ID: "example-web", SecretSHA256: config.SecretHash(secret), RedirectURIs: []string{callback}, PostLogoutRedirectURIs: []string{"http://127.0.0.1:8484/signed-out"}, SubjectKind: "member", OrganizationID: organization.ID},
		{ID: "second-web", SecretSHA256: config.SecretHash(secret), RedirectURIs: []string{callback}, SubjectKind: "member", OrganizationID: other.ID, Preauthorized: true},
		{ID: "registration", SecretSHA256: config.SecretHash(secret), RedirectURIs: []string{callback}, SubjectKind: "factor", EvidenceScope: "registration_identity", EvidenceAudience: "https://registration.example.test", Preauthorized: true},
	}
	configuration.Clients[0].Refresh = refreshEnabled
	configuration.Clients[1].Refresh = refreshEnabled
	key, _ := base64.StdEncoding.DecodeString(configuration.Secrets.PhoneCodeKey)
	sender := new(testSender)
	phone, err := identity.NewPhoneVerifier(store, key, sender)
	if err != nil {
		t.Fatal(err)
	}
	service, err := New(configuration, store, phone, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	server.Config.Handler = service
	server.Start()
	t.Cleanup(server.Close)
	return &fixture{t, server, service, store, sender, browserClient(), member, otherMember, secret}
}
func (f *fixture) call(client *http.Client, method, path string, form url.Values, headers map[string]string) reply {
	f.t.Helper()
	if strings.HasPrefix(path, "/") {
		path = f.server.URL + path
	}
	var body io.Reader
	if form != nil {
		body = strings.NewReader(form.Encode())
	}
	request, err := http.NewRequest(method, path, body)
	if err != nil {
		f.t.Fatal(err)
	}
	if form != nil {
		request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	for key, value := range headers {
		request.Header.Set(key, value)
	}
	response, err := client.Do(request)
	if err != nil {
		f.t.Fatal(err)
	}
	defer response.Body.Close()
	data, err := io.ReadAll(response.Body)
	if err != nil {
		f.t.Fatal(err)
	}
	return reply{response.StatusCode, response.Header, string(data)}
}
func (f *fixture) status(r reply, want int) {
	f.t.Helper()
	if r.status != want {
		f.t.Fatalf("HTTP %d, want %d: %s", r.status, want, r.body)
	}
}
func (f *fixture) authorization(client, scopes string, extra url.Values) (reply, string) {
	f.t.Helper()
	verifier := config.RandomSecret()
	digest := sha256.Sum256([]byte(verifier))
	query := url.Values{"client_id": {client}, "redirect_uri": {callback}, "response_type": {"code"}, "scope": {scopes}, "state": {"example-state"}, "nonce": {"example-nonce"}, "code_challenge": {base64.RawURLEncoding.EncodeToString(digest[:])}, "code_challenge_method": {"S256"}}
	for key, value := range extra {
		query[key] = value
	}
	result := f.call(f.browser, "GET", "/oauth/authorize?"+query.Encode(), nil, nil)
	return result, verifier
}
func hidden(t *testing.T, page, name string) string {
	t.Helper()
	match := regexp.MustCompile(`name="` + name + `" value="([^"]+)"`).FindStringSubmatch(page)
	if len(match) != 2 {
		t.Fatalf("missing %s in login page: %s", name, page)
	}
	return html.UnescapeString(match[1])
}
func (f *fixture) submit(page, action string, extra url.Values) reply {
	f.t.Helper()
	form := url.Values{"request": {hidden(f.t, page, "request")}, "csrf": {hidden(f.t, page, "csrf")}, "action": {action}}
	for key, value := range extra {
		form[key] = value
	}
	return f.call(f.browser, "POST", "/login", form, map[string]string{"Origin": f.server.URL})
}
func (f *fixture) loginPage(client, scopes string) (reply, string) {
	f.t.Helper()
	r, verifier := f.authorization(client, scopes, nil)
	f.status(r, 302)
	r = f.call(f.browser, "GET", r.header.Get("Location"), nil, nil)
	f.status(r, 200)
	if r.header.Get("Referrer-Policy") != "same-origin" {
		f.t.Fatal("login policy must preserve same-origin form Origin and suppress cross-origin referrers")
	}
	return r, verifier
}
func (f *fixture) verifyPhone(page reply) reply {
	f.t.Helper()
	r := f.submit(page.body, "send", url.Values{"phone": {"19900000001"}})
	f.status(r, 200)
	r = f.submit(r.body, "verify", url.Values{"code": {f.sender.latest()}})
	f.status(r, 200)
	if !strings.Contains(r.body, "Phone verified") {
		f.t.Fatalf("verification failed: %s", r.body)
	}
	return r
}
func (f *fixture) complete(page reply, member string) string {
	f.t.Helper()
	r := f.submit(page.body, "continue", url.Values{"member": {member}, "consent": {"yes"}})
	f.status(r, 303)
	r = f.call(f.browser, "GET", r.header.Get("Location"), nil, nil)
	f.status(r, 302)
	parsed, err := url.Parse(r.header.Get("Location"))
	if err != nil {
		f.t.Fatal(err)
	}
	if parsed.Scheme+"://"+parsed.Host+parsed.Path != callback || parsed.Query().Get("state") != "example-state" || parsed.Query().Get("code") == "" {
		f.t.Fatalf("unexpected callback: %s", parsed)
	}
	return parsed.Query().Get("code")
}
func (f *fixture) exchange(client, code, verifier string) reply {
	f.t.Helper()
	return f.call(browserClient(), "POST", "/oauth/token", url.Values{"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {callback}, "code_verifier": {verifier}}, map[string]string{"Authorization": "Basic " + base64.StdEncoding.EncodeToString([]byte(client+":"+f.secret))})
}
func jsonObject(t *testing.T, r reply) map[string]any {
	t.Helper()
	value := map[string]any{}
	if err := json.Unmarshal([]byte(r.body), &value); err != nil {
		t.Fatal(err, r.body)
	}
	return value
}
func (f *fixture) tokens() map[string]any {
	f.t.Helper()
	page, verifier := f.loginPage("example-web", "openid profile email phone")
	page = f.verifyPhone(page)
	code := f.complete(page, f.member.ID)
	r := f.exchange("example-web", code, verifier)
	f.status(r, 200)
	return jsonObject(f.t, r)
}
func (f *fixture) userinfo(token string) reply {
	return f.call(browserClient(), "GET", "/oauth/userinfo", nil, map[string]string{"Authorization": "Bearer " + token})
}
func (f *fixture) signedClaims(raw string) map[string]any {
	f.t.Helper()
	parsed, err := jwt.ParseSigned(raw, []jose.SignatureAlgorithm{jose.RS256})
	if err != nil {
		f.t.Fatal(err)
	}
	if len(parsed.Headers) != 1 || parsed.Headers[0].KeyID != f.service.configuration.KeyID {
		f.t.Fatal("wrong signing key")
	}
	claims := map[string]any{}
	if err := parsed.Claims(&f.service.configuration.SigningKey.PublicKey, &claims); err != nil {
		f.t.Fatal(err)
	}
	return claims
}

func TestAuthorizationCodeHTTP(t *testing.T) {
	f := newFixture(t)
	discovery := f.call(f.browser, "GET", "/.well-known/openid-configuration", nil, nil)
	f.status(discovery, 200)
	metadata := jsonObject(t, discovery)
	if metadata["issuer"] != f.server.URL || metadata["authorization_endpoint"] != f.server.URL+"/oauth/authorize" || metadata["token_endpoint"] != f.server.URL+"/oauth/token" {
		t.Fatal("wrong discovery endpoints", metadata)
	}
	for field, want := range map[string]string{"grant_types_supported": "authorization_code", "response_types_supported": "code", "token_endpoint_auth_methods_supported": "client_secret_basic", "revocation_endpoint_auth_methods_supported": "client_secret_basic", "code_challenge_methods_supported": "S256"} {
		values, ok := metadata[field].([]any)
		if !ok || len(values) != 1 || values[0] != want {
			t.Fatalf("incorrect discovery %s: %v", field, metadata[field])
		}
	}
	if metadata["device_authorization_endpoint"] != nil {
		t.Fatal("advertised unavailable device authorization")
	}
	keys := f.call(f.browser, "GET", "/.well-known/jwks.json", nil, nil)
	f.status(keys, 200)
	var keyset jose.JSONWebKeySet
	if err := json.Unmarshal([]byte(keys.body), &keyset); err != nil || len(keyset.Keys) != 1 || !keyset.Keys[0].IsPublic() {
		t.Fatal("invalid public key set")
	}
	tokens := f.tokens()
	if tokens["token_type"] != "Bearer" || tokens["refresh_token"] != nil {
		t.Fatal("unexpected token response")
	}
	id := f.signedClaims(tokens["id_token"].(string))
	access := f.signedClaims(tokens["access_token"].(string))
	audience, ok := id["aud"].([]any)
	if id["iss"] != f.server.URL || id["sub"] != f.member.ID || !ok || len(audience) != 2 || !slices.Contains(audience, any("example-web")) || id["azp"] != "example-web" || id["nonce"] != "example-nonce" || id["sid"] == nil || id["at_hash"] == nil || id["auth_time"] == nil {
		t.Fatal("wrong ID token claims", id)
	}
	if access["sub"] != f.member.ID || access["tokenUse"] != "access" || access["authentication"] != nil {
		t.Fatal("wrong access token claims", access)
	}
	r := f.userinfo(tokens["access_token"].(string))
	f.status(r, 200)
	info := jsonObject(t, r)
	if info["sub"] != f.member.ID || info["name"] != "Example Member" || info["phone_number"] != "+8619900000001" || info["phone_number_verified"] != true || info["email"] != nil {
		t.Fatal("wrong userinfo", info)
	}
	f.status(f.userinfo(tokens["id_token"].(string)), 401)
	// An existing SSO cookie authenticates a new transaction, but never chooses a different organization's Member implicitly.
	page, verifier := f.loginPage("second-web", "openid profile")
	if strings.Contains(page.body, `value="`+f.member.ID+`"`) || !strings.Contains(page.body, `value="`+f.otherMember.ID+`"`) {
		t.Fatal("organization selection leaked")
	}
	r = f.submit(page.body, "continue", url.Values{"member": {f.member.ID}, "consent": {"yes"}})
	f.status(r, 200)
	if !strings.Contains(r.body, "Select an available Member") {
		t.Fatal("cross-organization identity accepted")
	}
	code := f.complete(r, f.otherMember.ID)
	r = f.exchange("second-web", code, verifier)
	f.status(r, 200)
	second := f.signedClaims(jsonObject(t, r)["id_token"].(string))
	if second["sub"] != f.otherMember.ID || second["sub"] == id["sub"] {
		t.Fatal("organization subjects collapsed")
	}
}

func TestAuthorizationTransactionSecurity(t *testing.T) {
	f := newFixture(t)
	page, verifier := f.loginPage("example-web", "openid profile")
	requestID := hidden(t, page.body, "request")
	f.status(f.call(browserClient(), "GET", "/login?request="+requestID, nil, nil), 400)
	form := url.Values{"request": {requestID}, "csrf": {hidden(t, page.body, "csrf")}, "action": {"send"}, "phone": {"19900000001"}}
	for _, origin := range []string{"", "null", "https://untrusted.example.test"} {
		f.status(f.call(f.browser, "POST", "/login", form, map[string]string{"Origin": origin}), 403)
		if f.sender.latest() != "" {
			t.Fatal("rejected login origin sent a verification code")
		}
	}
	form.Set("csrf", "wrong")
	f.status(f.call(f.browser, "POST", "/login", form, map[string]string{"Origin": f.server.URL}), 403)
	page = f.verifyPhone(page)
	r := f.submit(page.body, "continue", url.Values{"member": {f.member.ID}})
	f.status(r, 200)
	if !strings.Contains(r.body, "Approve the requested identity information") {
		t.Fatal("consent was bypassed")
	}
	code := f.complete(r, f.member.ID)
	f.status(f.exchange("second-web", code, verifier), 400)
	f.status(f.exchange("example-web", code, config.RandomSecret()), 400)
	r = f.exchange("example-web", code, verifier)
	f.status(r, 200)
	tokens := jsonObject(t, r)
	f.status(f.exchange("example-web", code, verifier), 400)
	f.status(f.userinfo(tokens["access_token"].(string)), 401)
}

func TestAuthorizationRejectsUnsupportedRequests(t *testing.T) {
	f := newFixture(t)
	for _, query := range []url.Values{
		{"code_challenge": {""}}, {"code_challenge_method": {"plain"}}, {"scope": {"openid offline_access"}},
		{"resource": {"https://untrusted.example.test"}}, {"scope": {"profile"}}, {"client_id": {"unknown"}},
		{"redirect_uri": {"http://127.0.0.1:8484/unregistered"}}, {"response_type": {"token"}},
	} {
		r, _ := f.authorization("example-web", "openid", query)
		if strings.Contains(r.header.Get("Location"), "/login?") {
			t.Fatalf("unsupported request reached login: %v", query)
		}
		if r.status < 300 || r.status >= 500 {
			t.Fatalf("unexpected invalid request status: %d %s", r.status, r.body)
		}
	}
	r, _ := f.authorization("example-web", "openid", url.Values{"prompt": {"none"}})
	f.status(r, 302)
	r = f.call(f.browser, "GET", r.header.Get("Location"), nil, nil)
	f.status(r, 302)
	if !strings.Contains(r.header.Get("Location"), "error=login_required") {
		t.Fatal("prompt=none did not return login_required", r.header)
	}
	r = f.call(f.browser, "GET", "/oauth/authorize?client_id=example-web&client_id=second-web", nil, nil)
	f.status(r, 400)
}

func TestEligibilityRevocationAndLogout(t *testing.T) {
	for _, operation := range []string{"block", "revoke", "logout"} {
		t.Run(operation, func(t *testing.T) {
			f := newFixture(t)
			tokens := f.tokens()
			token := tokens["access_token"].(string)
			basic := map[string]string{"Authorization": "Basic " + base64.StdEncoding.EncodeToString([]byte("example-web:"+f.secret))}
			r := f.call(browserClient(), "POST", "/oauth/introspect", url.Values{"token": {token}}, basic)
			f.status(r, 200)
			if jsonObject(t, r)["active"] != true {
				t.Fatal("valid access token is not active", r.body)
			}
			other := map[string]string{"Authorization": "Basic " + base64.StdEncoding.EncodeToString([]byte("second-web:"+f.secret))}
			r = f.call(browserClient(), "POST", "/oauth/introspect", url.Values{"token": {token}}, other)
			if r.status == 200 && jsonObject(t, r)["active"] == true {
				t.Fatal("cross-client introspection succeeded")
			}
			f.status(f.call(browserClient(), "POST", "/oauth/revoke", url.Values{"token": {token}}, other), 200)
			f.status(f.userinfo(token), 200)
			switch operation {
			case "block":
				if _, err := f.store.SetManualBlock(t.Context(), f.member.OrganizationID, f.member.ID, true); err != nil {
					t.Fatal(err)
				}
			case "revoke":
				f.status(f.call(browserClient(), "POST", "/oauth/revoke", url.Values{"token": {token}}, basic), 200)
			case "logout":
				query := url.Values{"id_token_hint": {tokens["id_token"].(string)}, "post_logout_redirect_uri": {"http://127.0.0.1:8484/signed-out"}, "state": {"logout-state"}}
				r = f.call(f.browser, "GET", "/oauth/logout?"+query.Encode(), nil, nil)
				f.status(r, 302)
				if r.header.Get("Location") != "http://127.0.0.1:8484/signed-out?state=logout-state" {
					t.Fatal("wrong logout redirect", r.header)
				}
				r, _ = f.authorization("example-web", "openid", url.Values{"prompt": {"none"}})
				r = f.call(f.browser, "GET", r.header.Get("Location"), nil, nil)
				if !strings.Contains(r.header.Get("Location"), "error=login_required") {
					t.Fatal("logout retained SSO")
				}
			}
			f.status(f.userinfo(token), 401)
		})
	}
}

func TestConcurrentCodeExchangeRevokesWinner(t *testing.T) {
	f := newFixture(t)
	page, verifier := f.loginPage("example-web", "openid")
	code := f.complete(f.verifyPhone(page), f.member.ID)
	outcomes := make(chan reply, 8)
	for range 8 {
		go func() { outcomes <- f.exchange("example-web", code, verifier) }()
	}
	successes := 0
	var access string
	for range 8 {
		result := <-outcomes
		if result.status == 200 {
			successes++
			access = jsonObject(t, result)["access_token"].(string)
		} else {
			f.status(result, 400)
		}
	}
	if successes != 1 {
		t.Fatalf("successful code redemptions: %d", successes)
	}
	f.status(f.userinfo(access), 401)
}

func TestFactorSubjectAndAuthenticationAge(t *testing.T) {
	f := newFixture(t)
	page, verifier := f.loginPage("registration", "openid phone registration_identity")
	page = f.verifyPhone(page)
	code := f.complete(page, "")
	result := f.exchange("registration", code, verifier)
	f.status(result, 200)
	tokens := jsonObject(t, result)
	claims := f.signedClaims(tokens["access_token"].(string))
	evidence, ok := claims["authentication"].(map[string]any)
	audience, _ := claims["aud"].([]any)
	if !ok || evidence["factorType"] != "phone" || claims["sub"] != evidence["factorId"] || claims["memberId"] != nil || claims["organizationId"] != nil || len(audience) != 1 || audience[0] != "https://registration.example.test" {
		t.Fatal("invalid factor evidence", claims)
	}
	// max_age must check the original authentication, not the time of this SSO request.
	if _, err := f.store.Database().Exec(t.Context(), `UPDATE oidc_sessions SET verification=jsonb_set(verification,'{authenticatedAt}',to_jsonb(to_char(clock_timestamp()-interval '2 hours','YYYY-MM-DD"T"HH24:MI:SS"Z"')))`); err != nil {
		t.Fatal(err)
	}
	result, _ = f.authorization("registration", "openid registration_identity", url.Values{"prompt": {"none"}, "max_age": {"60"}})
	result = f.call(f.browser, "GET", result.header.Get("Location"), nil, nil)
	if !strings.Contains(result.header.Get("Location"), "error=login_required") {
		t.Fatal("max_age reused stale authentication")
	}
}

func TestRestartWithSigningKeyRollover(t *testing.T) {
	f := newFixture(t)
	original := f.tokens()
	oldToken := original["access_token"].(string)
	oldKey := f.service.configuration.SigningKey
	configuration := *f.service.configuration
	nextKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	configuration.SigningKey = nextKey
	configuration.KeyID = config.KeyID(&nextKey.PublicKey)
	configuration.PublicKeys = map[string]*rsa.PublicKey{config.KeyID(&oldKey.PublicKey): &oldKey.PublicKey, configuration.KeyID: &nextKey.PublicKey}
	issuer := f.server.URL
	f.server.Close()
	listener, err := net.Listen("tcp", strings.TrimPrefix(issuer, "http://"))
	if err != nil {
		t.Fatal(err)
	}
	replacement, err := New(&configuration, f.store, f.service.phone, nil, nil)
	if err != nil {
		listener.Close()
		t.Fatal(err)
	}
	restarted := httptest.NewUnstartedServer(replacement)
	restarted.Listener.Close()
	restarted.Listener = listener
	restarted.Start()
	t.Cleanup(restarted.Close)
	f.server, f.service = restarted, replacement
	keys := f.call(f.browser, "GET", "/.well-known/jwks.json", nil, nil)
	f.status(keys, 200)
	var bundle jose.JSONWebKeySet
	if err := json.Unmarshal([]byte(keys.body), &bundle); err != nil || len(bundle.Keys) != 2 {
		t.Fatal("retained verification keys unavailable", err)
	}
	for _, expected := range configuration.JWKS().Keys {
		found := bundle.Key(expected.KeyID)
		if len(found) != 1 || !found[0].IsPublic() || found[0].Algorithm != expected.Algorithm || found[0].Use != expected.Use {
			t.Fatal("published JWKS differs from offline export metadata")
		}
		public, ok := found[0].Key.(*rsa.PublicKey)
		if !ok || !public.Equal(expected.Key) {
			t.Fatal("published JWKS differs from offline export key material")
		}
	}
	parsed, err := jwt.ParseSigned(oldToken, []jose.SignatureAlgorithm{jose.RS256})
	if err != nil {
		t.Fatal(err)
	}
	found := bundle.Key(parsed.Headers[0].KeyID)
	if len(found) != 1 || parsed.Claims(found[0].Key, &map[string]any{}) != nil {
		t.Fatal("old token no longer verifies against retained JWKS")
	}
	f.status(f.userinfo(oldToken), 200)
	page, verifier := f.loginPage("example-web", "openid profile")
	// Persisted verification and the browser cookie still authenticate this request after restart.
	if !strings.Contains(page.body, `value="`+f.member.ID+`"`) {
		t.Fatal("restart lost SSO")
	}
	code := f.complete(page, f.member.ID)
	response := f.exchange("example-web", code, verifier)
	f.status(response, 200)
	renewed := jsonObject(t, response)
	claims := f.signedClaims(renewed["id_token"].(string))
	if claims["sub"] != f.member.ID {
		t.Fatal("rollover changed subject")
	}
}

func TestConfidentialEndpointTransportAndAuthentication(t *testing.T) {
	f := newFixture(t)
	tokens := f.tokens()
	basic := map[string]string{"Authorization": "Basic " + base64.StdEncoding.EncodeToString([]byte("example-web:"+f.secret))}
	for _, path := range []string{"/oauth/token", "/oauth/introspect", "/oauth/revoke"} {
		f.status(f.call(browserClient(), "GET", path, nil, basic), 405)
		body := url.Values{"client_id": {"example-web"}, "client_secret": {f.secret}, "token": {tokens["access_token"].(string)}}
		response := f.call(browserClient(), "POST", path, body, nil)
		f.status(response, 401)
		if jsonObject(t, response)["error"] != "invalid_client" || response.header.Get("WWW-Authenticate") == "" {
			t.Fatal("missing client authentication challenge")
		}
		f.status(f.call(browserClient(), "POST", path, body, basic), 400)
		f.status(f.call(browserClient(), "POST", path+"?token=untrusted", url.Values{"token": {"example"}}, basic), 400)
	}
	f.status(f.userinfo(tokens["access_token"].(string)), 200)
}
