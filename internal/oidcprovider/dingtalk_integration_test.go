//go:build integration

package oidcprovider

import (
	"context"
	"encoding/base64"
	"errors"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/euyuil/memberid/internal/config"
	"github.com/euyuil/memberid/internal/dingtalk"
	"github.com/euyuil/memberid/internal/identity"
)

type testDingTalk struct {
	calls              atomic.Int64
	before             func()
	fail               bool
	authorizationError error
	directoryError     error
	directoryBefore    func()
	directoryCalls     atomic.Int64
}

func (provider *testDingTalk) CheckAuthorization(context.Context, string, string, string) error {
	return provider.authorizationError
}
func (provider *testDingTalk) Login(_ context.Context, corp, client, secret, code string) (dingtalk.Member, error) {
	provider.calls.Add(1)
	if provider.before != nil {
		provider.before()
	}
	if provider.fail || code != "synthetic-code" || corp != "example-corp" || secret == "" {
		return dingtalk.Member{}, errors.New("private provider diagnostic")
	}
	return dingtalk.Member{UnionID: "example-union", UserID: "example-employee", DisplayName: "Example Member", DepartmentIDs: []string{"17"}}, nil
}

func (provider *testDingTalk) VerifyMember(context.Context, string, string, string, string) (dingtalk.Member, error) {
	provider.directoryCalls.Add(1)
	if provider.directoryBefore != nil {
		provider.directoryBefore()
	}
	if provider.directoryError != nil {
		return dingtalk.Member{}, provider.directoryError
	}
	return dingtalk.Member{UnionID: "example-union", UserID: "example-employee"}, provider.authorizationError
}

func enableDingTalk(t *testing.T, f *fixture, phone bool) (*testDingTalk, *identity.DingTalkApplications) {
	t.Helper()
	key, _ := base64.StdEncoding.DecodeString(f.service.configuration.Secrets.ProviderKey)
	provider := new(testDingTalk)
	apps, err := identity.NewDingTalkApplications(f.store, key, provider)
	if err != nil {
		t.Fatal(err)
	}
	for index, organization := range []string{f.member.OrganizationID, f.otherMember.OrganizationID} {
		client := "example-client"
		if index == 1 {
			client = "second-client"
		}
		if _, err := apps.Configure(t.Context(), identity.OperatorPrincipal(), organization, identity.DingTalkApplicationInput{CorpID: "example-corp", ClientID: client, ClientSecret: config.RandomSecret()}); err != nil {
			t.Fatal(err)
		}
	}
	verifier, err := identity.NewDingTalkVerifier(apps, provider)
	if err != nil {
		t.Fatal(err)
	}
	directory, err := identity.NewDingTalkDirectory(apps, provider)
	if err != nil {
		t.Fatal(err)
	}
	f.service.directory = directory
	f.service.dingtalk = verifier
	if !phone {
		f.service.phone = nil
	}
	return provider, apps
}

func beginDingTalk(t *testing.T, f *fixture, client, scopes, organization string) (reply, string, string) {
	t.Helper()
	page, verifier := f.loginPage(client, scopes)
	started := f.submit(page.body, "dingtalk", url.Values{"organization": {organization}})
	f.status(started, 303)
	location, err := url.Parse(started.header.Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	query := location.Query()
	if location.Scheme != "https" || location.Host != "login.dingtalk.com" || location.Path != "/oauth2/auth" || query.Get("redirect_uri") != f.server.URL+"/login/dingtalk/callback" || query.Get("scope") != "openid corpid" || query.Get("response_type") != "code" || query.Get("prompt") != "consent" || len(query.Get("state")) != 43 || query.Get("client_secret") != "" {
		t.Fatal("incorrect upstream authorization")
	}
	return page, verifier, "/login/dingtalk/callback?" + url.Values{"state": {query.Get("state")}, "authCode": {"synthetic-code"}}.Encode()
}

func admittedMember(t *testing.T, f *fixture, organization string) string {
	t.Helper()
	var id string
	if err := f.store.Database().QueryRow(t.Context(), "SELECT member_id FROM dingtalk_identities WHERE organization_id=$1", organization).Scan(&id); err != nil {
		t.Fatal(err)
	}
	return id
}

func TestDingTalkOnlyOIDCLoginRefreshAndIndependentSubjects(t *testing.T) {
	f := newConfiguredFixture(t, true)
	provider, _ := enableDingTalk(t, f, false)
	f.service.configuration.Clients[0].EvidenceScope = "identity"
	f.service.configuration.Clients[0].EvidenceAudience = "https://resource.example.invalid"
	page, verifier, callbackPath := beginDingTalk(t, f, "example-web", "openid profile email phone offline_access identity", f.member.OrganizationID)
	if strings.Contains(page.body, `id="phone"`) || !strings.Contains(page.body, "Sign in with DingTalk") {
		t.Fatal("disabled phone provider rendered")
	}
	csp := page.header.Get("Content-Security-Policy")
	if !strings.Contains(csp, "form-action 'self' http://127.0.0.1:8484 https://login.dingtalk.com;") || strings.Contains(csp, "unsafe-inline") {
		t.Fatal("form policy cannot complete controlled OAuth redirects")
	}
	// The live provider returns both names. A conflict must leave the state unused.
	f.status(f.call(f.browser, "GET", callbackPath+"&code=conflicting-code", nil, nil), 400)
	if provider.calls.Load() != 0 {
		t.Fatal("conflicting callback reached the provider")
	}
	callbackPath += "&code=synthetic-code"
	response := f.call(f.browser, "GET", callbackPath, nil, nil)
	f.status(response, 303)
	f.status(f.call(f.browser, "GET", callbackPath, nil, nil), 400)
	page = f.call(f.browser, "GET", response.header.Get("Location"), nil, nil)
	f.status(page, 200)
	memberID := admittedMember(t, f, f.member.OrganizationID)
	if memberID == f.member.ID {
		t.Fatal("contact information implicitly linked a Member")
	}
	code := f.complete(page, memberID)
	tokensResponse := f.exchange("example-web", code, verifier)
	f.status(tokensResponse, 200)
	tokens := jsonObject(t, tokensResponse)
	claims := f.signedClaims(tokens["access_token"].(string))
	idClaims := f.signedClaims(tokens["id_token"].(string))
	if claims["sub"] != memberID || idClaims["sub"] != memberID || claims["organizationId"] != f.member.OrganizationID || claims["authentication"].(map[string]any)["factorType"] != "dingtalk" {
		t.Fatal("incorrect independent Member evidence")
	}
	for _, name := range []string{"departments", "departmentIds", "email", "phone_number", "roles", "owner"} {
		if claims[name] != nil || idClaims[name] != nil {
			t.Fatal("unverified or business attributes became authentication claims")
		}
	}
	info := f.userinfo(tokens["access_token"].(string))
	f.status(info, 200)
	if user := jsonObject(t, info); user["sub"] != memberID || user["email"] != nil || user["phone_number"] != nil {
		t.Fatal("UserInfo invented contact evidence")
	}
	refreshed := f.refresh("example-web", tokens["refresh_token"].(string), "")
	f.status(refreshed, 200)
	next := jsonObject(t, refreshed)
	nextClaims := f.signedClaims(next["id_token"].(string))
	if nextClaims["sub"] != memberID || nextClaims["auth_time"] != idClaims["auth_time"] || next["refresh_token"] == tokens["refresh_token"] {
		t.Fatal("DingTalk refresh changed original authentication")
	}
	page, verifier, callbackPath = beginDingTalk(t, f, "second-web", "openid profile", f.otherMember.OrganizationID)
	callbackPath = strings.Replace(callbackPath, "authCode=", "code=", 1)
	response = f.call(f.browser, "GET", callbackPath, nil, nil)
	f.status(response, 303)
	page = f.call(f.browser, "GET", response.header.Get("Location"), nil, nil)
	f.status(page, 200)
	secondID := admittedMember(t, f, f.otherMember.OrganizationID)
	if secondID == memberID {
		t.Fatal("same provider person merged across organizations")
	}
	code = f.complete(page, secondID)
	f.status(f.exchange("second-web", code, verifier), 200)
	if provider.calls.Load() != 2 {
		t.Fatal("unexpected upstream exchanges")
	}
	// A DingTalk SSO session cannot serve the phone-only factor registration profile.
	page, _ = f.loginPage("registration", "openid registration_identity")
	if strings.Contains(page.body, "Sign in with DingTalk") {
		t.Fatal("factor client offered DingTalk login")
	}
	f.status(f.submit(page.body, "continue", url.Values{"consent": {"yes"}}), 200)
	if _, err := f.store.SetManualBlock(t.Context(), identity.OperatorPrincipal(), f.member.OrganizationID, memberID, true); err != nil {
		t.Fatal(err)
	}
	f.invalidRefresh("example-web", next["refresh_token"].(string))
}

func TestDingTalkCallbackBrowserBindingExpiryAndFailures(t *testing.T) {
	for _, kind := range []string{"browser", "expired", "provider", "denied", "wrong organization", "factor client"} {
		t.Run(kind, func(t *testing.T) {
			f := newFixture(t)
			provider, _ := enableDingTalk(t, f, true)
			if kind == "wrong organization" || kind == "factor client" {
				client := "example-web"
				organization := f.otherMember.OrganizationID
				scopes := "openid"
				if kind == "factor client" {
					client = "registration"
					scopes = "openid registration_identity"
					organization = f.member.OrganizationID
				}
				page, _ := f.loginPage(client, scopes)
				f.status(f.submit(page.body, "dingtalk", url.Values{"organization": {organization}}), 400)
				if provider.calls.Load() != 0 {
					t.Fatal("rejected selection reached provider")
				}
				return
			}
			_, _, callbackPath := beginDingTalk(t, f, "example-web", "openid", f.member.OrganizationID)
			switch kind {
			case "browser":
				f.status(f.call(browserClient(), "GET", callbackPath, nil, nil), 400)
				f.status(f.call(f.browser, "GET", callbackPath, nil, nil), 303)
			case "expired":
				now := time.Now()
				f.service.now = func() time.Time { return now.Add(6 * time.Minute) }
				f.status(f.call(f.browser, "GET", callbackPath, nil, nil), 400)
			case "provider":
				provider.fail = true
				response := f.call(f.browser, "GET", callbackPath, nil, nil)
				f.status(response, 200)
				if strings.Contains(response.body, "private provider diagnostic") {
					t.Fatal("provider diagnostic disclosed")
				}
				f.status(f.call(f.browser, "GET", callbackPath, nil, nil), 400)
			case "denied":
				parsed, _ := url.Parse(callbackPath)
				query := parsed.Query()
				query.Del("authCode")
				query.Set("error", "access_denied")
				query.Set("error_description", "private provider diagnostic")
				response := f.call(f.browser, "GET", parsed.Path+"?"+query.Encode(), nil, nil)
				f.status(response, 200)
				if strings.Contains(response.body, "private provider diagnostic") {
					t.Fatal("upstream error rendered")
				}
				f.status(f.call(f.browser, "GET", callbackPath, nil, nil), 400)
			}
			if kind == "expired" || kind == "denied" {
				if provider.calls.Load() != 0 {
					t.Fatal("rejected callback exchanged code")
				}
			}
		})
	}
}

func TestConcurrentDingTalkCallbackConsumesStateOnce(t *testing.T) {
	f := newFixture(t)
	provider, _ := enableDingTalk(t, f, true)
	_, _, callbackPath := beginDingTalk(t, f, "example-web", "openid", f.member.OrganizationID)
	results := make(chan reply, 8)
	var group sync.WaitGroup
	for range 8 {
		group.Go(func() { results <- f.call(f.browser, "GET", callbackPath, nil, nil) })
	}
	group.Wait()
	close(results)
	accepted := 0
	for response := range results {
		if response.status == 303 {
			accepted++
		} else {
			f.status(response, 400)
		}
	}
	if accepted != 1 || provider.calls.Load() != 1 {
		t.Fatal("callback replay exchanged multiple codes")
	}
}

func TestDingTalkCallbackRejectsInvalidationDuringProviderIO(t *testing.T) {
	for _, kind := range []string{"cancel", "rotate", "disable", "reenable", "authorization"} {
		t.Run(kind, func(t *testing.T) {
			f := newFixture(t)
			provider, apps := enableDingTalk(t, f, true)
			page, _, callbackPath := beginDingTalk(t, f, "example-web", "openid", f.member.OrganizationID)
			started := make(chan struct{})
			release := make(chan struct{})
			provider.before = func() { close(started); <-release }
			result := make(chan reply, 1)
			go func() { result <- f.call(f.browser, "GET", callbackPath, nil, nil) }()
			<-started
			switch kind {
			case "cancel":
				f.status(f.submit(page.body, "cancel", nil), 200)
			case "rotate":
				_, err := apps.Configure(t.Context(), identity.OperatorPrincipal(), f.member.OrganizationID, identity.DingTalkApplicationInput{CorpID: "example-corp", ClientID: "example-client", ClientSecret: config.RandomSecret(), ExpectedRevision: 1})
				if err != nil {
					t.Fatal(err)
				}
			case "authorization":
				if _, err := apps.SynchronizeAuthorization(t.Context(), f.member.OrganizationID); err != nil {
					t.Fatal(err)
				}
			case "disable", "reenable":
				status := "disabled"
				if _, err := f.store.UpdateOrganization(t.Context(), identity.OperatorPrincipal(), f.member.OrganizationID, identity.OrganizationChange{Status: &status}); err != nil {
					t.Fatal(err)
				}
				if kind == "reenable" {
					status = "enabled"
					if _, err := f.store.UpdateOrganization(t.Context(), identity.OperatorPrincipal(), f.member.OrganizationID, identity.OrganizationChange{Status: &status}); err != nil {
						t.Fatal(err)
					}
				}
			}
			close(release)
			response := <-result
			f.status(response, 403)
			if len(response.header.Values("Set-Cookie")) != 0 {
				t.Fatal("failed callback installed a session cookie")
			}
			var count int
			for _, table := range []string{"dingtalk_identities", "oidc_sessions"} {
				if err := f.store.Database().QueryRow(t.Context(), "SELECT count(*) FROM "+table).Scan(&count); err != nil || count != 0 {
					t.Fatal("invalidated callback left identity or session state", err)
				}
			}
		})
	}
}

func TestDingTalkRevocationPreservesPhoneOIDCGrants(t *testing.T) {
	f := newConfiguredFixture(t, true)
	provider, apps := enableDingTalk(t, f, true)
	tokens := f.refreshTokens()
	provider.authorizationError = dingtalk.ErrUnavailable
	if _, err := apps.SynchronizeAuthorization(t.Context(), f.member.OrganizationID); !errors.Is(err, identity.ErrProviderUnavailable) {
		t.Fatal(err)
	}
	refreshed := f.refresh("example-web", tokens["refresh_token"].(string), "")
	f.status(refreshed, 200)
	tokens = jsonObject(t, refreshed)
	provider.authorizationError = dingtalk.ErrAuthorizationDenied
	if _, err := apps.SynchronizeAuthorization(t.Context(), f.member.OrganizationID); err != nil {
		t.Fatal(err)
	}
	f.status(f.userinfo(tokens["access_token"].(string)), 200)
	f.status(f.refresh("example-web", tokens["refresh_token"].(string), ""), 200)
	page, verifier := f.loginPage("example-web", "openid")
	code := f.complete(page, f.member.ID)
	f.status(f.exchange("example-web", code, verifier), 200)
	// Independently configured organizations and factor-only registration remain available.
	page, verifier = f.loginPage("registration", "openid registration_identity")
	code = f.complete(page, "")
	f.status(f.exchange("registration", code, verifier), 200)
	provider.authorizationError = nil
	if _, err := apps.SynchronizeAuthorization(t.Context(), f.member.OrganizationID); err != nil {
		t.Fatal(err)
	}
	page, verifier = f.loginPage("example-web", "openid")
	code = f.complete(page, f.member.ID)
	f.status(f.exchange("example-web", code, verifier), 200)
}
