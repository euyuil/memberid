//go:build integration

package oidcprovider

import (
	"context"
	"encoding/base64"
	"net/http"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/euyuil/memberid/internal/config"
	"github.com/euyuil/memberid/internal/dingtalk"
	"github.com/euyuil/memberid/internal/feishu"
	"github.com/euyuil/memberid/internal/identity"
)

type testFeishu struct {
	revoked, wrongTenant atomic.Bool
	calls                atomic.Int64
}

func (provider *testFeishu) CheckAuthorization(_ context.Context, clientID, _ string) error {
	if clientID == "cli_first" && provider.revoked.Load() {
		return feishu.ErrAuthorizationDenied
	}
	return nil
}

func (provider *testFeishu) Login(_ context.Context, clientID, secret, callback, code, verifier string) (feishu.Profile, error) {
	provider.calls.Add(1)
	if provider.CheckAuthorization(context.Background(), clientID, secret) != nil {
		return feishu.Profile{}, feishu.ErrAuthorizationDenied
	}
	if code != "synthetic-code" || len(verifier) != 43 || !strings.HasSuffix(callback, feishuCallbackPath) || len(secret) < 16 {
		return feishu.Profile{}, feishu.ErrUnavailable
	}
	tenant := "example-tenant"
	if provider.wrongTenant.Load() {
		tenant = "other-tenant"
	}
	return feishu.Profile{TenantKey: tenant, OpenID: "ou_example", Name: "Example Member"}, nil
}

func TestOrganizationProviderManagementAndFeishuOIDC(t *testing.T) {
	f := newConfiguredFixture(t, true)
	dingTalk := new(testDingTalk)
	provider := new(testFeishu)
	key, _ := base64.StdEncoding.DecodeString(f.service.configuration.Secrets.ProviderKey)
	apps, err := identity.NewFeishuApplications(f.store, key, provider)
	if err != nil {
		t.Fatal(err)
	}
	dingTalkApps, err := identity.NewDingTalkApplications(f.store, key, dingTalk)
	if err != nil {
		t.Fatal(err)
	}
	f.service.dingtalk, err = identity.NewDingTalkVerifier(dingTalkApps, dingTalk)
	if err != nil {
		t.Fatal(err)
	}
	f.service.directory, err = identity.NewDingTalkDirectory(dingTalkApps, dingTalk)
	if err != nil {
		t.Fatal(err)
	}
	f.service.feishu = apps
	if err := f.store.SetAdministrator(t.Context(), identity.ManagementActor{}, f.member.OrganizationID, f.member.ID, true); err != nil {
		t.Fatal(err)
	}
	server := consoleProviderFixture(t, f, dingTalk, provider)
	consoleLogin(t, f, server, f.member.ID)
	csrf := consoleJSON(t, f, server, "GET", "/api/session", "", "", 200)["csrf"].(string)
	base := "/api/organizations/" + f.member.OrganizationID + "/providers"
	foreign := "/api/organizations/" + f.otherMember.OrganizationID + "/providers"
	secret := config.RandomSecret()
	create := func(name, clientID, tenant string) string {
		return `{"displayName":"` + name + `","clientId":"` + clientID + `","tenantId":"` + tenant + `","clientSecret":"` + secret + `","expectedRevision":0,"enabled":true}`
	}
	consoleJSON(t, f, server, "GET", foreign, "", "", 403)
	consoleJSON(t, f, server, "POST", foreign+"/feishu", csrf, create("Forbidden", "cli_other", "example-tenant"), 403)
	consoleJSON(t, f, server, "POST", base+"/feishu", "wrong-token", create("Feishu A", "cli_first", "example-tenant"), 403)
	first := consoleJSON(t, f, server, "POST", base+"/feishu", csrf, create("Feishu A", "cli_first", "example-tenant"), 200)["id"].(string)
	second := consoleJSON(t, f, server, "POST", base+"/feishu", csrf, create("Feishu B", "cli_second", "example-tenant"), 200)["id"].(string)
	ding := consoleJSON(t, f, server, "POST", base+"/dingtalk", csrf, create("DingTalk A", "example-client", "example-corp"), 200)["id"].(string)
	dingB := consoleJSON(t, f, server, "POST", base+"/dingtalk", csrf, create("DingTalk B", "second-dingtalk", "example-corp"), 200)["id"].(string)
	consoleJSON(t, f, server, "POST", base+"/feishu", csrf, create("Duplicate app", "cli_first", "example-tenant"), 409)
	list := consoleJSON(t, f, server, "GET", base, "", "", 200)
	if len(list["items"].([]any)) != 4 || list["feishuCallback"] != f.server.URL+feishuCallbackPath {
		t.Fatal("organization provider directory is incomplete")
	}
	for _, item := range list["items"].([]any) {
		if _, ok := item.(map[string]any)["clientSecret"]; ok {
			t.Fatal("provider secret returned to the browser")
		}
	}
	edit := `{"displayName":"Renamed Feishu B","clientId":"cli_second","tenantId":"example-tenant","expectedRevision":1,"enabled":true}`
	consoleJSON(t, f, server, "PUT", base+"/feishu/"+second, csrf, edit, 200)
	consoleJSON(t, f, server, "PUT", base+"/feishu/"+second, csrf, edit, 409)
	events := consoleJSON(t, f, server, "GET", "/api/events", "", "", 200)["items"].([]any)
	changes := events[0].(map[string]any)["changes"].(map[string]any)
	if changes["displayName"] != "Renamed Feishu B" || changes["clientSecret"] != nil {
		t.Fatal("missing effective audited provider change")
	}

	adminBrowser := f.browser
	f.browser = browserClient()
	factorClient, _ := f.loginPage("registration", "openid registration_identity")
	if strings.Contains(factorClient.body, "Sign in with Feishu") {
		t.Fatal("factor client offered Feishu")
	}
	foreignPage, _ := f.loginPage("second-web", "openid")
	f.status(f.submit(foreignPage.body, "feishu", url.Values{"organization": {f.member.OrganizationID}, "provider": {first}}), 400)

	start := func(id, clientID string) (string, string) {
		t.Helper()
		f.browser = browserClient()
		page, verifier := f.loginPage("example-web", "openid profile offline_access")
		for _, label := range []string{"Sign in with DingTalk", "Feishu A", "Renamed Feishu B"} {
			if !strings.Contains(page.body, label) && !provider.revoked.Load() {
				t.Fatal("organization login options missing", label)
			}
		}
		r := f.submit(page.body, "feishu", url.Values{"organization": {f.member.OrganizationID}, "provider": {id}})
		f.status(r, 303)
		location, err := url.Parse(r.header.Get("Location"))
		if err != nil {
			t.Fatal(err)
		}
		q := location.Query()
		if location.Host != "accounts.feishu.cn" || q.Get("client_id") != clientID || q.Get("redirect_uri") != f.server.URL+feishuCallbackPath ||
			q.Get("code_challenge_method") != "S256" || len(q.Get("code_challenge")) != 43 || len(q.Get("state")) != 43 || q.Has("client_secret") {
			t.Fatal("invalid Feishu authorization request")
		}
		return feishuCallbackPath + "?" + url.Values{"state": {q.Get("state")}, "code": {"synthetic-code"}}.Encode(), verifier
	}
	signIn := func(id, clientID string) (string, map[string]any) {
		t.Helper()
		path, verifier := start(id, clientID)
		f.status(f.call(browserClient(), http.MethodGet, path, nil, nil), 400)
		r := f.call(f.browser, http.MethodGet, path, nil, nil)
		f.status(r, 303)
		f.status(f.call(f.browser, http.MethodGet, path, nil, nil), 400)
		page := f.call(f.browser, http.MethodGet, r.header.Get("Location"), nil, nil)
		f.status(page, 200)
		var memberID string
		if err := f.store.Database().QueryRow(t.Context(), `SELECT b.member_id FROM member_auth_factor_bindings b
 JOIN authentication_factors f ON f.id=b.authentication_factor_id WHERE f.type='feishu' AND f.namespace=$1 AND f.subject='ou_example'`, id).Scan(&memberID); err != nil {
			t.Fatal(err)
		}
		code := f.complete(page, memberID)
		r = f.exchange("example-web", code, verifier)
		f.status(r, 200)
		tokens := jsonObject(t, r)
		claims := f.signedClaims(tokens["id_token"].(string))
		if claims["sub"] != memberID || claims["amr"].([]any)[0] != "feishu" {
			t.Fatal("Feishu OIDC subject or authentication method is wrong")
		}
		return memberID, tokens
	}
	path, _ := start(first, "cli_first")
	provider.wrongTenant.Store(true)
	rejected := f.call(f.browser, http.MethodGet, path, nil, nil)
	f.status(rejected, 200)
	if !strings.Contains(rejected.body, "Unable to verify the Feishu identity") {
		t.Fatal("wrong Feishu tenant was accepted")
	}
	provider.wrongTenant.Store(false)
	memberA, tokensA := signIn(first, "cli_first")
	memberB, tokensB := signIn(second, "cli_second")
	repeat, _ := signIn(second, "cli_second")
	if memberA == memberB || memberA == f.member.ID || memberB == f.member.ID || memberB != repeat {
		t.Fatal("provider application identities were merged or became unstable")
	}
	if calls := provider.calls.Load(); calls != 4 {
		t.Fatalf("unexpected number of provider code exchanges: %d", calls)
	}

	f.browser = adminBrowser
	phonePage, phoneVerifier := f.loginPage("example-web", "openid profile phone offline_access")
	phoneResponse := f.exchange("example-web", f.complete(phonePage, f.member.ID), phoneVerifier)
	f.status(phoneResponse, 200)
	phone := jsonObject(t, phoneResponse)
	provider.revoked.Store(true)
	if err := apps.CheckApplications(t.Context()); err != nil {
		t.Fatal(err)
	}
	f.status(f.userinfo(tokensA["access_token"].(string)), 401)
	f.invalidRefresh("example-web", tokensA["refresh_token"].(string))
	f.status(f.userinfo(tokensB["access_token"].(string)), 200)
	f.status(f.refresh("example-web", tokensB["refresh_token"].(string), ""), 200)
	f.status(f.refresh("example-web", phone["refresh_token"].(string), ""), 200)

	dingTalk.authorizationError = dingtalk.ErrAuthorizationDenied
	if app, err := dingTalkApps.SynchronizeSource(t.Context(), f.member.OrganizationID, ding); err != nil || app.AuthorizationStatus != "revoked" {
		t.Fatal("could not revoke the selected DingTalk application", err)
	}
	f.browser = browserClient()
	page, verifier := f.loginPage("example-web", "openid")
	if strings.Contains(page.body, "Feishu A") || strings.Contains(page.body, "DingTalk A") || !strings.Contains(page.body, "DingTalk B") || !strings.Contains(page.body, "Renamed Feishu B") {
		t.Fatal("revocation modified the wrong login options")
	}
	dingTalk.authorizationError = nil
	r := f.submit(page.body, "dingtalk", url.Values{"organization": {f.member.OrganizationID}, "provider": {dingB}})
	f.status(r, 303)
	location, _ := url.Parse(r.header.Get("Location"))
	r = f.call(f.browser, "GET", "/login/dingtalk/callback?"+url.Values{"state": {location.Query().Get("state")}, "authCode": {"synthetic-code"}}.Encode(), nil, nil)
	f.status(r, 303)
	page = f.call(f.browser, "GET", r.header.Get("Location"), nil, nil)
	f.status(page, 200)
	f.status(f.exchange("example-web", f.complete(page, admittedMember(t, f, f.member.OrganizationID)), verifier), 200)

	f.browser = adminBrowser
	disable := `{"displayName":"Renamed Feishu B","clientId":"cli_second","tenantId":"example-tenant","expectedRevision":2,"enabled":false}`
	consoleJSON(t, f, server, "PUT", base+"/feishu/"+second, csrf, disable, 200)
	f.status(f.userinfo(tokensB["access_token"].(string)), 401)
}
