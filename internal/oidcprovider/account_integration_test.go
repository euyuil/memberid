//go:build integration

package oidcprovider

import (
	"context"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/euyuil/memberid/internal/config"
	"github.com/euyuil/memberid/internal/identity"
)

const accountReturn = "http://127.0.0.1:8484/settings"

func accountFixture(t *testing.T) (*fixture, *testDingTalk, *identity.DingTalkApplications, reply) {
	t.Helper()
	f := newConfiguredFixture(t, true)
	provider, apps := enableDingTalk(t, f, true)
	f.service.configuration.Clients[0].AccountReturnURIs = []string{accountReturn}
	page, _ := f.loginPage("example-web", "openid offline_access")
	f.verifyPhone(page)
	query := url.Values{"memberId": {f.member.ID}, "client_id": {"example-web"}, "returnUri": {accountReturn}}
	account := f.call(f.browser, "GET", accountPath+"?"+query.Encode(), nil, nil)
	f.status(account, 200)
	return f, provider, apps, account
}
func accountSubmit(f *fixture, page reply, action string) reply {
	f.t.Helper()
	return f.call(f.browser, "POST", accountPath, url.Values{"request": {hidden(f.t, page.body, "request")}, "csrf": {hidden(f.t, page.body, "csrf")}, "action": {action}}, map[string]string{"Origin": f.server.URL})
}
func startAccount(f *fixture, page reply) string {
	f.t.Helper()
	response := accountSubmit(f, page, "link")
	f.status(response, 303)
	upstream, err := url.Parse(response.header.Get("Location"))
	if err != nil {
		f.t.Fatal(err)
	}
	if upstream.Scheme != "https" || upstream.Host != "login.dingtalk.com" || upstream.Query().Get("redirect_uri") != f.server.URL+"/account/dingtalk/callback" || upstream.Query().Get("scope") != "openid corpid" || len(upstream.Query().Get("state")) != 43 {
		f.t.Fatal("invalid account authorization")
	}
	return "/account/dingtalk/callback?" + url.Values{"state": {upstream.Query().Get("state")}, "authCode": {"synthetic-code"}}.Encode()
}
func assertUnlinked(t *testing.T, f *fixture) {
	t.Helper()
	var identities, factors int
	if err := f.store.Database().QueryRow(t.Context(), "SELECT count(*) FROM dingtalk_identities").Scan(&identities); err != nil {
		t.Fatal(err)
	}
	if err := f.store.Database().QueryRow(t.Context(), "SELECT count(*) FROM authentication_factors WHERE type='dingtalk'").Scan(&factors); err != nil {
		t.Fatal(err)
	}
	if identities != 0 || factors != 0 {
		t.Fatal("failed link left partial identity state")
	}
}

func TestAccountLinkPreservesMemberSessionAndOIDCSubject(t *testing.T) {
	f, provider, _, page := accountFixture(t)
	login, verifier := f.loginPage("example-web", "openid offline_access")
	tokens := f.exchange("example-web", f.complete(login, f.member.ID), verifier)
	f.status(tokens, 200)
	original := jsonObject(t, tokens)
	var grantBefore string
	if err := f.store.Database().QueryRow(t.Context(), "SELECT row_to_json(g)::text FROM oidc_grants g").Scan(&grantBefore); err != nil {
		t.Fatal(err)
	}
	var beforeSession, beforeDeadline, beforeVerification string
	if err := f.store.Database().QueryRow(t.Context(), "SELECT id,absolute_expires_at::text,verification::text FROM oidc_sessions").Scan(&beforeSession, &beforeDeadline, &beforeVerification); err != nil {
		t.Fatal(err)
	}
	callbackPath := startAccount(f, page) + "&code=synthetic-code"
	result := f.call(f.browser, "GET", callbackPath, nil, nil)
	f.status(result, 200)
	if !strings.Contains(result.body, "DingTalk is linked to this Member") || !strings.Contains(result.body, `href="`+accountReturn+`"`) || result.header.Get("Set-Cookie") != "" || !strings.Contains(result.header.Get("Content-Security-Policy"), "form-action 'self' https://login.dingtalk.com;") {
		t.Fatal("incorrect account result", result.body)
	}
	if id := admittedMember(t, f, f.member.OrganizationID); id != f.member.ID {
		t.Fatal("link created another Member")
	}
	var sessions, members, grants int
	if err := f.store.Database().QueryRow(t.Context(), "SELECT (SELECT count(*) FROM oidc_sessions),(SELECT count(*) FROM members),(SELECT count(*) FROM oidc_grants)").Scan(&sessions, &members, &grants); err != nil || sessions != 1 || members != 2 || grants != 1 {
		t.Fatal("link created login state", err)
	}
	var afterDeadline, afterVerification string
	if err := f.store.Database().QueryRow(t.Context(), "SELECT absolute_expires_at::text,verification::text FROM oidc_sessions WHERE id=$1", beforeSession).Scan(&afterDeadline, &afterVerification); err != nil || afterDeadline != beforeDeadline || afterVerification != beforeVerification {
		t.Fatal("link renewed or replaced original session", err)
	}
	f.status(f.call(f.browser, "GET", callbackPath, nil, nil), 400)
	if provider.calls.Load() != 1 {
		t.Fatal("callback replay called provider")
	}
	var grantAfter string
	if err := f.store.Database().QueryRow(t.Context(), "SELECT row_to_json(g)::text FROM oidc_grants g").Scan(&grantAfter); err != nil || grantAfter != grantBefore {
		t.Fatal("link changed an existing grant", err)
	}
	f.status(f.refresh("example-web", original["refresh_token"].(string), ""), 200)
	// A fresh standard DingTalk login resolves to the same independently selected Member.
	f.browser = browserClient()
	_, verifier, loginCallback := beginDingTalk(t, f, "example-web", "openid offline_access", f.member.OrganizationID)
	response := f.call(f.browser, "GET", loginCallback, nil, nil)
	f.status(response, 303)
	login = f.call(f.browser, "GET", response.header.Get("Location"), nil, nil)
	code := f.complete(login, f.member.ID)
	tokens = f.exchange("example-web", code, verifier)
	f.status(tokens, 200)
	values := jsonObject(t, tokens)
	if claims := f.signedClaims(values["id_token"].(string)); claims["sub"] != f.member.ID {
		t.Fatal("linked login changed OIDC subject")
	}
	f.status(f.refresh("example-web", values["refresh_token"].(string), ""), 200)
}

func TestAccountReturnAndSessionBoundaries(t *testing.T) {
	f, _, _, page := accountFixture(t)
	unknownMember, _ := identity.NewID(identity.MemberKind)
	for _, test := range []struct {
		name   string
		query  url.Values
		status int
	}{
		{"local", url.Values{"memberId": {f.member.ID}}, 200},
		{"no client", url.Values{"memberId": {f.member.ID}, "returnUri": {accountReturn}}, 400},
		{"logout destination", url.Values{"memberId": {f.member.ID}, "client_id": {"example-web"}, "returnUri": {"http://127.0.0.1:8484/signed-out"}}, 400},
		{"oauth callback", url.Values{"memberId": {f.member.ID}, "client_id": {"example-web"}, "returnUri": {callback}}, 400},
		{"prefix match", url.Values{"memberId": {f.member.ID}, "client_id": {"example-web"}, "returnUri": {accountReturn + "/extra"}}, 400},
		{"wrong client organization", url.Values{"memberId": {f.otherMember.ID}, "client_id": {"example-web"}, "returnUri": {accountReturn}}, 400},
		{"factor client", url.Values{"memberId": {f.member.ID}, "client_id": {"registration"}, "returnUri": {accountReturn}}, 400},
		{"unknown member", url.Values{"memberId": {unknownMember}}, 403},
	} {
		t.Run(test.name, func(t *testing.T) {
			scoped := *f
			scoped.t = t
			scoped.status(scoped.call(f.browser, "GET", accountPath+"?"+test.query.Encode(), nil, nil), test.status)
		})
	}
	f.status(f.call(browserClient(), "GET", accountPath+"?memberId="+f.member.ID, nil, nil), 401)
	form := url.Values{"request": {hidden(t, page.body, "request")}, "csrf": {hidden(t, page.body, "csrf")}, "action": {"link"}}
	f.status(f.call(f.browser, "POST", accountPath, form, nil), 403)
	f.status(f.call(f.browser, "POST", accountPath, form, map[string]string{"Origin": "https://other.example.invalid"}), 403)
	wrong := url.Values{"request": form["request"], "csrf": {"wrong"}, "action": {"link"}}
	f.status(f.call(f.browser, "POST", accountPath, wrong, map[string]string{"Origin": f.server.URL}), 403)
	form.Set("memberId", f.otherMember.ID)
	f.status(f.call(f.browser, "POST", accountPath, form, map[string]string{"Origin": f.server.URL}), 403)
	assertUnlinked(t, f)
}

func TestAccountCallbackBrowserBindingCancellationAndConcurrency(t *testing.T) {
	f, provider, _, page := accountFixture(t)
	callbackPath := startAccount(f, page)
	f.status(f.call(browserClient(), "GET", callbackPath, nil, nil), 400)
	// Copying only the SSO cookie does not copy the browser-bound account transaction.
	copied := browserClient()
	issuer, _ := url.Parse(f.server.URL)
	for _, cookie := range f.browser.Jar.Cookies(issuer) {
		if cookie.Name == f.service.cookieName("session") {
			copied.Jar.SetCookies(issuer, []*http.Cookie{cookie})
		}
	}
	f.status(f.call(copied, "GET", callbackPath, nil, nil), 400)
	reopened := f.call(f.browser, "GET", accountPath+"?"+url.Values{"memberId": {f.member.ID}, "client_id": {"example-web"}, "returnUri": {accountReturn}}.Encode(), nil, nil)
	f.status(reopened, 200)
	if hidden(t, reopened.body, "request") != hidden(t, page.body, "request") {
		t.Fatal("reopen abandoned pending verification")
	}
	canceled := accountSubmit(f, reopened, "cancel")
	f.status(canceled, 303)
	f.status(f.call(f.browser, "GET", callbackPath, nil, nil), 400)
	if provider.calls.Load() != 0 {
		t.Fatal("canceled callback contacted provider")
	}
	page = f.call(f.browser, "GET", canceled.header.Get("Location"), nil, nil)
	callbackPath = startAccount(f, page)
	var group sync.WaitGroup
	replies := make(chan reply, 2)
	for range 2 {
		group.Go(func() { replies <- f.call(f.browser, "GET", callbackPath, nil, nil) })
	}
	group.Wait()
	close(replies)
	success, rejected := 0, 0
	for response := range replies {
		if response.status == 200 {
			success++
		} else if response.status == 400 {
			rejected++
		} else {
			t.Fatal(response)
		}
	}
	if success != 1 || rejected != 1 || provider.calls.Load() != 1 {
		t.Fatal("concurrent callback was not single-use", success, rejected)
	}
}

func TestAccountRejectsChangesDuringProviderVerification(t *testing.T) {
	for _, kind := range []string{"session revoked", "member blocked", "departure", "source binding revoked", "source factor disabled", "rotation", "organization disabled", "request canceled", "return removed", "expired"} {
		t.Run(kind, func(t *testing.T) {
			f, provider, apps, page := accountFixture(t)
			callbackPath := startAccount(f, page)
			provider.before = func() {
				var err error
				switch kind {
				case "session revoked":
					_, err = f.store.Database().Exec(t.Context(), "UPDATE oidc_sessions SET revoked_at=clock_timestamp()")
				case "member blocked":
					_, err = f.store.SetManualBlock(t.Context(), f.member.OrganizationID, f.member.ID, true)
				case "departure":
					_, err = f.store.SetExternalDeparture(t.Context(), f.member.OrganizationID, f.member.ID, true)
				case "source binding revoked":
					factor, e := f.store.PhoneFactor(t.Context(), "19900000001")
					if e != nil {
						t.Fatal(e)
					}
					err = f.store.RevokeBinding(t.Context(), f.member.OrganizationID, f.member.ID, factor.ID)
				case "source factor disabled":
					_, err = f.store.Database().Exec(t.Context(), "UPDATE authentication_factors SET status='disabled' WHERE type='phone'")
				case "rotation":
					app, e := apps.Inspect(t.Context(), f.member.OrganizationID)
					if e != nil {
						t.Fatal(e)
					}
					_, err = apps.Configure(t.Context(), app.OrganizationID, identity.DingTalkApplicationInput{CorpID: app.CorpID, ClientID: app.ClientID, ClientSecret: config.RandomSecret(), ExpectedRevision: app.Revision})
				case "organization disabled":
					disabled := "disabled"
					_, err = f.store.UpdateOrganization(t.Context(), f.member.OrganizationID, identity.OrganizationChange{Status: &disabled})
				case "request canceled":
					_, err = f.store.Database().Exec(t.Context(), "UPDATE account_link_requests SET state='canceled'")
				case "return removed":
					f.service.configuration.Clients[0].AccountReturnURIs = nil
				case "expired":
					_, err = f.store.Database().Exec(t.Context(), "UPDATE account_link_requests SET expires_at=clock_timestamp()-interval '1 second'")
				}
				if err != nil {
					t.Fatal(err)
				}
			}
			response := f.call(f.browser, "GET", callbackPath, nil, nil)
			f.status(response, 200)
			if !strings.Contains(response.body, "Unable to link this identity") {
				t.Fatal("stale link did not fail", response.body)
			}
			if kind == "return removed" && strings.Contains(response.body, `href="`+accountReturn+`"`) {
				t.Fatal("removed destination remained actionable")
			}
			assertUnlinked(t, f)
		})
	}
}

func TestAccountRequiresFreshSourceAndFreshTarget(t *testing.T) {
	f, provider, _, page := accountFixture(t)
	at := f.service.now()
	f.service.now = func() time.Time { return at.Add(6 * time.Minute) }
	f.status(accountSubmit(f, page, "link"), 403) // The account request has also expired.
	page = f.call(f.browser, "GET", accountPath+"?memberId="+f.member.ID, nil, nil)
	f.status(page, 200)
	response := accountSubmit(f, page, "link")
	f.status(response, 200)
	if !strings.Contains(response.body, "Sign in again") || provider.calls.Load() != 0 {
		t.Fatal("old source session started linking")
	}
	assertUnlinked(t, f)
	f.service.now = time.Now
	page = f.call(f.browser, "GET", accountPath+"?"+url.Values{"memberId": {f.member.ID}, "client_id": {"example-web"}, "returnUri": {accountReturn}}.Encode(), nil, nil)
	callbackPath := startAccount(f, page)
	provider.fail = true
	response = f.call(f.browser, "GET", callbackPath, nil, nil)
	f.status(response, 200)
	if !strings.Contains(response.body, "Unable to verify DingTalk membership") || strings.Contains(response.body, "private provider diagnostic") {
		t.Fatal("failed provider handling")
	}
	f.status(f.call(f.browser, "GET", callbackPath, nil, nil), 400)
	assertUnlinked(t, f)
}

func TestAccountCleanupDoesNotRenewSession(t *testing.T) {
	f, _, _, _ := accountFixture(t)
	if _, err := f.store.Database().Exec(t.Context(), "UPDATE account_link_requests SET expires_at=clock_timestamp()-interval '1 second'"); err != nil {
		t.Fatal(err)
	}
	if err := f.service.Cleanup(context.Background()); err != nil {
		t.Fatal(err)
	}
	var requests, sessions int
	if err := f.store.Database().QueryRow(t.Context(), "SELECT (SELECT count(*) FROM account_link_requests),(SELECT count(*) FROM oidc_sessions)").Scan(&requests, &sessions); err != nil || requests != 0 || sessions != 1 {
		t.Fatal("incorrect account cleanup", err)
	}
}

func TestAccountLinkDoesNotTransferOrReplaceBindings(t *testing.T) {
	for _, kind := range []string{"bound elsewhere", "target occupied", "target revoked"} {
		t.Run(kind, func(t *testing.T) {
			f, _, apps, page := accountFixture(t)
			app, err := apps.Inspect(t.Context(), f.member.OrganizationID)
			if err != nil {
				t.Fatal(err)
			}
			union := "different-union"
			target := f.member
			if kind == "bound elsewhere" {
				union = "example-union"
				target, err = f.store.CreateMember(t.Context(), f.member.OrganizationID, "", "Another Member")
				if err != nil {
					t.Fatal(err)
				}
			}
			factor, err := f.store.EnsureFactor(t.Context(), "dingtalk", app.Namespace, union)
			if err != nil {
				t.Fatal(err)
			}
			binding, err := f.store.BindFactor(t.Context(), target.OrganizationID, target.ID, factor.ID)
			if err != nil {
				t.Fatal(err)
			}
			if kind == "target revoked" {
				if err := f.store.RevokeBinding(t.Context(), target.OrganizationID, target.ID, factor.ID); err != nil {
					t.Fatal(err)
				}
			}
			response := f.call(f.browser, "GET", startAccount(f, page), nil, nil)
			f.status(response, 200)
			if !strings.Contains(response.body, "Unable to link this identity") {
				t.Fatal("conflicting binding accepted")
			}
			var storedFactor, storedStatus string
			var factors, identities int
			if err := f.store.Database().QueryRow(t.Context(), "SELECT authentication_factor_id,status FROM member_auth_factor_bindings WHERE id=$1", binding.ID).Scan(&storedFactor, &storedStatus); err != nil || storedFactor != factor.ID {
				t.Fatal("binding transferred", err)
			}
			if kind == "target revoked" && storedStatus != "revoked" {
				t.Fatal("binding restored")
			}
			if err := f.store.Database().QueryRow(t.Context(), "SELECT (SELECT count(*) FROM authentication_factors WHERE type='dingtalk'),(SELECT count(*) FROM dingtalk_identities)").Scan(&factors, &identities); err != nil || factors != 1 || identities != 0 {
				t.Fatal("conflict retained partial evidence", err)
			}
		})
	}
}

func TestAccountLinkKeepsOrganizationsIndependent(t *testing.T) {
	f, _, _, page := accountFixture(t)
	first := f.call(f.browser, "GET", startAccount(f, page), nil, nil)
	f.status(first, 200)
	// The same verified phone can select another independent Member, without a return client.
	page = f.call(f.browser, "GET", accountPath+"?memberId="+f.otherMember.ID, nil, nil)
	f.status(page, 200)
	second := f.call(f.browser, "GET", startAccount(f, page), nil, nil)
	f.status(second, 200)
	firstID := admittedMember(t, f, f.member.OrganizationID)
	secondID := admittedMember(t, f, f.otherMember.OrganizationID)
	if firstID != f.member.ID || secondID != f.otherMember.ID || firstID == secondID {
		t.Fatal("link merged organizational identities")
	}
	var factors int
	if err := f.store.Database().QueryRow(t.Context(), "SELECT count(*) FROM authentication_factors WHERE type='dingtalk'").Scan(&factors); err != nil || factors != 2 {
		t.Fatal("provider namespaces were conflated", err)
	}
}

func TestAccountCreatesBrowserBindingWhenOnlySessionCookieExists(t *testing.T) {
	f, _, _, _ := accountFixture(t)
	issuer, _ := url.Parse(f.server.URL)
	f.browser.Jar.SetCookies(issuer, []*http.Cookie{{Name: f.service.cookieName("browser"), Value: "", Path: "/", MaxAge: -1}})
	page := f.call(f.browser, "GET", accountPath+"?memberId="+f.member.ID, nil, nil)
	f.status(page, 200)
	response := f.call(f.browser, "GET", startAccount(f, page), nil, nil)
	f.status(response, 200)
	if !strings.Contains(response.body, "DingTalk is linked to this Member") {
		t.Fatal("new browser cookie was not bound to the form")
	}
}
