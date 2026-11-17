//go:build integration

package oidcprovider

import (
	"encoding/base64"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/euyuil/memberid/internal/config"
	"github.com/euyuil/memberid/internal/identity"
)

// All upstream exchanges in this file use synthetic Feishu responses.
func feishuAccountFixture(t *testing.T) (*fixture, *testFeishu, string, reply) {
	t.Helper()
	f := newConfiguredFixture(t, true)
	provider := new(testFeishu)
	key, _ := base64.StdEncoding.DecodeString(f.service.configuration.Secrets.ProviderKey)
	apps, err := identity.NewFeishuApplications(f.store, key, provider)
	if err != nil {
		t.Fatal(err)
	}
	f.service.feishu = apps
	if err := f.store.SetAdministrator(t.Context(), identity.OperatorPrincipal(), f.member.OrganizationID, f.member.ID, true); err != nil {
		t.Fatal(err)
	}
	f.updateClient("example-web", func(c *config.Client) { c.AccountReturnURIs = []string{accountReturn} })
	login, verifier := f.loginPage("example-web", "openid offline_access")
	login = f.verifyPhone(login)
	f.status(f.exchange("example-web", f.complete(login, f.member.ID), verifier), 200)
	var grantID string
	if err := f.store.Database().QueryRow(t.Context(), "SELECT id FROM oidc_grants WHERE data->>'memberId'=$1", f.member.ID).Scan(&grantID); err != nil {
		t.Fatal(err)
	}
	enabled := true
	app, err := identity.NewManagementService(f.store, nil, apps, 0).ConfigureProvider(t.Context(), identity.ManagementPrincipal(f.member.ID, grantID), f.member.OrganizationID, "feishu", "", identity.ProviderInput{DisplayName: "Synthetic Feishu", ClientID: "cli_first", TenantID: "example-tenant", ClientSecret: config.RandomSecret(), Enabled: &enabled})
	if err != nil {
		t.Fatal(err)
	}
	page := f.call(f.browser, "GET", feishuAccountPath+"?"+url.Values{"memberId": {f.member.ID}, "client_id": {"example-web"}, "returnUri": {accountReturn}}.Encode(), nil, nil)
	f.status(page, 200)
	return f, provider, app.ID, page
}

func feishuAccountSubmit(f *fixture, page reply, provider, action string) reply {
	f.t.Helper()
	return f.call(f.browser, "POST", feishuAccountPath, url.Values{"request": {hidden(f.t, page.body, "request")}, "csrf": {hidden(f.t, page.body, "csrf")}, "provider": {provider}, "action": {action}}, map[string]string{"Origin": f.server.URL})
}

func startFeishuAccount(f *fixture, page reply, provider string) string {
	f.t.Helper()
	response := feishuAccountSubmit(f, page, provider, "link")
	f.status(response, 303)
	location, err := url.Parse(response.header.Get("Location"))
	if err != nil {
		f.t.Fatal(err)
	}
	query := location.Query()
	if location.Scheme != "https" || location.Host != "accounts.feishu.cn" || query.Get("client_id") != "cli_first" || query.Get("redirect_uri") != f.server.URL+feishuAccountCallbackPath || query.Get("code_challenge_method") != "S256" || len(query.Get("code_challenge")) != 43 || len(query.Get("state")) != 43 || query.Has("client_secret") {
		f.t.Fatal("invalid Feishu link authorization")
	}
	return feishuAccountCallbackPath + "?" + url.Values{"state": {query.Get("state")}, "code": {"synthetic-code"}}.Encode()
}

func assertFeishuUnlinked(t *testing.T, f *fixture) {
	t.Helper()
	var factors, bindings, completed int
	if err := f.store.Database().QueryRow(t.Context(), `SELECT
 (SELECT count(*) FROM authentication_factors WHERE type='feishu'),
 (SELECT count(*) FROM member_auth_factor_bindings WHERE factor_type='feishu'),
 (SELECT count(*) FROM account_link_requests WHERE state='completed')`).Scan(&factors, &bindings, &completed); err != nil || factors != 0 || bindings != 0 || completed != 0 {
		t.Fatal("partial Feishu link", factors, bindings, completed, err)
	}
}

func accountLoginSnapshot(t *testing.T, f *fixture) string {
	t.Helper()
	var snapshot string
	if err := f.store.Database().QueryRow(t.Context(), `SELECT jsonb_build_object(
 'sessions',(SELECT jsonb_agg(to_jsonb(s) ORDER BY id) FROM authentication_sessions s),
 'grants',(SELECT jsonb_agg(to_jsonb(g) ORDER BY id) FROM oidc_grants g),
 'members',(SELECT jsonb_agg(to_jsonb(m) ORDER BY id) FROM members m))::text`).Scan(&snapshot); err != nil {
		t.Fatal(err)
	}
	return snapshot
}

func TestFeishuAccountPreservesIdentityAndAuthentication(t *testing.T) {
	f, provider, id, page := feishuAccountFixture(t)
	assertAccountFormAction(t, page, "https://accounts.feishu.cn")
	sp := enableSAML(t, f)
	samlLogin := samlPage(t, f, sp)
	before := verifySAMLResponse(t, f, sp, f.submit(samlLogin.body, "continue", url.Values{"member": {f.member.ID}, "consent": {"yes"}}))
	snapshot := accountLoginSnapshot(t, f)
	callback := startFeishuAccount(f, page, id)
	result := f.call(f.browser, "GET", callback, nil, nil)
	f.status(result, 200)
	assertAccountFormAction(t, result, "https://accounts.feishu.cn")
	if !strings.Contains(result.body, "Feishu is linked to this Member") || !strings.Contains(result.body, `href="`+accountReturn+`"`) || result.header.Get("Set-Cookie") != "" {
		t.Fatal("incorrect link result")
	}
	if accountLoginSnapshot(t, f) != snapshot {
		t.Fatal("link changed Member, session or grant")
	}
	f.status(f.call(f.browser, "GET", callback, nil, nil), 400)
	if provider.calls.Load() != 1 {
		t.Fatal("replayed provider exchange")
	}
	// A fresh Feishu OIDC login must resolve to the existing Member.
	f.browser = browserClient()
	login, verifier := f.loginPage("example-web", "openid offline_access")
	response := f.submit(login.body, "feishu", url.Values{"organization": {f.member.OrganizationID}, "provider": {id}})
	f.status(response, 303)
	location, _ := url.Parse(response.header.Get("Location"))
	response = f.call(f.browser, "GET", feishuCallbackPath+"?"+url.Values{"state": {location.Query().Get("state")}, "code": {"synthetic-code"}}.Encode(), nil, nil)
	f.status(response, 303)
	login = f.call(f.browser, "GET", response.header.Get("Location"), nil, nil)
	tokens := f.exchange("example-web", f.complete(login, f.member.ID), verifier)
	f.status(tokens, 200)
	if claims := f.signedClaims(jsonObject(t, tokens)["id_token"].(string)); claims["sub"] != f.member.ID {
		t.Fatal("linked OIDC subject changed")
	}
	samlLogin = samlPage(t, f, sp)
	after := verifySAMLResponse(t, f, sp, f.submit(samlLogin.body, "continue", url.Values{"member": {f.member.ID}, "consent": {"yes"}}))
	if after.Assertion.Subject.NameID.Value != before.Assertion.Subject.NameID.Value {
		t.Fatal("linked SAML NameID changed")
	}
}

func TestFeishuAccountRequestBoundaries(t *testing.T) {
	f, provider, id, page := feishuAccountFixture(t)
	form := url.Values{"request": {hidden(t, page.body, "request")}, "csrf": {hidden(t, page.body, "csrf")}, "provider": {id}, "action": {"link"}}
	f.status(f.call(f.browser, "POST", feishuAccountPath, form, nil), 403)
	form.Set("csrf", "wrong")
	f.status(f.call(f.browser, "POST", feishuAccountPath, form, map[string]string{"Origin": f.server.URL}), 403)
	form.Set("csrf", hidden(t, page.body, "csrf"))
	f.status(f.call(f.browser, "POST", accountPath, form, map[string]string{"Origin": f.server.URL}), 404)
	form.Set("provider", "another-application")
	f.status(f.call(f.browser, "POST", feishuAccountPath, form, map[string]string{"Origin": f.server.URL}), 200)
	f.status(f.call(f.browser, "GET", feishuAccountPath+"?memberId="+f.otherMember.ID, nil, nil), 200)
	other := f.call(f.browser, "GET", feishuAccountPath+"?memberId="+f.otherMember.ID, nil, nil)
	f.status(feishuAccountSubmit(f, other, id, "link"), 200) // The app belongs to another organization.
	f.status(f.call(browserClient(), "GET", feishuAccountPath+"?memberId="+f.member.ID, nil, nil), 401)
	callback := startFeishuAccount(f, page, id)
	f.status(f.call(browserClient(), "GET", callback, nil, nil), 400)
	copied := browserClient()
	issuer, _ := url.Parse(f.server.URL)
	for _, cookie := range f.browser.Jar.Cookies(issuer) {
		if cookie.Name == f.service.cookieName("session") {
			copied.Jar.SetCookies(issuer, []*http.Cookie{cookie})
		}
	}
	f.status(f.call(copied, "GET", callback, nil, nil), 400)
	f.status(f.call(f.browser, "GET", strings.Replace(callback, "?", "?authCode=synthetic-code&", 1), nil, nil), 400)
	snapshot := accountLoginSnapshot(t, f)
	provider.wrongTenant.Store(true)
	result := f.call(f.browser, "GET", callback, nil, nil)
	f.status(result, 200)
	if !strings.Contains(result.body, "Unable to verify Feishu membership") {
		t.Fatal("wrong tenant accepted")
	}
	f.status(f.call(f.browser, "GET", callback, nil, nil), 400)
	if accountLoginSnapshot(t, f) != snapshot {
		t.Fatal("failed link changed identity or authentication")
	}
	assertFeishuUnlinked(t, f)
}

func TestFeishuAccountCancellationExpiryAndConcurrency(t *testing.T) {
	for _, kind := range []string{"cancel", "expired", "old session", "provider error", "concurrent"} {
		t.Run(kind, func(t *testing.T) {
			f, provider, id, page := feishuAccountFixture(t)
			callback := startFeishuAccount(f, page, id)
			switch kind {
			case "cancel":
				f.status(feishuAccountSubmit(f, page, id, "cancel"), 303)
			case "expired":
				if _, err := f.store.Database().Exec(t.Context(), "UPDATE account_link_requests SET expires_at=clock_timestamp()-interval '1 second'"); err != nil {
					t.Fatal(err)
				}
			case "old session":
				at := f.service.now()
				f.service.now = func() time.Time { return at.Add(6 * time.Minute) }
			case "provider error":
				callback = strings.Replace(callback, "synthetic-code", "invalid-code", 1)
				result := f.call(f.browser, "GET", callback, nil, nil)
				f.status(result, 200)
				if !strings.Contains(result.body, "Unable to verify Feishu membership") {
					t.Fatal("provider failure accepted")
				}
			case "concurrent":
				var group sync.WaitGroup
				results := make(chan reply, 2)
				for range 2 {
					group.Go(func() { results <- f.call(f.browser, "GET", callback, nil, nil) })
				}
				group.Wait()
				close(results)
				success, rejected := 0, 0
				for result := range results {
					if result.status == 200 && strings.Contains(result.body, "Feishu is linked") {
						success++
					} else if result.status == 400 {
						rejected++
					} else {
						t.Fatal("unexpected concurrent outcome", result.status)
					}
				}
				if success != 1 || rejected != 1 || provider.calls.Load() != 1 {
					t.Fatal("callback was not single-use")
				}
				return
			}
			f.status(f.call(f.browser, "GET", callback, nil, nil), 400)
			assertFeishuUnlinked(t, f)
		})
	}
}

func TestFeishuAccountRejectsPolicyChangesDuringVerification(t *testing.T) {
	for _, kind := range []string{"session", "member", "departure", "source binding", "source factor", "provider revision", "authorization revision", "organization", "cancel", "return", "expiry"} {
		t.Run(kind, func(t *testing.T) {
			f, provider, id, page := feishuAccountFixture(t)
			callback := startFeishuAccount(f, page, id)
			provider.before = func() {
				query := ""
				var args []any
				switch kind {
				case "session":
					query = "UPDATE authentication_sessions SET revoked_at=clock_timestamp()"
				case "member":
					query = "UPDATE members SET manual_block=true,eligibility_revision=eligibility_revision+1"
				case "departure":
					query = "UPDATE members SET external_departure=true,eligibility_revision=eligibility_revision+1"
				case "source binding":
					query = "UPDATE member_auth_factor_bindings SET status='revoked',revoked_at=clock_timestamp() WHERE factor_type='phone'"
				case "source factor":
					query = "UPDATE authentication_factors SET status='disabled' WHERE type='phone'"
				case "provider revision":
					query, args = "UPDATE feishu_applications SET revision=revision+1 WHERE namespace=$1", []any{id}
				case "authorization revision":
					query, args = "UPDATE feishu_applications SET authorization_revision=authorization_revision+1 WHERE namespace=$1", []any{id}
				case "organization":
					query, args = "UPDATE organizations SET status='disabled',lifecycle_revision=lifecycle_revision+1 WHERE id=$1", []any{f.member.OrganizationID}
				case "cancel":
					query = "UPDATE account_link_requests SET state='canceled'"
				case "return":
					f.updateClient("example-web", func(c *config.Client) { c.AccountReturnURIs = nil })
					return
				case "expiry":
					query = "UPDATE account_link_requests SET expires_at=clock_timestamp()-interval '1 second'"
				}
				if _, err := f.store.Database().Exec(t.Context(), query, args...); err != nil {
					t.Fatal(err)
				}
			}
			result := f.call(f.browser, "GET", callback, nil, nil)
			f.status(result, 200)
			if !strings.Contains(result.body, "Unable to link this identity") {
				t.Fatal("policy change accepted")
			}
			assertFeishuUnlinked(t, f)
		})
	}
}

func TestFeishuAccountConflictsNeverTransferOrRestore(t *testing.T) {
	for _, kind := range []string{"elsewhere", "occupied", "revoked", "revoked during verification"} {
		t.Run(kind, func(t *testing.T) {
			f, provider, id, page := feishuAccountFixture(t)
			subject, member := "another-open-id", f.member
			if kind == "elsewhere" {
				subject = "ou_example"
				var err error
				member, err = f.store.CreateMember(t.Context(), identity.OperatorPrincipal(), f.member.OrganizationID, "", "Another Member")
				if err != nil {
					t.Fatal(err)
				}
			}
			factor, err := f.store.EnsureFactor(t.Context(), "feishu", id, subject)
			if err != nil {
				t.Fatal(err)
			}
			binding, err := f.store.BindFactor(t.Context(), identity.OperatorPrincipal(), member.OrganizationID, member.ID, factor.ID)
			if err != nil {
				t.Fatal(err)
			}
			revoke := func() {
				if err := f.store.RevokeBinding(t.Context(), identity.OperatorPrincipal(), member.OrganizationID, member.ID, factor.ID); err != nil {
					t.Fatal(err)
				}
			}
			if kind == "revoked" {
				revoke()
			}
			if kind == "revoked during verification" {
				provider.before = revoke
			}
			result := f.call(f.browser, "GET", startFeishuAccount(f, page, id), nil, nil)
			f.status(result, 200)
			if !strings.Contains(result.body, "binding conflict exists") {
				t.Fatal("conflict accepted")
			}
			var stored, status string
			var factors int
			if err := f.store.Database().QueryRow(t.Context(), "SELECT authentication_factor_id,status FROM member_auth_factor_bindings WHERE id=$1", binding.ID).Scan(&stored, &status); err != nil || stored != factor.ID {
				t.Fatal("binding transferred", err)
			}
			if strings.HasPrefix(kind, "revoked") && status != "revoked" {
				t.Fatal("binding restored")
			}
			if err := f.store.Database().QueryRow(t.Context(), "SELECT count(*) FROM authentication_factors WHERE type='feishu'").Scan(&factors); err != nil || factors != 1 {
				t.Fatal("partial factor on conflict", err)
			}
		})
	}
}
