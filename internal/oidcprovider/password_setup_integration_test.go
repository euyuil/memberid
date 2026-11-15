//go:build integration

package oidcprovider

import (
	"errors"
	"net/url"
	"regexp"
	"strings"
	"testing"

	"github.com/euyuil/memberid/internal/config"
	"github.com/euyuil/memberid/internal/identity"
)

func TestSimultaneousSetupCanCreateOnlyOneAdministrator(t *testing.T) {
	f := newFixture(t)
	code, err := f.store.IssueSetupCode(t.Context(), identity.OperatorPrincipal())
	if err != nil {
		t.Fatal(err)
	}
	confirmation := config.RandomSecret()
	if _, err := f.store.PrepareSetupPassword(t.Context(), code, confirmation); err != nil {
		t.Fatal(err)
	}
	results := make(chan error, 2)
	for range 2 {
		go func() { results <- f.store.CompleteSetup(t.Context(), confirmation) }()
	}
	successes := 0
	for range 2 {
		if err := <-results; err == nil {
			successes++
		} else if !errors.Is(err, identity.ErrSetupCredential) {
			t.Fatal(err)
		}
	}
	admins, err := f.store.AdministratorIDs(t.Context(), identity.SystemOrganizationID)
	if err != nil || successes != 1 || len(admins) != 1 {
		t.Fatal("setup did not create exactly one system administrator", err)
	}
}

func TestConsoleFirstSetupAndPasswordRecovery(t *testing.T) {
	f := newFixture(t)
	server := consoleFixture(t, f)
	setup := server.URL + "/setup"
	origin := map[string]string{"Origin": server.URL}
	page := f.call(f.browser, "GET", server.URL+"/", nil, nil)
	f.status(page, 303)
	if page.header.Get("Location") != "/setup" {
		t.Fatal("uninitialized console did not open setup")
	}
	page = f.call(f.browser, "GET", setup, nil, nil)
	f.status(page, 200)
	if page.header.Get("Referrer-Policy") != "same-origin" ||
		!strings.Contains(page.body, "org_system") || !strings.Contains(page.body, "root") || strings.Contains(page.body, "generated-password") {
		t.Fatal("unexpected initial setup page")
	}
	if _, err := f.store.IssueSetupCode(t.Context(), identity.Principal{}); !errors.Is(err, identity.ErrForbidden) {
		t.Fatal("untrusted caller could issue a setup code")
	}
	code, err := f.store.IssueSetupCode(t.Context(), identity.OperatorPrincipal())
	if err != nil {
		t.Fatal(err)
	}
	generate := url.Values{"action": {"generate"}, "code": {code}}
	f.status(f.call(f.browser, "POST", setup, generate, map[string]string{"Origin": f.server.URL}), 403)
	page = f.call(f.browser, "POST", setup, generate, origin)
	if page.status != 200 || page.header.Get("Cache-Control") != "no-store" {
		t.Fatal("setup password was not delivered in a non-cacheable response")
	}
	match := regexp.MustCompile(`id="generated-password" value="([A-Za-z0-9_-]{32})"`).FindStringSubmatch(page.body)
	if len(match) != 2 {
		t.Fatal("missing generated password")
	}
	password := match[1]
	confirmation := hidden(t, page.body, "confirmation")
	for _, page := range []reply{
		f.call(f.browser, "GET", setup, nil, nil),
		f.call(f.browser, "POST", setup, generate, origin),
	} {
		if strings.Contains(page.body, password) {
			t.Fatal("setup revealed the password again")
		}
	}
	complete := url.Values{"action": {"complete"}, "confirmation": {confirmation}, "saved": {"yes"}}
	r := f.call(browserClient(), "POST", setup, complete, origin)
	if r.status != 200 || r.header.Get("Location") != "" {
		t.Fatal("unbound browser could confirm setup")
	}
	r = f.call(f.browser, "POST", setup, complete, origin)
	f.status(r, 303)
	login := f.call(f.browser, "GET", r.header.Get("Location"), nil, nil)
	f.status(login, 302)
	login = f.call(f.browser, "GET", login.header.Get("Location"), nil, nil)
	f.status(login, 200)
	if !strings.Contains(login.body, `value="org_system"`) || !strings.Contains(login.body, `value="root"`) {
		t.Fatal("first login did not prefill the system account")
	}
	fields := url.Values{"password_organization": {identity.SystemOrganizationID}, "username": {identity.RootUsername}, "password": {"incorrect"}}
	login = f.submit(login.body, "password", fields)
	f.status(login, 200)
	if !strings.Contains(login.body, "password is incorrect") {
		t.Fatal("wrong password was not rejected")
	}
	fields.Set("password", password)
	login = f.submit(login.body, "password", fields)
	f.status(login, 303)
	login = f.call(f.browser, "GET", login.header.Get("Location"), nil, nil)
	f.status(login, 302)
	login = f.call(f.browser, "GET", login.header.Get("Location"), nil, nil)
	f.status(login, 303)
	who := consoleJSON(t, f, server, "GET", "/api/session", "", "", 200)["actor"].(map[string]any)
	if who["displayName"] != "root" || who["organizationId"] != "org_system" || who["platform"] != true {
		t.Fatal("root did not reach the console as platform administrator")
	}
	f.status(f.call(f.browser, "GET", setup, nil, nil), 303)
	if _, err = f.store.IssueSetupCode(t.Context(), identity.OperatorPrincipal()); !errors.Is(err, identity.ErrSetupClosed) {
		t.Fatal("completed setup could be reopened")
	}
	next, err := f.store.ResetRootPassword(t.Context(), identity.OperatorPrincipal())
	if err != nil || len(next) != 32 || next == password {
		t.Fatal("root password was not rotated", err)
	}
	consoleJSON(t, f, server, "GET", "/api/session", "", "", 401)
}

func TestPasswordLoginOrganizationIsolationAndRefreshRevocation(t *testing.T) {
	f := newConfiguredFixture(t, true)
	operator := identity.OperatorPrincipal()
	first, err := f.store.SetMemberPassword(t.Context(), operator, f.member.OrganizationID, f.member.ID, "example")
	if err != nil {
		t.Fatal(err)
	}
	second, err := f.store.SetMemberPassword(t.Context(), operator, f.otherMember.OrganizationID, f.otherMember.ID, "example")
	if err != nil {
		t.Fatal(err)
	}
	page, verifier := f.loginPage("second-web", "openid offline_access")
	form := url.Values{"password_organization": {f.member.OrganizationID}, "username": {"example"}, "password": {first}}
	page = f.submit(page.body, "password", form)
	f.status(page, 200)
	if !strings.Contains(page.body, "password is incorrect") {
		t.Fatal("credential from another organization was accepted")
	}
	form.Set("password", second)
	login := f.submit(page.body, "password", form)
	f.status(login, 303)
	login = f.call(f.browser, "GET", login.header.Get("Location"), nil, nil)
	f.status(login, 302)
	redirect, err := url.Parse(login.header.Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	tokens := f.exchange("second-web", redirect.Query().Get("code"), verifier)
	f.status(tokens, 200)
	issued := jsonObject(t, tokens)
	claims := f.signedClaims(issued["id_token"].(string))
	methods, ok := claims["amr"].([]any)
	if claims["sub"] != f.otherMember.ID || !ok || len(methods) != 1 || methods[0] != "pwd" {
		t.Fatal("issued token did not identify the password-authenticated Member")
	}
	refresh := issued["refresh_token"].(string)
	rotated := f.refresh("second-web", refresh, "")
	f.status(rotated, 200)
	activeRefresh := jsonObject(t, rotated)["refresh_token"].(string)
	if _, err = f.store.SetMemberPassword(t.Context(), operator, f.otherMember.OrganizationID, f.otherMember.ID, "example"); err != nil {
		t.Fatal(err)
	}
	f.invalidRefresh("second-web", activeRefresh)
	f.status(f.userinfo(issued["access_token"].(string)), 401)
}
