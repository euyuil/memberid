//go:build integration

package oidcprovider

import (
	"context"
	"net/url"
	"strings"
	"testing"

	"github.com/euyuil/memberid/internal/identity"
)

func TestConsoleFirstLoginWithProvisionedRoot(t *testing.T) {
	var password string
	f := newFixtureWithInitializer(t, false, func(ctx context.Context, databaseURL string) error {
		return identity.InitializeWithRoot(ctx, databaseURL, func(initialPassword string) error {
			password = initialPassword
			return nil
		})
	})
	server := consoleFixture(t, f)
	f.status(f.call(f.browser, "GET", server.URL+"/setup", nil, nil), 404)
	response := f.call(f.browser, "GET", server.URL+"/auth/login", nil, nil)
	f.status(response, 303)
	login := f.call(f.browser, "GET", response.header.Get("Location"), nil, nil)
	f.status(login, 302)
	login = f.call(f.browser, "GET", login.header.Get("Location"), nil, nil)
	f.status(login, 200)
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
