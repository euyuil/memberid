//go:build integration

package oidcprovider

import (
	"context"
	"net/url"
	"reflect"
	"strings"
	"testing"

	"github.com/zhizhun-tech/memberid/internal/identity"
)

func TestConsoleFirstLoginAndMemberPasswordManagement(t *testing.T) {
	var password string
	f := newFixtureWithInitializer(t, false, func(ctx context.Context, databaseURL string) error {
		return identity.InitializeWithRoot(ctx, databaseURL, func(initialPassword string) error {
			password = initialPassword
			return nil
		})
	})
	server := consoleFixture(t, f)
	f.status(f.call(f.browser, "GET", server.URL+"/setup", nil, nil), 404)
	loginPage := func(organizationID string) reply {
		t.Helper()
		response := f.call(f.browser, "GET", server.URL+"/auth/login", nil, nil)
		f.status(response, 303)
		response = f.call(f.browser, "GET", response.header.Get("Location"), nil, nil)
		f.status(response, 302)
		response = f.call(f.browser, "GET", response.header.Get("Location"), nil, nil)
		f.status(response, 200)
		return f.selectOrganization(response, organizationID)
	}
	finishLogin := func(response reply) {
		t.Helper()
		f.status(response, 303)
		response = f.call(f.browser, "GET", response.header.Get("Location"), nil, nil)
		f.status(response, 302)
		response = f.call(f.browser, "GET", response.header.Get("Location"), nil, nil)
		f.status(response, 303)
	}
	fields := url.Values{"username": {"ROOT@SYSTEM"}, "password": {"incorrect"}}
	login := f.submit(loginPage(f.store.SystemOrganizationID()).body, "password", fields)
	f.status(login, 200)
	if !strings.Contains(login.body, "password is incorrect") {
		t.Fatal("wrong password was not rejected")
	}
	fields.Set("password", password)
	finishLogin(f.submit(login.body, "password", fields))
	session := consoleJSON(t, f, server, "GET", "/api/session", "", "", 200)
	who := session["actor"].(map[string]any)
	if who["memberId"] != f.store.RootMemberID() || who["displayName"] != "root" ||
		who["organizationId"] != f.store.SystemOrganizationID() || who["platform"] != true {
		t.Fatal("root did not reach the console as platform administrator")
	}

	csrf := session["csrf"].(string)
	rootMemberID := who["memberId"].(string)
	target := "/api/organizations/" + f.otherMember.OrganizationID + "/members/" + f.otherMember.ID
	consoleJSON(t, f, server, "POST", target+"/password", "bad-token", `{"username":"example"}`, 403)
	consoleJSON(t, f, server, "POST", target+"/password", csrf, `{"username":"example","password":"caller-supplied"}`, 400)
	consoleJSON(t, f, server, "POST", "/api/organizations/"+f.member.OrganizationID+"/members/"+f.otherMember.ID+"/password", csrf, `{"username":"example"}`, 404)
	created := consoleJSON(t, f, server, "POST", target+"/password", csrf, `{"username":"Example"}`, 200)
	consoleJSON(t, f, server, "POST", target+"/password", csrf, `{"username":"other"}`, 409)
	generated, ok := created["password"].(string)
	if !ok || len(generated) != 32 || created["username"] != "example" {
		t.Fatal("the console did not return the generated Member credential")
	}
	detail := consoleJSON(t, f, server, "GET", target, "", "", 200)
	if len(detail["bindings"].([]any)) != 2 || detail["passwordUsername"] != "example" {
		t.Fatal("password setup did not preserve the Member's existing phone binding")
	}
	consoleJSON(t, f, server, "PATCH", target+"/password", "bad-token", `{"expectedUsername":"example","username":"member-login"}`, 403)
	consoleJSON(t, f, server, "PATCH", target+"/password", csrf, `{"expectedUsername":"EXAMPLE","username":"Member-Login"}`, 200)
	if result := consoleJSON(t, f, server, "PATCH", target+"/password", csrf, `{"expectedUsername":"MEMBER-LOGIN","username":"MEMBER-LOGIN"}`, 200); result["username"] != "member-login" {
		t.Fatal("case-only rename returned a noncanonical username", result)
	}
	renamed := consoleJSON(t, f, server, "GET", target, "", "", 200)
	if renamed["passwordUsername"] != "member-login" || !reflect.DeepEqual(renamed["bindings"], detail["bindings"]) {
		t.Fatal("changing a username changed the Member's bindings")
	}
	consoleJSON(t, f, server, "PUT", target+"/administrator", csrf, `{"enabled":true}`, 200)
	rootBrowser := f.browser
	f.browser = browserClient()
	memberFields := url.Values{"username": {"example"}, "password": {generated}}
	memberLogin := f.submit(loginPage(f.otherMember.OrganizationID).body, "password", memberFields)
	f.status(memberLogin, 200)
	if !strings.Contains(memberLogin.body, "password is incorrect") {
		t.Fatal("the old Member username was accepted")
	}
	memberFields.Set("username", "Member-LOGIN")
	finishLogin(f.submit(memberLogin.body, "password", memberFields))
	memberActor := consoleJSON(t, f, server, "GET", "/api/session", "", "", 200)["actor"].(map[string]any)
	if memberActor["memberId"] != f.otherMember.ID || memberActor["platform"] != false {
		t.Fatal("new credential did not sign in as the intended organization administrator")
	}
	f.browser = rootBrowser

	base := "/api/organizations/" + f.store.SystemOrganizationID() + "/members"
	rootCredential := base + "/" + rootMemberID + "/password"
	consoleJSON(t, f, server, "PATCH", rootCredential, csrf, `{"expectedUsername":"root","username":"platform-login"}`, 403)
	other := consoleJSON(t, f, server, "POST", base, csrf, `{"displayName":"Other system Member"}`, 200)
	otherCredential := base + "/" + other["id"].(string) + "/password"
	consoleJSON(t, f, server, "POST", otherCredential, csrf, `{"username":"Root"}`, 403)

	rootReset := rootCredential + "/reset"
	consoleJSON(t, f, server, "POST", rootReset, csrf, `{"username":"another-root"}`, 400)
	rotated := consoleJSON(t, f, server, "POST", rootReset, csrf, `{}`, 200)
	next, ok := rotated["password"].(string)
	if !ok || len(next) != 32 || next == password || rotated["username"] != "root" {
		t.Fatal("root password was not rotated under its existing username")
	}
	consoleJSON(t, f, server, "GET", "/api/session", "", "", 401)
	f.browser = browserClient()
	login = f.submit(loginPage(f.store.SystemOrganizationID()).body, "password", fields)
	f.status(login, 200)
	if !strings.Contains(login.body, "password is incorrect") {
		t.Fatal("old root password was accepted after rotation")
	}
	fields.Set("password", next)
	finishLogin(f.submit(login.body, "password", fields))
	for _, expected := range []struct{ organizationID, memberID, action string }{
		{f.otherMember.OrganizationID, f.otherMember.ID, "password.create"},
		{f.otherMember.OrganizationID, f.otherMember.ID, "password.username.update"},
		{f.store.SystemOrganizationID(), rootMemberID, "password.reset"},
	} {
		events := consoleJSON(t, f, server, "GET", "/api/events?organizationId="+expected.organizationID+"&memberId="+expected.memberID, "", "", 200)["items"].([]any)
		found := false
		for _, item := range events {
			event := item.(map[string]any)
			if event["action"] == expected.action {
				found = event["actor"] == rootMemberID && len(event["changes"].(map[string]any)) == 0 && len(event["previous"].(map[string]any)) == 0
				break
			}
		}
		if !found {
			t.Fatal("password mutation was not attributed to the console actor with an empty audit payload")
		}
	}
	recovered, err := f.store.ResetRootPassword(t.Context(), identity.OperatorPrincipal())
	if err != nil || recovered.Username != "root" || len(recovered.Password) != 32 || recovered.Password == next {
		t.Fatal("local recovery did not rotate the original root account", err)
	}
	f.browser = browserClient()
	fields.Set("password", recovered.Password)
	finishLogin(f.submit(loginPage(f.store.SystemOrganizationID()).body, "password", fields))
	who = consoleJSON(t, f, server, "GET", "/api/session", "", "", 200)["actor"].(map[string]any)
	if who["memberId"] != rootMemberID || who["platform"] != true {
		t.Fatal("local recovery changed the selected administrator")
	}
}

func TestPasswordLoginOrganizationIsolationAndRefreshRevocation(t *testing.T) {
	f := newConfiguredFixture(t, true)
	operator := identity.OperatorPrincipal()
	first, err := f.store.SetMemberPassword(t.Context(), operator, f.member.OrganizationID, f.member.ID, "Example")
	if err != nil {
		t.Fatal(err)
	}
	second, err := f.store.SetMemberPassword(t.Context(), operator, f.otherMember.OrganizationID, f.otherMember.ID, "example")
	if err != nil {
		t.Fatal(err)
	}
	page, verifier := f.loginPage("second-web", "openid offline_access")
	form := url.Values{"username": {"example"}, "password": {first}}
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
