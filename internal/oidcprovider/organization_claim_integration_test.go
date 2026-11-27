//go:build integration

package oidcprovider

import (
	"fmt"
	"net/url"
	"slices"
	"strings"
	"testing"

	"github.com/zhizhun-tech/memberid/internal/identity"
)

func TestOIDCOrganizationScope(t *testing.T) {
	f := newFixture(t)
	ctx, op := t.Context(), identity.OperatorPrincipal()
	a, b := f.member, f.otherMember // Distinct Members bound to the same verified phone.
	for _, m := range []identity.Member{a, b} {
		if err := f.store.SetAdministrator(ctx, op, m.OrganizationID, m.ID, true); err != nil {
			t.Fatal(err)
		}
	}
	another, err := f.store.CreateMember(ctx, op, a.OrganizationID, "", "Second employee")
	if err != nil {
		t.Fatal(err)
	}
	password, err := f.store.SetMemberPassword(ctx, op, a.OrganizationID, another.ID, "second")
	if err != nil {
		t.Fatal(err)
	}
	server := consoleFixture(t, f)
	login := func(m identity.Member) string {
		t.Helper()
		consoleLogin(t, f, server, m.ID)
		return consoleJSON(t, f, server, "GET", "/api/session", "", "", 200)["csrf"].(string)
	}
	base := func(m identity.Member) string { return "/api/organizations/" + m.OrganizationID + "/oidc-applications" }
	csrf := login(a)
	app := consoleJSON(t, f, server, "POST", base(a), csrf, fmt.Sprintf(`{"displayName":"Workspace","redirectUris":[%q],"refresh":true}`, callback), 200)
	meta := app["application"].(map[string]any)
	if meta["allowOrganizationScope"] != false {
		t.Fatal("default must be off")
	}
	id := meta["clientId"].(string)
	f.secret = app["clientSecret"].(string)
	consoleJSON(t, f, server, "PUT", base(a)+"/"+id+"/publication", csrf, `{"enabled":true}`, 200)
	csrf = login(b)
	consoleJSON(t, f, server, "PUT", base(b)+"/"+id+"/enablement", csrf, `{"enabled":true}`, 200)
	csrf = login(a)
	const ordinary = "openid profile offline_access"
	const withOrg = ordinary + " " + identity.OrganizationScope
	token := func(m identity.Member, scope string) map[string]any {
		t.Helper()
		r, verifier := f.authorization(id, scope, nil)
		f.status(r, 302)
		r = f.call(f.browser, "GET", r.header.Get("Location"), nil, nil)
		r = f.selectOrganization(r, m.OrganizationID)
		if m.ID == another.ID {
			r = f.submit(r.body, "password", url.Values{"username": {"second"}, "password": {password}})
			f.status(r, 200)
		} else if strings.Contains(r.body, `id="phone"`) {
			r = f.verifyPhone(r)
		}
		result := f.exchange(id, f.complete(r, m.ID), verifier)
		f.status(result, 200)
		return jsonObject(t, result)
	}
	check := func(tokens map[string]any, m identity.Member, want bool) {
		t.Helper()
		claims := f.signedClaims(tokens["id_token"].(string))
		audiences, _ := claims["aud"].([]any)
		if !slices.Contains(audiences, any(id)) {
			t.Fatal("ID token not addressed to client")
		}
		org, exists := claims["organizationId"]
		if claims["sub"] != m.ID || claims["iss"] != f.server.URL || exists != want || want && org != m.OrganizationID {
			t.Fatal("unexpected signed organization or subject", m.ID, want)
		}
		access := f.signedClaims(tokens["access_token"].(string))
		info := f.userinfo(tokens["access_token"].(string))
		f.status(info, 200)
		user := jsonObject(t, info)
		if access["organizationId"] != nil || user["organizationId"] != nil {
			t.Fatal("organization claim escaped the ID token")
		}
		for _, values := range []map[string]any{claims, access, user} {
			for _, key := range []string{"authentication", "memberId", "factorId", "bindingId", "memberships", "roles"} {
				if _, ok := values[key]; ok {
					t.Fatal("unexpected claim", key)
				}
			}
		}
	}
	advertised := func(want bool) {
		t.Helper()
		discovery := jsonObject(t, f.call(f.browser, "GET", "/.well-known/openid-configuration", nil, nil))
		scopes, _ := discovery["scopes_supported"].([]any)
		claims, _ := discovery["claims_supported"].([]any)
		if slices.Contains(scopes, any(identity.OrganizationScope)) != want || slices.Contains(claims, any("organizationId")) != want {
			t.Fatal("discovery mismatch")
		}
	}
	advertised(false)
	check(token(a, ordinary), a, false)
	// The protocol library drops an unregistered optional scope before consent.
	check(token(a, withOrg), a, false)
	set := func(enabled bool) {
		t.Helper()
		reg, err := f.store.OIDCClient(ctx, id)
		if err != nil {
			t.Fatal(err)
		}
		body := fmt.Sprintf(`{"displayName":"Workspace","redirectUris":[%q],"refresh":true,"expectedRevision":%d,"allowOrganizationScope":%t}`, callback, reg.Revision, enabled)
		got := consoleJSON(t, f, server, "PATCH", base(a)+"/"+id, csrf, body, 200)["application"].(map[string]any)
		if got["allowOrganizationScope"] != enabled {
			t.Fatal("opt-in did not persist")
		}
	}
	set(true)
	advertised(true)
	plain := token(b, ordinary)
	check(plain, b, false)
	check(token(a, withOrg), a, true)
	original := token(b, withOrg)
	check(original, b, true)
	name := "Renamed consumer"
	if _, err = f.store.UpdateOrganization(ctx, op, b.OrganizationID, identity.OrganizationChange{Name: &name}); err != nil {
		t.Fatal(err)
	}
	refresh := f.refresh(id, original["refresh_token"].(string), "")
	f.status(refresh, 200)
	renewed := jsonObject(t, refresh)
	check(renewed, b, true)
	narrowed := f.refresh(id, renewed["refresh_token"].(string), "openid profile")
	f.status(narrowed, 200)
	check(jsonObject(t, narrowed), b, false)
	ownerBrowser := f.browser
	f.browser = browserClient()
	check(token(another, withOrg), another, true)
	f.browser = ownerBrowser
	scoped := token(a, withOrg)
	set(false)
	advertised(false)
	set(true)
	f.invalidRefresh(id, scoped["refresh_token"].(string))
	f.status(f.refresh(id, plain["refresh_token"].(string), ""), 200)
}
