//go:build integration

package oidcprovider

import (
	"fmt"
	"net/url"
	"strings"
	"sync"
	"testing"

	"github.com/zhizhun-tech/memberid/internal/identity"
)

func TestOIDCSharingWithdrawal(t *testing.T) {
	f := newFixture(t)
	ctx, operator := t.Context(), identity.OperatorPrincipal()
	owner, b := f.member, f.otherMember
	org, err := f.store.CreateOrganization(ctx, operator, "", "Third team")
	if err != nil {
		t.Fatal(err)
	}
	c, err := f.store.CreateMember(ctx, operator, org.ID, "", "Third administrator")
	if err != nil {
		t.Fatal(err)
	}
	factor, err := f.store.EnsureFactor(ctx, "phone", "phone:e164", "+8619900000001")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.store.BindFactor(ctx, operator, org.ID, c.ID, factor.ID); err != nil {
		t.Fatal(err)
	}
	for _, m := range []identity.Member{owner, b, c} {
		if err := f.store.SetAdministrator(ctx, operator, m.OrganizationID, m.ID, true); err != nil {
			t.Fatal(err)
		}
	}
	server := consoleFixture(t, f)
	login := func(m identity.Member) string {
		t.Helper()
		consoleLogin(t, f, server, m.ID)
		return consoleJSON(t, f, server, "GET", "/api/session", "", "", 200)["csrf"].(string)
	}
	base := func(m identity.Member) string { return "/api/organizations/" + m.OrganizationID + "/oidc-applications" }
	csrf := login(owner)
	created := consoleJSON(t, f, server, "POST", base(owner), csrf, fmt.Sprintf(`{"displayName":"Shared app","redirectUris":[%q],"refresh":true}`, callback), 200)
	id := created["application"].(map[string]any)["clientId"].(string)
	f.secret = created["clientSecret"].(string)
	put := func(target identity.Member, action string, enabled bool, status int) {
		t.Helper()
		consoleJSON(t, f, server, "PUT", base(target)+"/"+id+"/"+action, csrf, fmt.Sprintf(`{"enabled":%t}`, enabled), status)
	}
	page := func(m identity.Member) (reply, string) {
		t.Helper()
		r, verifier := f.authorization(id, "openid profile offline_access", nil)
		f.status(r, 302)
		r = f.call(f.browser, "GET", r.header.Get("Location"), nil, nil)
		f.status(r, 200)
		return f.selectOrganization(r, m.OrganizationID), verifier
	}
	code := func(m identity.Member) (string, string) {
		t.Helper()
		r, verifier := page(m)
		if strings.Contains(r.body, `id="phone"`) {
			r = f.verifyPhone(r)
		}
		return f.complete(r, m.ID), verifier
	}
	grant := func(m identity.Member) (string, string) {
		t.Helper()
		v, pkce := code(m)
		r := f.exchange(id, v, pkce)
		f.status(r, 200)
		tokens := jsonObject(t, r)
		if f.signedClaims(tokens["id_token"].(string))["sub"] != m.ID {
			t.Fatal("wrong Member subject")
		}
		return tokens["access_token"].(string), tokens["refresh_token"].(string)
	}
	_, ownerToken := grant(owner)
	put(b, "enablement", true, 403)
	csrf = login(b)
	put(b, "enablement", true, 404)
	put(owner, "publication", true, 403)
	csrf = login(owner)
	put(owner, "publication", true, 200)
	csrf = login(b)
	r, _ := page(b)
	if !strings.Contains(r.body, "Enter a valid organization ID.") {
		t.Fatal("unsubscribed consumer selected")
	}
	var duplicate sync.WaitGroup
	for range 2 {
		duplicate.Go(func() { put(b, "enablement", true, 200) })
	}
	duplicate.Wait()
	bAccess, bRefresh := grant(b)
	pending, pkce := code(b)
	interaction, _ := page(b)
	csrf = login(c)
	put(c, "enablement", true, 200)
	_, cRefresh := grant(c)
	csrf = login(b)
	rotated := make(chan reply, 1)
	go func(token string) { rotated <- f.refresh(id, token, "") }(bRefresh)
	put(b, "enablement", false, 200)
	switch result := <-rotated; result.status {
	case 200:
		f.invalidRefresh(id, jsonObject(t, result)["refresh_token"].(string))
	case 400:
		if jsonObject(t, result)["error"] != "invalid_grant" {
			t.Fatal("unexpected refresh failure")
		}
	default:
		t.Fatal("unexpected concurrent refresh status", result.status)
	}
	put(b, "enablement", false, 200)
	f.status(f.userinfo(bAccess), 401)
	f.invalidRefresh(id, bRefresh)
	put(b, "enablement", true, 200)
	f.status(f.exchange(id, pending, pkce), 400)
	f.status(f.submit(interaction.body, "continue", url.Values{"member": {b.ID}, "consent": {"yes"}}), 400)
	f.invalidRefresh(id, bRefresh)
	r = f.refresh(id, cRefresh, "")
	f.status(r, 200)
	cRefresh = jsonObject(t, r)["refresh_token"].(string)
	_, bRefresh = grant(b)
	csrf = login(owner)
	put(owner, "publication", false, 200)
	f.invalidRefresh(id, bRefresh)
	f.invalidRefresh(id, cRefresh)
	f.status(f.refresh(id, ownerToken, ""), 200)
	put(owner, "publication", true, 200)
	for _, m := range []identity.Member{b, c} {
		r, _ := page(m)
		if !strings.Contains(r.body, "Enter a valid organization ID.") {
			t.Fatal("republishing restored a consumer")
		}
	}
	csrf = login(c)
	put(c, "enablement", true, 200)
	_, cRefresh = grant(c)
	_, ownerToken = grant(owner)
	csrf = login(owner)
	reg, err := f.store.OIDCClient(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	consoleJSON(t, f, server, "PATCH", base(owner)+"/"+id, csrf, fmt.Sprintf(`{"enabled":false,"expectedRevision":%d}`, reg.Revision), 200)
	f.status(f.refresh(id, cRefresh, ""), 401)
	f.status(f.refresh(id, ownerToken, ""), 401)
	var count int
	if err := f.store.Database().QueryRow(ctx, "SELECT count(*) FROM management_events WHERE organization_id=$1 AND actor=$2 AND action='oidc.application.enablement.update'", b.OrganizationID, b.ID).Scan(&count); err != nil || count != 3 {
		t.Fatal("consumer audit", count, err)
	}
}
