//go:build integration

package oidcprovider

import (
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/zhizhun-tech/memberid/internal/identity"
)

func TestAccountFirstLoginNameJourney(t *testing.T) {
	f := newFixture(t)
	ctx := t.Context()
	op := identity.OperatorPrincipal()
	m := f.member
	// Both test Members have an independent binding to the same verified phone.
	if err := f.store.SetAdministrator(ctx, op, m.OrganizationID, m.ID, true); err != nil {
		t.Fatal(err)
	}
	page, _ := f.loginPage("example-web", "openid")
	f.verifyPhone(page)
	home := func(member string) reply { return f.call(f.browser, "GET", "/account?memberId="+member, nil, nil) }
	form := home(m.ID)
	f.status(form, 200)
	csrf := hidden(t, form.body, "csrf")
	post := func(member, token, name, origin string) reply {
		return f.call(f.browser, "POST", "/account", url.Values{"memberId": {member}, "csrf": {token}, "username": {name}}, map[string]string{"Origin": origin})
	}
	f.status(post(m.ID, csrf, "alpha", "https://example.invalid"), 403)
	f.status(post(f.otherMember.ID, csrf, "alpha", f.server.URL), 403)
	f.status(post(m.ID, "missing", "alpha", f.server.URL), 403)
	at := time.Now()
	f.service.now = func() time.Time { return at.Add(accountLifetime + time.Second) }
	f.status(post(m.ID, csrf, "alpha", f.server.URL), 401)
	f.service.now = time.Now
	taken, err := f.store.CreateMember(ctx, op, m.OrganizationID, "", "Another member")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = f.store.SetMemberPassword(ctx, op, m.OrganizationID, taken.ID, "taken"); err != nil {
		t.Fatal(err)
	}
	occupied := post(m.ID, csrf, "TAKEN", f.server.URL)
	f.status(occupied, 409)
	if !strings.Contains(occupied.body, "Choose another") {
		t.Fatal("missing occupied-name feedback")
	}
	outcomes := make(chan reply, 2)
	for range 2 {
		go func() { outcomes <- post(m.ID, csrf, "Casey", f.server.URL) }()
	}
	a, b := <-outcomes, <-outcomes
	if !(a.status == 303 && b.status == 409 || a.status == 409 && b.status == 303) {
		t.Fatal("concurrent self-service outcomes", a.status, b.status)
	}
	f.status(post(m.ID, csrf, "replacement", f.server.URL), 409)
	current := home(m.ID)
	f.status(current, 200)
	if !strings.Contains(current.body, ">casey<") || strings.Contains(current.body, `name="username"`) {
		t.Fatal("account page did not display read-only canonical username")
	}
	other := home(f.otherMember.ID)
	f.status(other, 200)
	f.status(post(f.otherMember.ID, hidden(t, other.body, "csrf"), "Casey", f.server.URL), 303)
	bindings, err := f.store.Bindings(ctx, m.OrganizationID, m.ID)
	if err != nil || len(bindings) != 1 || bindings[0].FactorType != "phone" {
		t.Fatal("first assignment changed external sign-in methods", err)
	}
	password, err := f.store.SetMemberPassword(ctx, op, m.OrganizationID, m.ID, "casey")
	if err != nil {
		t.Fatal(err)
	}
	f.browser = browserClient()
	page, verifier := f.loginPage("example-web", "openid")
	verified := f.submit(page.body, "password", url.Values{"username": {"Casey"}, "password": {password}})
	f.status(verified, http.StatusOK)
	tokens := f.exchange("example-web", f.complete(verified, m.ID), verifier)
	f.status(tokens, 200)
	if f.signedClaims(jsonObject(t, tokens)["id_token"].(string))["sub"] != m.ID {
		t.Fatal("first password changed OIDC subject")
	}
}

func TestDingTalkFirstLoginNameKeepsOIDCSubject(t *testing.T) {
	f := newFixture(t)
	enableDingTalk(t, f, false)
	org := f.member.OrganizationID
	_, verifier, callbackPath := beginDingTalk(t, f, "example-web", "openid", org)
	callback := f.call(f.browser, "GET", callbackPath, nil, nil)
	f.status(callback, 303)
	consent := f.call(f.browser, "GET", callback.header.Get("Location"), nil, nil)
	member := admittedMember(t, f, org)
	subject := func(page reply, v string) string {
		tokens := f.exchange("example-web", f.complete(page, member), v)
		f.status(tokens, 200)
		return f.signedClaims(jsonObject(t, tokens)["id_token"].(string))["sub"].(string)
	}
	before := subject(consent, verifier)
	account := f.call(f.browser, "GET", "/account?memberId="+member, nil, nil)
	f.status(account, 200)
	f.status(f.call(f.browser, "POST", "/account", url.Values{"memberId": {member}, "csrf": {hidden(t, account.body, "csrf")}, "username": {"Casey"}}, map[string]string{"Origin": f.server.URL}), 303)
	bindings, err := f.store.Bindings(t.Context(), org, member)
	if err != nil || len(bindings) != 1 || bindings[0].FactorType != "dingtalk" {
		t.Fatal("DingTalk binding changed", err)
	}
	password, err := f.store.SetMemberPassword(t.Context(), identity.OperatorPrincipal(), org, member, "casey")
	if err != nil {
		t.Fatal(err)
	}
	f.browser = browserClient()
	page, verifier := f.loginPage("example-web", "openid")
	confirmed := f.submit(page.body, "password", url.Values{"username": {"casey"}, "password": {password}})
	if after := subject(confirmed, verifier); before != member || after != before {
		t.Fatal("different OIDC subject after password provisioning")
	}
}
