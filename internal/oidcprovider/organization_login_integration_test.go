//go:build integration

package oidcprovider

import (
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/zhizhun-tech/memberid/internal/config"
	"github.com/zhizhun-tech/memberid/internal/identity"
)

func TestOrganizationFirstLoginBindsMethodsAndMembers(t *testing.T) {
	f := newFixture(t)
	f.updateClient("example-web", func(c *config.Client) { c.OrganizationID = "" })
	password, err := f.store.SetMemberPassword(t.Context(), identity.OperatorPrincipal(), f.member.OrganizationID, f.member.ID, "example")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.store.SetMemberPassword(t.Context(), identity.OperatorPrincipal(), f.otherMember.OrganizationID, f.otherMember.ID, "example"); err != nil {
		t.Fatal(err)
	}

	r, verifier := f.authorization("example-web", "openid profile", nil)
	f.status(r, http.StatusFound)
	r = f.call(f.browser, "GET", r.header.Get("Location"), nil, nil)
	f.status(r, http.StatusOK)
	if !strings.Contains(r.body, `value="choose-organization"`) || !strings.Contains(r.body, `id="username"`) || strings.Contains(r.body, `id="phone"`) {
		t.Fatal("common entry did not offer password sign-in and organization selection")
	}
	short := f.submit(r.body, "password", url.Values{"username": {"example"}, "password": {password}})
	f.status(short, http.StatusOK)
	if !strings.Contains(short.body, "select your organization below") {
		t.Fatal("short username did not require an explicit organization")
	}

	selected := f.submit(r.body, "choose-organization", url.Values{"organization": {f.member.OrganizationID}})
	f.status(selected, http.StatusSeeOther)
	organizationPath := "/login/" + f.member.OrganizationID
	if location := selected.header.Get("Location"); !strings.HasPrefix(location, organizationPath+"?request=") {
		t.Fatalf("organization selection redirected to %q", location)
	}
	r = f.call(f.browser, "GET", selected.header.Get("Location"), nil, nil)
	f.status(r, http.StatusOK)
	if !strings.Contains(r.body, `action="`+organizationPath+`"`) || !strings.Contains(r.body, "Example Team") || !strings.Contains(r.body, `id="username"`) || strings.Contains(r.body, `id="password_organization"`) {
		t.Fatal("organization login did not show only the selected organization's methods")
	}
	if strings.Contains(r.body, "Use a different organization") {
		t.Fatal("organization-specific login offered a conflicting organization switch")
	}
	otherPath := "/login/" + f.otherMember.OrganizationID + "?request=" + url.QueryEscape(hidden(t, r.body, "request"))
	f.status(f.call(f.browser, "GET", otherPath, nil, nil), http.StatusBadRequest)

	changed := f.submit(r.body, "cancel", nil)
	f.status(changed, http.StatusSeeOther)
	r = f.call(f.browser, "GET", changed.header.Get("Location"), nil, nil)
	f.status(r, http.StatusOK)
	if !strings.Contains(r.body, `action="`+organizationPath+`"`) || strings.Contains(r.body, `value="choose-organization"`) {
		t.Fatal("canceling verification lost the bound organization")
	}
	f.status(f.submit(r.body, "choose-organization", url.Values{"organization": {f.otherMember.OrganizationID}}), http.StatusBadRequest)
	r = f.submit(r.body, "password", url.Values{"username": {"example"}, "password": {password}})
	f.status(r, http.StatusOK)
	if !strings.Contains(r.body, `<option value="`+f.member.ID+`" selected>`) || strings.Contains(r.body, `<option value="`+f.otherMember.ID+`">`) {
		t.Fatal("verified identities were not limited to the selected organization")
	}
	code := f.complete(r, f.member.ID)
	f.status(f.exchange("example-web", code, verifier), http.StatusOK)
}

func TestCommonQualifiedPasswordLogin(t *testing.T) {
	f := newFixture(t)
	f.updateClient("example-web", func(c *config.Client) { c.OrganizationID = "" })
	ctx, op := t.Context(), identity.OperatorPrincipal()
	for _, member := range []identity.Member{f.member, f.otherMember} {
		password, err := f.store.SetMemberPassword(ctx, op, member.OrganizationID, member.ID, "casey")
		if err != nil {
			t.Fatal(err)
		}
		suffix := member.OrganizationID
		if member.ID == f.member.ID {
			suffix = "north"
			f.seedOrganizationSlug(member.OrganizationID, suffix)
		}
		fields := url.Values{"username": {"Casey@" + suffix}, "password": {password}}
		f.browser = browserClient()
		common := f.openDirectLogin("/login")
		result := f.submitDirect(common, "/login", "password", fields)
		f.status(result, http.StatusSeeOther)
		if result.header.Get("Location") != "/account?memberId="+member.ID {
			t.Fatal("direct sign-in did not open the expected Member account")
		}

		f.browser = browserClient()
		start, verifier := f.authorization("example-web", "openid", nil)
		common = f.call(f.browser, "GET", start.header.Get("Location"), nil, nil)
		consent := f.submit(common.body, "password", fields)
		f.status(consent, http.StatusOK)
		if !strings.Contains(consent.body, `action="/login/`+member.OrganizationID+`"`) {
			t.Fatal("consent was not bound to the selected organization")
		}
		tokens := f.exchange("example-web", f.complete(consent, member.ID), verifier)
		f.status(tokens, http.StatusOK)
		if f.signedClaims(jsonObject(t, tokens)["id_token"].(string))["sub"] != member.ID {
			t.Fatal("application sign-in returned the wrong subject")
		}
	}
}

func TestCommonAndScopedPasswordAttemptLimit(t *testing.T) {
	f := newFixture(t)
	member := f.member
	ctx, op := t.Context(), identity.OperatorPrincipal()
	password, err := f.store.SetMemberPassword(ctx, op, member.OrganizationID, member.ID, "casey")
	if err != nil {
		t.Fatal(err)
	}
	f.seedOrganizationSlug(member.OrganizationID, "north")
	path := "/login/" + member.OrganizationID
	common := f.openDirectLogin("/login")
	fields := url.Values{"username": {"CASEY@NORTH"}, "password": {"incorrect"}}
	page := f.submitDirect(common, "/login", "password", fields)
	fields.Set("username", "casey@"+member.OrganizationID)
	for i := 1; i < 10; i++ {
		if !strings.Contains(page.body, `action="`+path+`"`) || !strings.Contains(page.body, "password is incorrect") {
			t.Fatalf("attempt %d did not preserve the scoped retry", i)
		}
		page = f.submitDirect(page, path, "password", fields)
	}
	fields.Set("username", "casey")
	fields.Set("password", password)
	page = f.submitDirect(page, path, "password", fields)
	if !strings.Contains(page.body, "Too many sign-in attempts") {
		t.Fatal("common and scoped entries did not share the password attempt limit")
	}
}

func TestScopedQualifiedPasswordUsername(t *testing.T) {
	f := newFixture(t)
	ctx, op := t.Context(), identity.OperatorPrincipal()
	for _, member := range []identity.Member{f.member, f.otherMember} {
		password, err := f.store.SetMemberPassword(ctx, op, member.OrganizationID, member.ID, "Casey")
		if err != nil {
			t.Fatal(err)
		}
		path := "/login/" + member.OrganizationID
		signIn := func(input, suffix string, ok bool) {
			t.Helper()
			f.browser = browserClient()
			page := f.openDirectLogin(path)
			if !strings.Contains(page.body, `data-suffix="`+suffix+`"`) {
				t.Fatal("missing preferred password suffix", suffix)
			}
			response := f.submitDirect(page, path, "password", url.Values{"username": {input}, "password": {password}})
			if ok {
				f.status(response, http.StatusSeeOther)
				if response.header.Get("Location") != "/account?memberId="+member.ID {
					t.Fatal("qualified username selected the wrong Member")
				}
			} else {
				f.status(response, http.StatusOK)
				if !strings.Contains(response.body, "does not match this organization") {
					t.Fatal("expected organization mismatch", input)
				}
			}
		}
		signIn("Casey@"+member.OrganizationID, member.OrganizationID, true)
		if member.ID == f.member.ID {
			f.seedOrganizationSlug(member.OrganizationID, "north")
			signIn("CASEY@NORTH", "north", true)
			signIn("Casey@"+member.OrganizationID, "north", true)
			signIn("casey@"+f.otherMember.OrganizationID, "north", false)
		} else {
			signIn("casey@north", member.OrganizationID, false)
			signIn("casey@unknown", member.OrganizationID, false)
			signIn("casey@@north", member.OrganizationID, false)
			signIn("casey@", member.OrganizationID, false)
		}
	}
}

func TestReassignedSlugPasswordLogin(t *testing.T) {
	f := newFixture(t)
	a, b := f.member, f.otherMember
	original, err := f.store.SetMemberPassword(t.Context(), identity.OperatorPrincipal(), a.OrganizationID, a.ID, "casey")
	if err != nil {
		t.Fatal(err)
	}
	other, err := f.store.SetMemberPassword(t.Context(), identity.OperatorPrincipal(), b.OrganizationID, b.ID, "casey")
	if err != nil {
		t.Fatal(err)
	}
	f.seedOrganizationSlug(a.OrganizationID, "old-team")
	path := "/login/" + a.OrganizationID
	page := f.openDirectLogin(path)
	bound := f.submitDirect(page, path, "password", url.Values{"username": {"casey"}, "password": {"wrong"}})
	f.status(bound, http.StatusOK)
	if _, err := f.store.Database().Exec(t.Context(), "UPDATE organization_login_slugs SET slug='new-team' WHERE organization_id=$1", a.OrganizationID); err != nil {
		t.Fatal(err)
	}
	f.status(f.call(f.browser, "GET", "/login/old-team", nil, nil), http.StatusNotFound)
	f.seedOrganizationSlug(b.OrganizationID, "old-team")
	for slug, id := range map[string]string{"new-team": a.OrganizationID, "old-team": b.OrganizationID} {
		r := f.call(f.browser, "GET", "/login/"+slug, nil, nil)
		f.status(r, http.StatusSeeOther)
		if r.header.Get("Location") != "/login/"+id {
			t.Fatal("wrong bookmark", slug)
		}
	}
	rejected := f.submitDirect(bound, path, "password", url.Values{"username": {"casey@old-team"}, "password": {other}})
	f.status(rejected, http.StatusOK)
	if !strings.Contains(rejected.body, "does not match this organization") {
		t.Fatal("reassigned suffix changed the bound organization")
	}
	finish := f.submitDirect(rejected, path, "password", url.Values{"username": {"casey@" + a.OrganizationID}, "password": {original}})
	f.status(finish, http.StatusSeeOther)
	if finish.header.Get("Location") != "/account?memberId="+a.ID {
		t.Fatal("permanent ID selected wrong Member")
	}
	for _, tc := range []struct{ suffix, password, id string }{{"old-team", other, b.ID}, {"new-team", original, a.ID}} {
		f.browser = browserClient()
		start := f.openDirectLogin("/login")
		r := f.submitDirect(start, "/login", "password", url.Values{"username": {"casey@" + tc.suffix}, "password": {tc.password}})
		f.status(r, http.StatusSeeOther)
		if r.header.Get("Location") != "/account?memberId="+tc.id {
			t.Fatal("wrong qualified login", tc.suffix)
		}
	}
}

func TestProviderLoginNames(t *testing.T) {
	f := newFixture(t)
	enableDingTalk(t, f, true)
	ctx, operator := t.Context(), identity.OperatorPrincipal()
	third, err := f.store.CreateOrganization(ctx, operator, "", "Callback team")
	if err != nil {
		t.Fatal(err)
	}
	for name, id := range map[string]string{"dingtalk": f.member.OrganizationID, "feishu": f.otherMember.OrganizationID, "callback": third.ID} {
		f.seedOrganizationSlug(id, name)
		bookmark := f.call(f.browser, "GET", "/login/"+name, nil, nil)
		f.status(bookmark, http.StatusSeeOther)
		if bookmark.header.Get("Location") != "/login/"+id {
			t.Fatal("wrong bookmark destination", name)
		}
		page := f.openDirectLogin(bookmark.header.Get("Location"))
		if name != "dingtalk" {
			continue
		}
		start := f.submitDirect(page, "/login/"+id, "dingtalk", url.Values{"organization": {id}})
		f.status(start, http.StatusSeeOther)
		upstream, err := url.Parse(start.header.Get("Location"))
		if err != nil || upstream.Query().Get("redirect_uri") != f.server.URL+"/auth/dingtalk/callback" {
			t.Fatal("unexpected DingTalk redirect", err)
		}
		callback := "/auth/dingtalk/callback?" + url.Values{"state": {upstream.Query().Get("state")}, "authCode": {"synthetic-code"}}.Encode()
		back := f.call(f.browser, "GET", callback, nil, nil)
		f.status(back, http.StatusSeeOther)
		page = f.call(f.browser, "GET", back.header.Get("Location"), nil, nil)
		f.status(page, http.StatusOK)
		member := admittedMember(t, f, id)
		finish := f.submit(page.body, "continue", url.Values{"member": {member}})
		f.status(finish, http.StatusSeeOther)
		if finish.header.Get("Location") != "/account?memberId="+member {
			t.Fatal("direct DingTalk login did not open the organization's Member account")
		}
	}
}

func (f *fixture) seedOrganizationSlug(id, slug string) {
	f.t.Helper()
	if _, err := f.store.Database().Exec(f.t.Context(), "INSERT INTO organization_login_slugs(organization_id,slug) VALUES($1,$2)", id, slug); err != nil {
		f.t.Fatal(err)
	}
}

func TestOrganizationSlugLogin(t *testing.T) {
	f := newFixture(t)
	_, apps := enableDingTalk(t, f, true)
	id := f.member.OrganizationID
	path := "/login/" + id
	for slug, org := range map[string]string{"team-one": id, "team-two": f.otherMember.OrganizationID} {
		f.seedOrganizationSlug(org, slug)
	}
	alias := func(slug, query, want string) string {
		t.Helper()
		r := f.call(f.browser, "GET", "/login/"+slug+query, nil, nil)
		f.status(r, http.StatusSeeOther)
		if location := r.header.Get("Location"); location != want {
			t.Fatalf("alias redirected to %q, want %q", location, want)
		}
		return want
	}
	f.openDirectLogin(alias("Team-One", "?returnTo=https://example.invalid", path))
	name := "Renamed team"
	if _, err := f.store.UpdateOrganization(t.Context(), identity.OperatorPrincipal(), id, identity.OrganizationChange{Name: &name}); err != nil {
		t.Fatal(err)
	}
	app, err := apps.Inspect(t.Context(), id)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := apps.Configure(t.Context(), identity.OperatorPrincipal(), id, identity.DingTalkApplicationInput{
		CorpID: app.CorpID, ClientID: app.ClientID, ClientSecret: config.RandomSecret(), ExpectedRevision: app.Revision,
	}); err != nil {
		t.Fatal(err)
	}
	page := f.openDirectLogin(alias("team-one", "", path))
	if !strings.Contains(page.body, name) || !strings.Contains(page.body, `value="dingtalk"`) {
		t.Fatal("alias did not reflect the organization's current name and provider")
	}
	f.checkDirectCount(0)
	f.status(f.submitDirect(page, "/login/"+f.otherMember.OrganizationID, "send", url.Values{"phone": {"19900000001"}}), http.StatusForbidden)
	f.status(f.submitDirect(page, path, "send", url.Values{"phone": {"19900000001"}}), http.StatusOK)
	f.checkDirectCount(1)
	start, _ := f.authorization("example-web", "openid", nil)
	f.status(start, http.StatusFound)
	location, err := url.Parse(start.header.Get("Location"))
	if err != nil || location.RawQuery == "" {
		t.Fatal("missing authorization transaction", err)
	}
	query := "?" + location.RawQuery
	other := alias("team-two", query, "/login/"+f.otherMember.OrganizationID+query)
	f.status(f.call(f.browser, "GET", other, nil, nil), http.StatusBadRequest)
	correct := alias("team-one", query, path+query)
	f.status(f.call(browserClient(), "GET", correct, nil, nil), http.StatusBadRequest)
	f.status(f.call(f.browser, "GET", correct, nil, nil), http.StatusOK)
	f.status(f.call(f.browser, "GET", "/login/unknown-slug", nil, nil), http.StatusNotFound)
	f.status(f.call(f.browser, "POST", "/login/team-one", nil, nil), http.StatusMethodNotAllowed)
}
