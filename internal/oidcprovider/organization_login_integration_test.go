//go:build integration

package oidcprovider

import (
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/euyuil/memberid/internal/config"
	"github.com/euyuil/memberid/internal/identity"
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
	if !strings.Contains(r.body, `value="choose-organization"`) || strings.Contains(r.body, `id="username"`) || strings.Contains(r.body, `id="phone"`) {
		t.Fatal("organization selection did not precede authentication methods")
	}
	f.status(f.submit(r.body, "password", url.Values{"username": {"example"}, "password": {password}}), http.StatusBadRequest)

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

func TestOrganizationSlugLogin(t *testing.T) {
	f := newFixture(t)
	_, apps := enableDingTalk(t, f, true)
	id := f.member.OrganizationID
	path := "/login/" + id
	for slug, org := range map[string]string{"team-one": id, "team-two": f.otherMember.OrganizationID} {
		if err := f.store.AssignOrganizationSlug(t.Context(), identity.OperatorPrincipal(), org, slug); err != nil {
			t.Fatal(err)
		}
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
	f.openDirectLogin(alias("team-one", "?returnTo=https://example.invalid", path))
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
