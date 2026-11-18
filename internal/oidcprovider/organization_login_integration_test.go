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
	if !strings.Contains(r.body, `value="choose-organization"`) {
		t.Fatal("changing organization did not restore the selection step")
	}
	r = f.selectOrganization(r, f.member.OrganizationID)
	r = f.submit(r.body, "password", url.Values{"username": {"example"}, "password": {password}})
	f.status(r, http.StatusOK)
	if !strings.Contains(r.body, `<option value="`+f.member.ID+`" selected>`) || strings.Contains(r.body, `<option value="`+f.otherMember.ID+`">`) {
		t.Fatal("verified identities were not limited to the selected organization")
	}
	code := f.complete(r, f.member.ID)
	f.status(f.exchange("example-web", code, verifier), http.StatusOK)
}
