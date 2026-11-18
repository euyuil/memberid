//go:build integration

package oidcprovider

import (
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/euyuil/memberid/internal/identity"
)

func TestDirectOrganizationPasswordLoginOpensMemberAccount(t *testing.T) {
	f := newFixture(t)
	password, err := f.store.SetMemberPassword(t.Context(), identity.OperatorPrincipal(), f.member.OrganizationID, f.member.ID, "example")
	if err != nil {
		t.Fatal(err)
	}
	page := f.call(f.browser, "GET", "/login", nil, nil)
	f.status(page, http.StatusOK)
	if !strings.Contains(page.body, `value="choose-organization"`) || strings.Contains(page.body, `id="username"`) {
		t.Fatal("direct login did not start with organization selection")
	}
	selected := f.submit(page.body, "choose-organization", url.Values{"organization": {f.member.OrganizationID}})
	f.status(selected, http.StatusSeeOther)
	page = f.call(f.browser, "GET", selected.header.Get("Location"), nil, nil)
	f.status(page, http.StatusOK)
	result := f.submit(page.body, "password", url.Values{"username": {"example"}, "password": {password}})
	f.status(result, http.StatusSeeOther)
	if result.header.Get("Location") != "/account?memberId="+f.member.ID {
		t.Fatalf("direct password login redirected to %q", result.header.Get("Location"))
	}
	account := f.call(f.browser, "GET", result.header.Get("Location"), nil, nil)
	f.status(account, http.StatusOK)
	if !strings.Contains(account.body, "Example Member") {
		t.Fatal("direct login did not open the Member account")
	}
	var grants int
	if err := f.store.Database().QueryRow(t.Context(), "SELECT count(*) FROM oidc_grants").Scan(&grants); err != nil || grants != 0 {
		t.Fatal("direct login created an OIDC grant", grants, err)
	}
}

func TestBookmarkableOrganizationLoginReusesSessionWithoutClientConsent(t *testing.T) {
	f := newFixture(t)
	page := f.call(f.browser, "GET", "/login/"+f.member.OrganizationID, nil, nil)
	f.status(page, http.StatusOK)
	page = f.submit(page.body, "send", url.Values{"phone": {"19900000001"}})
	f.status(page, http.StatusOK)
	page = f.submit(page.body, "verify", url.Values{"code": {f.sender.latest()}})
	f.status(page, http.StatusOK)
	if !strings.Contains(page.body, "Continue to account") || strings.Contains(page.body, "Allow this application") {
		t.Fatal("direct login presented client authorization instead of account continuation")
	}
	result := f.submit(page.body, "continue", url.Values{"member": {f.member.ID}})
	f.status(result, http.StatusSeeOther)
	account := f.call(f.browser, "GET", result.header.Get("Location"), nil, nil)
	f.status(account, http.StatusOK)

	page = f.call(f.browser, "GET", "/login/"+f.member.OrganizationID, nil, nil)
	f.status(page, http.StatusOK)
	if !strings.Contains(page.body, "Continue to account") || strings.Contains(page.body, `id="phone"`) {
		t.Fatal("bookmarkable organization login did not reuse the current session")
	}
	result = f.submit(page.body, "continue", url.Values{"member": {f.member.ID}})
	f.status(result, http.StatusSeeOther)
	f.status(f.call(f.browser, "GET", result.header.Get("Location"), nil, nil), http.StatusOK)
}
