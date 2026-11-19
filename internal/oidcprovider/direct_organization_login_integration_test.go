//go:build integration

package oidcprovider

import (
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/euyuil/memberid/internal/identity"
)

func TestOrganizationLoginLookupErrors(t *testing.T) {
	f := newFixture(t)
	page := f.call(f.browser, "GET", "/login", nil, nil)
	f.status(page, http.StatusOK)
	requestQuery := "?request=" + url.QueryEscape(hidden(t, page.body, "request"))
	selectOrganization := func(organizationID string) reply {
		return f.submit(page.body, "choose-organization", url.Values{"organization": {organizationID}})
	}
	checkResponse := func(response reply, status int, message string) {
		t.Helper()
		f.status(response, status)
		if strings.TrimSpace(response.body) != message {
			t.Fatalf("response body = %q, want %q", response.body, message)
		}
	}

	unknownID, err := identity.NewID(identity.OrganizationKind)
	if err != nil {
		t.Fatal(err)
	}
	disabled := "disabled"
	if _, err := f.store.UpdateOrganization(t.Context(), identity.OperatorPrincipal(), f.otherMember.OrganizationID, identity.OrganizationChange{Status: &disabled}); err != nil {
		t.Fatal(err)
	}
	for _, organizationID := range []string{unknownID, f.otherMember.OrganizationID} {
		path := "/login/" + organizationID
		for _, target := range []string{path, path + requestQuery} {
			checkResponse(f.call(f.browser, "GET", target, nil, nil), http.StatusNotFound, "Organization login is unavailable")
		}
	}
	for _, organizationID := range []string{"invalid id", unknownID, f.otherMember.OrganizationID} {
		response := selectOrganization(organizationID)
		f.status(response, http.StatusOK)
		if !strings.Contains(response.body, "Enter a valid organization ID.") {
			t.Fatalf("missing organization ID validation message for %q", organizationID)
		}
	}

	// Break organization reads while leaving the stored login transaction readable.
	if _, err := f.store.Database().Exec(t.Context(), "ALTER TABLE organizations RENAME TO unavailable_organizations"); err != nil {
		t.Fatal(err)
	}
	path := "/login/" + f.member.OrganizationID
	for _, target := range []string{path, path + requestQuery} {
		checkResponse(f.call(f.browser, "GET", target, nil, nil), http.StatusServiceUnavailable, "Login temporarily unavailable")
	}
	checkResponse(selectOrganization(f.member.OrganizationID), http.StatusServiceUnavailable, "Login temporarily unavailable")
	if _, err := f.store.Database().Exec(t.Context(), "ALTER TABLE unavailable_organizations RENAME TO organizations"); err != nil {
		t.Fatal(err)
	}

	selected := selectOrganization(f.member.OrganizationID)
	f.status(selected, http.StatusSeeOther)
	if selected.header.Get("Location") != path+requestQuery {
		t.Fatalf("organization selection redirected to %q", selected.header.Get("Location"))
	}
	f.status(f.call(f.browser, "GET", selected.header.Get("Location"), nil, nil), http.StatusOK)
}

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

	if _, err := f.store.Database().Exec(t.Context(), "UPDATE authentication_sessions SET verification=jsonb_set(verification,'{authenticatedAt}',to_jsonb(clock_timestamp()-interval '6 minutes'))"); err != nil {
		t.Fatal(err)
	}
	page = f.call(f.browser, "GET", "/login/"+f.member.OrganizationID, nil, nil)
	f.status(page, http.StatusOK)
	if strings.Contains(page.body, "Continue to account") || !strings.Contains(page.body, `id="phone"`) {
		t.Fatal("stale SSO bypassed fresh account authentication")
	}
	password, err := f.store.SetMemberPassword(t.Context(), identity.OperatorPrincipal(), f.member.OrganizationID, f.member.ID, "example")
	if err != nil {
		t.Fatal(err)
	}
	result = f.submit(page.body, "password", url.Values{"username": {"example"}, "password": {password}})
	f.status(result, http.StatusSeeOther)
	f.status(f.call(f.browser, "GET", result.header.Get("Location"), nil, nil), http.StatusOK)
}
