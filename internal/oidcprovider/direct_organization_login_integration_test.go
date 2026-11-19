//go:build integration

package oidcprovider

import (
	"net/http"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/euyuil/memberid/internal/identity"
)

func (f *fixture) openDirectLogin(path string) reply {
	f.t.Helper()
	start := f.call(f.browser, "GET", path, nil, nil)
	f.status(start, http.StatusSeeOther)
	location := start.header.Get("Location")
	page := f.call(f.browser, "GET", location, nil, nil)
	f.status(page, http.StatusOK)
	if location != path+"?request="+url.QueryEscape(hidden(f.t, page.body, "request")) {
		f.t.Fatal("direct login did not redirect to its canonical transaction URL")
	}
	return page
}

func TestDirectOrganizationPasswordLoginOpensMemberAccount(t *testing.T) {
	f := newFixture(t)
	password, err := f.store.SetMemberPassword(t.Context(), identity.OperatorPrincipal(), f.member.OrganizationID, f.member.ID, "example")
	if err != nil {
		t.Fatal(err)
	}
	page := f.openDirectLogin("/login")
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
	page := f.openDirectLogin("/login/" + f.member.OrganizationID)
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

	page = f.openDirectLogin("/login/" + f.member.OrganizationID)
	if !strings.Contains(page.body, "Continue to account") || strings.Contains(page.body, `id="phone"`) {
		t.Fatal("bookmarkable organization login did not reuse the current session")
	}
	result = f.submit(page.body, "continue", url.Values{"member": {f.member.ID}})
	f.status(result, http.StatusSeeOther)
	f.status(f.call(f.browser, "GET", result.header.Get("Location"), nil, nil), http.StatusOK)

	if _, err := f.store.Database().Exec(t.Context(), "UPDATE authentication_sessions SET verification=jsonb_set(verification,'{authenticatedAt}',to_jsonb(clock_timestamp()-interval '6 minutes'))"); err != nil {
		t.Fatal(err)
	}
	page = f.openDirectLogin("/login/" + f.member.OrganizationID)
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

func TestDirectLoginQuotaRefreshExpiryAndCleanup(t *testing.T) {
	f := newFixture(t)
	now := time.Now()
	var elapsed atomic.Int64
	f.service.now = func() time.Time { return now.Add(time.Duration(elapsed.Load())) }
	path := "/login/" + f.member.OrganizationID
	page := f.openDirectLogin(path)
	transaction := path + "?request=" + url.QueryEscape(hidden(t, page.body, "request"))
	for i := 1; i < browserStartsPerMinute; i++ {
		f.status(f.call(f.browser, "GET", "/login", nil, nil), http.StatusSeeOther)
	}
	limited := f.call(f.browser, "GET", path, nil, nil)
	f.status(limited, http.StatusTooManyRequests)
	if limited.header.Get("Retry-After") != "60" {
		t.Fatal("missing direct login retry interval")
	}
	f.status(f.call(f.browser, "GET", transaction, nil, nil), http.StatusOK)
	checkCount := func(want int) {
		t.Helper()
		var count int
		if err := f.store.Database().QueryRow(t.Context(), "SELECT count(*) FROM authentication_requests WHERE client_id=''").Scan(&count); err != nil || count != want {
			t.Fatalf("direct transaction count = %d, want %d, err = %v", count, want, err)
		}
	}
	checkCount(browserStartsPerMinute)
	f.status(f.call(browserClient(), "GET", path, nil, nil), http.StatusSeeOther)
	elapsed.Add(int64(time.Minute))
	f.status(f.call(f.browser, "GET", path, nil, nil), http.StatusSeeOther)
	checkCount(browserStartsPerMinute + 2)
	elapsed.Add(int64(11 * time.Minute))
	f.status(f.call(f.browser, "GET", transaction, nil, nil), http.StatusBadRequest)
	if err := f.service.Cleanup(t.Context()); err != nil {
		t.Fatal(err)
	}
	checkCount(0)
}
