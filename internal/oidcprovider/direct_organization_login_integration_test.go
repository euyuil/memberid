//go:build integration

package oidcprovider

import (
	"net/http"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/zhizhun-tech/memberid/internal/config"
	"github.com/zhizhun-tech/memberid/internal/identity"
)

func (f *fixture) openDirectLogin(path string) reply {
	f.t.Helper()
	page := f.call(f.browser, "GET", path, nil, nil)
	f.status(page, http.StatusOK)
	if !strings.Contains(page.body, `method="post" action="`+path+`"`) {
		f.t.Fatal("direct form did not target its entry URL")
	}
	return page
}

func (f *fixture) submitDirect(page reply, path, action string, fields url.Values) reply {
	f.t.Helper()
	form := url.Values{"request": {hidden(f.t, page.body, "request")}, "csrf": {hidden(f.t, page.body, "csrf")}, "action": {action}}
	for key, values := range fields {
		form[key] = values
	}
	return f.call(f.browser, "POST", path, form, map[string]string{"Origin": f.server.URL})
}

func (f *fixture) checkDirectCount(want int) {
	f.t.Helper()
	var count int
	if err := f.store.Database().QueryRow(f.t.Context(), "SELECT count(*) FROM authentication_requests WHERE client_id=''").Scan(&count); err != nil || count != want {
		f.t.Fatalf("direct transaction count = %d, want %d, err = %v", count, want, err)
	}
}

func TestOrganizationLoginLookupErrors(t *testing.T) {
	f := newFixture(t)
	page := f.openDirectLogin("/login")
	// An application request also exercises the stored transaction path.
	f.updateClient("example-web", func(client *config.Client) { client.OrganizationID = "" })
	started, _ := f.authorization("example-web", "openid", nil)
	f.status(started, http.StatusFound)
	location, err := url.Parse(started.header.Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	requestQuery := "?" + location.RawQuery
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
	if err := f.store.AssignOrganizationSlug(t.Context(), identity.OperatorPrincipal(), f.otherMember.OrganizationID, "disabled-team"); err != nil {
		t.Fatal(err)
	}
	if _, err := f.store.UpdateOrganization(t.Context(), identity.OperatorPrincipal(), f.otherMember.OrganizationID, identity.OrganizationChange{Status: &disabled}); err != nil {
		t.Fatal(err)
	}
	for _, organizationID := range []string{unknownID, f.otherMember.OrganizationID} {
		path := "/login/" + organizationID
		for _, target := range []string{path, path + requestQuery} {
			checkResponse(f.call(f.browser, "GET", target, nil, nil), http.StatusNotFound, "Organization login is unavailable")
		}
	}
	checkResponse(f.call(f.browser, "GET", "/login/disabled-team", nil, nil), http.StatusNotFound, "Organization login is unavailable")
	for _, organizationID := range []string{"invalid id", "unknown-name", "disabled-team", "Disabled-Team", unknownID, f.otherMember.OrganizationID} {
		response := selectOrganization(organizationID)
		f.status(response, http.StatusOK)
		if !strings.Contains(response.body, "Enter a valid organization login name or ID.") {
			t.Fatalf("missing organization ID validation message for %q", organizationID)
		}
	}

	// Break organization reads while leaving the stored login transaction readable.
	if _, err := f.store.Database().Exec(t.Context(), "ALTER TABLE organizations RENAME TO unavailable_organizations"); err != nil {
		t.Fatal(err)
	}
	path := "/login/" + f.member.OrganizationID
	checkResponse(f.call(f.browser, "GET", "/login/disabled-team", nil, nil), http.StatusServiceUnavailable, "Login temporarily unavailable")
	for _, target := range []string{path, path + requestQuery} {
		checkResponse(f.call(f.browser, "GET", target, nil, nil), http.StatusServiceUnavailable, "Login temporarily unavailable")
	}
	checkResponse(selectOrganization(f.member.OrganizationID), http.StatusServiceUnavailable, "Login temporarily unavailable")
	if _, err := f.store.Database().Exec(t.Context(), "ALTER TABLE unavailable_organizations RENAME TO organizations"); err != nil {
		t.Fatal(err)
	}

	selected := selectOrganization(f.member.OrganizationID)
	f.status(selected, http.StatusSeeOther)
	if selected.header.Get("Location") != path {
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
	const loginName = "dingtalk"
	if err := f.store.AssignOrganizationSlug(t.Context(), identity.OperatorPrincipal(), f.member.OrganizationID, loginName); err != nil {
		t.Fatal(err)
	}
	for previous, value := range []string{f.member.OrganizationID, strings.ToUpper(loginName)} {
		f.browser = browserClient()
		page := f.openDirectLogin("/login")
		if !strings.Contains(page.body, `value="choose-organization"`) || !strings.Contains(page.body, `id="username"`) {
			t.Fatal("direct login did not start with organization selection")
		}
		path := "/login/" + f.member.OrganizationID
		selected := f.submitDirect(page, "/login", "choose-organization", url.Values{"organization": {value}})
		f.status(selected, http.StatusSeeOther)
		if selected.header.Get("Location") != path {
			t.Fatal("organization selection did not redirect to its stable entry URL")
		}
		page = f.openDirectLogin(path)
		f.checkDirectCount(previous)
		result := f.submitDirect(page, path, "password", url.Values{"username": {"example"}, "password": {password}})
		f.status(result, http.StatusSeeOther)
		f.checkDirectCount(previous + 1)
		if result.header.Get("Location") != "/account?memberId="+f.member.ID {
			t.Fatalf("direct password login redirected to %q", result.header.Get("Location"))
		}
		account := f.call(f.browser, "GET", result.header.Get("Location"), nil, nil)
		f.status(account, http.StatusOK)
		if !strings.Contains(account.body, "Example Member") {
			t.Fatal("direct login did not open the Member account")
		}
	}
	var grants int
	if err := f.store.Database().QueryRow(t.Context(), "SELECT count(*) FROM oidc_grants").Scan(&grants); err != nil || grants != 0 {
		t.Fatal("direct login created an OIDC grant", grants, err)
	}
}

func TestBookmarkableOrganizationLoginReusesSessionWithoutClientConsent(t *testing.T) {
	f := newFixture(t)
	path := "/login/" + f.member.OrganizationID
	page := f.openDirectLogin(path)
	page = f.submitDirect(page, path, "send", url.Values{"phone": {"19900000001"}})
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
	for range 2 {
		result = f.submitDirect(page, path, "continue", url.Values{"member": {f.member.ID}})
		f.status(result, http.StatusSeeOther)
		f.status(f.call(f.browser, "GET", result.header.Get("Location"), nil, nil), http.StatusOK)
	}
	f.status(f.submitDirect(page, path, "continue", url.Values{"member": {f.otherMember.ID}}), http.StatusForbidden)
	f.checkDirectCount(1)

	if _, err := f.store.Database().Exec(t.Context(), "UPDATE authentication_sessions SET verification=jsonb_set(verification,'{authenticatedAt}',to_jsonb(clock_timestamp()-interval '6 minutes'))"); err != nil {
		t.Fatal(err)
	}
	f.status(f.call(f.browser, "GET", result.header.Get("Location"), nil, nil), http.StatusUnauthorized)
	stale := f.submitDirect(page, path, "continue", url.Values{"member": {f.member.ID}})
	f.status(stale, http.StatusOK)
	if strings.Contains(stale.body, "Continue to account") {
		t.Fatal("stale continuation did not require authentication")
	}
	f.checkDirectCount(1)
	page = f.openDirectLogin("/login/" + f.member.OrganizationID)
	if strings.Contains(page.body, "Continue to account") || !strings.Contains(page.body, `id="phone"`) {
		t.Fatal("stale SSO bypassed fresh account authentication")
	}
	password, err := f.store.SetMemberPassword(t.Context(), identity.OperatorPrincipal(), f.member.OrganizationID, f.member.ID, "example")
	if err != nil {
		t.Fatal(err)
	}
	result = f.submitDirect(page, path, "password", url.Values{"username": {"example"}, "password": {password}})
	f.status(result, http.StatusSeeOther)
	f.status(f.call(f.browser, "GET", result.header.Get("Location"), nil, nil), http.StatusOK)
	page = f.openDirectLogin(path)
	blocked := true
	if _, err := f.store.UpdateMember(t.Context(), identity.OperatorPrincipal(), f.member.OrganizationID, f.member.ID, identity.MemberChange{ManualBlocked: &blocked}); err != nil {
		t.Fatal(err)
	}
	f.status(f.call(f.browser, "GET", result.header.Get("Location"), nil, nil), http.StatusForbidden)
	if denied := f.submitDirect(page, path, "continue", url.Values{"member": {f.member.ID}}); denied.header.Get("Location") != "" {
		t.Fatal("blocked Member could continue")
	}
	f.checkDirectCount(2)
}

func TestDirectLoginQuotaRefreshExpiryAndCleanup(t *testing.T) {
	f := newFixture(t)
	now := time.Now()
	var elapsed atomic.Int64
	f.service.now = func() time.Time { return now.Add(time.Duration(elapsed.Load())) }
	path := "/login/" + f.member.OrganizationID
	for range browserStartsPerMinute + 2 {
		f.openDirectLogin("/login")
		f.openDirectLogin(path)
	}
	f.checkDirectCount(0)
	page := f.openDirectLogin(path)
	form := url.Values{"phone": {"19900000001"}}
	pending := f.submitDirect(page, path, "send", form)
	f.status(pending, http.StatusOK)
	transaction := path + "?request=" + url.QueryEscape(hidden(t, pending.body, "request"))
	repeated := f.submitDirect(page, path, "send", form)
	f.status(repeated, http.StatusSeeOther)
	if repeated.header.Get("Location") != transaction {
		t.Fatal("resubmission did not resume the existing transaction")
	}
	f.checkDirectCount(1)
	for i := 2; i < browserStartsPerMinute; i++ {
		page = f.openDirectLogin(path)
		f.status(f.submitDirect(page, path, "password", url.Values{"username": {"absent"}, "password": {"example"}}), http.StatusOK)
	}
	page = f.openDirectLogin(path)
	limited := f.submitDirect(page, path, "password", nil)
	f.status(limited, http.StatusTooManyRequests)
	if limited.header.Get("Retry-After") != "60" {
		t.Fatal("missing direct login retry interval")
	}
	f.status(f.call(f.browser, "GET", transaction, nil, nil), http.StatusOK)
	f.checkDirectCount(browserStartsPerMinute - 1)
	elapsed.Add(int64(time.Minute))
	f.status(f.submitDirect(page, path, "password", nil), http.StatusOK)
	f.checkDirectCount(browserStartsPerMinute)
	elapsed.Add(int64(11 * time.Minute))
	f.status(f.call(f.browser, "GET", transaction, nil, nil), http.StatusBadRequest)
	if err := f.service.Cleanup(t.Context()); err != nil {
		t.Fatal(err)
	}
	f.status(f.submitDirect(page, path, "send", form), http.StatusBadRequest)
	f.checkDirectCount(0)
}

func TestDirectAuthenticationLocksOrganization(t *testing.T) {
	f := newFixture(t)
	enableDingTalk(t, f, true)
	path, otherPath := "/login/"+f.member.OrganizationID, "/login/"+f.otherMember.OrganizationID
	page := f.openDirectLogin(path)
	form := url.Values{"request": {hidden(t, page.body, "request")}, "csrf": {hidden(t, page.body, "csrf")}, "action": {"dingtalk"}, "organization": {f.member.OrganizationID}}
	f.status(f.call(browserClient(), "POST", path, form, map[string]string{"Origin": f.server.URL}), http.StatusForbidden)
	f.status(f.call(f.browser, "POST", path, form, nil), http.StatusForbidden)
	f.status(f.call(f.browser, "POST", otherPath, form, map[string]string{"Origin": f.server.URL}), http.StatusForbidden)
	f.checkDirectCount(0)
	started := f.call(f.browser, "POST", path, form, map[string]string{"Origin": f.server.URL})
	f.status(started, http.StatusSeeOther)
	if !strings.HasPrefix(started.header.Get("Location"), "https://login.dingtalk.com/") {
		t.Fatal("expected the configured upstream authorization endpoint")
	}
	var id string
	if err := f.store.Database().QueryRow(t.Context(), "SELECT id FROM authentication_requests WHERE client_id='' AND data->>'providerOrganizationId'=$1", f.member.OrganizationID).Scan(&id); err != nil {
		t.Fatal(err)
	}
	f.status(f.call(f.browser, "GET", otherPath+"?request="+url.QueryEscape(id), nil, nil), http.StatusBadRequest)
	pending := f.call(f.browser, "GET", path+"?request="+url.QueryEscape(id), nil, nil)
	f.status(pending, http.StatusOK)
	canceled := f.submitDirect(pending, path, "cancel", nil)
	f.status(canceled, http.StatusOK)
	f.status(f.submitDirect(canceled, otherPath, "send", url.Values{"phone": {"19900000001"}}), http.StatusBadRequest)
	f.checkDirectCount(1)
}
