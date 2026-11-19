//go:build integration

package oidcprovider

import (
	"net/http"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/euyuil/memberid/internal/config"
)

func (f *fixture) checkOIDCRequests(want int) {
	f.t.Helper()
	var count int
	if err := f.store.Database().QueryRow(f.t.Context(), "SELECT count(*) FROM authentication_requests WHERE protocol='oidc' AND client_id<>''").Scan(&count); err != nil || count != want {
		f.t.Fatalf("OIDC requests = %d, want %d, err %v", count, want, err)
	}
}

func TestOIDCOrganizationChoiceBeforeAuthentication(t *testing.T) {
	f := newFixture(t)
	f.updateClient("example-web", func(c *config.Client) { c.OrganizationID = "" })
	start, _ := f.authorization("example-web", "openid", nil)
	f.status(start, http.StatusFound)
	f.checkOIDCRequests(0)
	entry := start.header.Get("Location")
	f.status(f.call(browserClient(), "GET", entry, nil, nil), http.StatusBadRequest)
	tampered, err := url.Parse(entry)
	if err != nil {
		t.Fatal(err)
	}
	query := tampered.Query()
	query.Set("request", query.Get("request")+"x")
	tampered.RawQuery = query.Encode()
	f.status(f.call(f.browser, "GET", tampered.String(), nil, nil), http.StatusBadRequest)
	page := f.call(f.browser, "GET", entry, nil, nil)
	f.status(page, http.StatusOK)
	first := f.selectOrganization(page, f.member.OrganizationID)
	second := f.selectOrganization(page, f.otherMember.OrganizationID)
	f.checkOIDCRequests(0)
	for _, selected := range []reply{first, second} {
		token := hidden(t, selected.body, "request")
		f.status(f.call(browserClient(), "GET", "/login?request="+url.QueryEscape(token), nil, nil), http.StatusBadRequest)
	}
	pending := f.submit(second.body, "send", url.Values{"phone": {"19900000001"}})
	f.status(pending, http.StatusOK)
	f.checkOIDCRequests(1)
	f.status(f.submit(first.body, "send", url.Values{"phone": {"19900000002"}}), http.StatusBadRequest)
	f.checkOIDCRequests(1)
}

func TestOIDCConfirmationRechecksTheDisplayedSSOSession(t *testing.T) {
	f := newFixture(t)
	f.tokens()
	page, _ := f.loginPage("example-web", "openid")
	f.checkOIDCRequests(1)
	if _, err := f.store.Database().Exec(t.Context(), "UPDATE authentication_sessions SET revoked_at=now()"); err != nil {
		t.Fatal(err)
	}
	confirmation := f.submit(page.body, "continue", url.Values{"member": {f.member.ID}, "consent": {"yes"}})
	f.status(confirmation, http.StatusBadRequest)
	f.checkOIDCRequests(1)
}

func TestOIDCConcurrentSSOConfirmationAndExpiry(t *testing.T) {
	f := newFixture(t)
	var elapsed atomic.Int64
	started := time.Now()
	f.service.now = func() time.Time { return started.Add(time.Duration(elapsed.Load())) }
	f.tokens()
	page, verifier := f.loginPage("example-web", "openid")
	f.checkOIDCRequests(1)
	form := url.Values{"member": {f.member.ID}, "consent": {"yes"}}
	confirm := func() reply { return f.submit(page.body, "continue", form) }
	race := func(call func() reply, winner func(reply) string) string {
		t.Helper()
		const tabs = 4
		start := make(chan struct{})
		results := make(chan reply, tabs)
		for range tabs {
			go func() {
				<-start
				results <- call()
			}()
		}
		close(start)
		var successes []string
		for range tabs {
			if result := winner(<-results); result != "" {
				successes = append(successes, result)
			}
		}
		if len(successes) != 1 {
			t.Fatalf("successful concurrent submissions = %d, want 1", len(successes))
		}
		return successes[0]
	}
	callbackURL := race(confirm, func(r reply) string {
		if r.status == http.StatusSeeOther {
			return r.header.Get("Location")
		}
		return ""
	})
	code := race(func() reply { return f.call(f.browser, "GET", callbackURL, nil, nil) }, func(r reply) string {
		u, err := url.Parse(r.header.Get("Location"))
		if err != nil {
			t.Fatal(err)
		}
		return u.Query().Get("code")
	})
	f.status(f.exchange("example-web", code, verifier), http.StatusOK)
	f.checkOIDCRequests(2)
	elapsed.Store(int64(2 * time.Minute))
	if err := f.service.Cleanup(t.Context()); err != nil {
		t.Fatal(err)
	}
	f.status(confirm(), http.StatusBadRequest)
	f.checkOIDCRequests(2)
	elapsed.Store(int64(12 * time.Minute))
	if err := f.service.Cleanup(t.Context()); err != nil {
		t.Fatal(err)
	}
	f.checkOIDCRequests(0)
	f.status(confirm(), http.StatusBadRequest)
}

func TestOIDCLargeAuthorizationStateRoundTrip(t *testing.T) {
	f := newFixture(t)
	state := strings.Repeat("x", 30<<10)
	start, verifier := f.authorization("example-web", "openid", url.Values{"state": {state}})
	f.status(start, http.StatusFound)
	page := f.call(f.browser, "GET", start.header.Get("Location"), nil, nil)
	f.status(page, http.StatusOK)
	f.checkOIDCRequests(0)
	verified := f.verifyPhone(page)
	confirmed := f.submit(verified.body, "continue", url.Values{"member": {f.member.ID}, "consent": {"yes"}})
	f.status(confirmed, http.StatusSeeOther)
	response := f.call(f.browser, "GET", confirmed.header.Get("Location"), nil, nil)
	f.status(response, http.StatusFound)
	u, err := url.Parse(response.header.Get("Location"))
	if err != nil || u.Query().Get("state") != state {
		t.Fatal("authorization response lost the original state", err)
	}
	f.status(f.exchange("example-web", u.Query().Get("code"), verifier), http.StatusOK)
}
