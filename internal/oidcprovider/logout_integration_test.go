//go:build integration

package oidcprovider

import (
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"
)

func (f *fixture) logoutConfirmation(page reply, action string) reply {
	f.t.Helper()
	return f.call(f.browser, "POST", "/logout/confirm", url.Values{"request": {hidden(f.t, page.body, "request")}, "action": {action}}, map[string]string{"Origin": f.server.URL})
}

func TestLogoutWithoutHint(t *testing.T) {
	for _, method := range []string{"GET", "POST"} {
		t.Run(method, func(t *testing.T) {
			f := newFixture(t)
			tokens := f.tokens()
			query := url.Values{"client_id": {"example-web"}, "post_logout_redirect_uri": {"http://127.0.0.1:8484/signed-out"}, "state": {"logout-state"}}
			var page reply
			if method == "POST" {
				page = f.call(f.browser, method, "/oauth/logout", query, nil)
				f.status(page, 303)
				page = f.call(f.browser, "GET", page.header.Get("Location"), nil, nil)
			} else {
				page = f.call(f.browser, method, "/oauth/logout?"+query.Encode(), nil, nil)
			}
			f.status(page, 200)
			f.status(f.userinfo(tokens["access_token"].(string)), 200)
			form := url.Values{"request": {hidden(t, page.body, "request")}, "action": {"confirm"}}
			f.status(f.call(f.browser, "POST", "/logout/confirm", form, nil), 403)
			f.status(f.call(browserClient(), "POST", "/logout/confirm", form, map[string]string{"Origin": f.server.URL}), 403)
			f.status(f.logoutConfirmation(page, "cancel"), 200)
			f.status(f.userinfo(tokens["access_token"].(string)), 200)
			result := f.logoutConfirmation(page, "confirm")
			f.status(result, 302)
			if result.header.Get("Location") != "http://127.0.0.1:8484/signed-out?state=logout-state" {
				t.Fatal("logout lost its registered redirect or state")
			}
			f.status(f.userinfo(tokens["access_token"].(string)), 401)
			r, _ := f.authorization("example-web", "openid", url.Values{"prompt": {"none"}})
			r = f.call(f.browser, "GET", r.header.Get("Location"), nil, nil)
			location, _ := url.Parse(r.header.Get("Location"))
			if r.status != 302 || location.Query().Get("error") != "login_required" {
				t.Fatal("logout retained browser SSO")
			}
		})
	}
}

func TestLogoutConfirmationSessionBoundary(t *testing.T) {
	f := newFixture(t)
	original := f.tokens()
	oldBrowser := f.browser
	oldPage := f.call(f.browser, "GET", "/oauth/logout", nil, nil)
	f.status(oldPage, 200)
	f.browser = browserClient()
	member, err := f.store.CreateMember(t.Context(), f.member.OrganizationID, "", "Another person")
	if err != nil {
		t.Fatal(err)
	}
	factor, err := f.store.EnsureFactor(t.Context(), "phone", "phone:e164", "+8619900000002")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.store.BindFactor(t.Context(), member.OrganizationID, member.ID, factor.ID); err != nil {
		t.Fatal(err)
	}
	login, verifier := f.loginPage("example-web", "openid")
	login = f.submit(login.body, "send", url.Values{"phone": {"19900000002"}})
	f.status(login, 200)
	login = f.submit(login.body, "verify", url.Values{"code": {f.sender.latest()}})
	f.status(login, 200)
	code := f.complete(login, member.ID)
	response := f.exchange("example-web", code, verifier)
	f.status(response, 200)
	current := jsonObject(t, response)
	form := url.Values{"request": {hidden(t, oldPage.body, "request")}, "action": {"confirm"}}
	// Even with the original browser binding, confirmation cannot end a new login.
	issuer, _ := url.Parse(f.server.URL)
	for _, cookie := range oldBrowser.Jar.Cookies(issuer) {
		if cookie.Name == f.service.cookieName("browser") {
			f.browser.Jar.SetCookies(issuer, []*http.Cookie{cookie})
		}
	}
	f.status(f.call(f.browser, "POST", "/logout/confirm", form, map[string]string{"Origin": f.server.URL}), 403)
	query := url.Values{"id_token_hint": {original["id_token"].(string)}}
	page := f.call(f.browser, "GET", "/oauth/logout?"+query.Encode(), nil, nil)
	f.status(page, 200)
	f.status(f.userinfo(original["access_token"].(string)), 200)
	f.status(f.userinfo(current["access_token"].(string)), 200)
	f.status(f.logoutConfirmation(page, "confirm"), 302)
	f.status(f.userinfo(original["access_token"].(string)), 200)
	f.status(f.userinfo(current["access_token"].(string)), 401)
}

func TestLogoutConfirmationValidation(t *testing.T) {
	f := newFixture(t)
	tokens := f.tokens()
	for _, query := range []url.Values{
		{"client_id": {"unknown"}},
		{"client_id": {"example-web"}, "post_logout_redirect_uri": {"https://unregistered.example.test"}},
		{"post_logout_redirect_uri": {"http://127.0.0.1:8484/signed-out"}},
		{"id_token_hint": {"invalid"}},
	} {
		r := f.call(f.browser, "GET", "/oauth/logout?"+query.Encode(), nil, nil)
		if r.status < 400 || r.header.Get("Location") != "" {
			t.Fatal("invalid logout request was accepted")
		}
	}
	page := f.call(f.browser, "GET", "/oauth/logout", nil, nil)
	f.status(page, 200)
	sealed := hidden(t, page.body, "request")
	bad := strings.Repeat("A", len(sealed))
	f.status(f.call(f.browser, "POST", "/logout/confirm", url.Values{"request": {bad}, "action": {"confirm"}}, map[string]string{"Origin": f.server.URL}), 403)
	f.service.now = func() time.Time { return time.Now().Add(11 * time.Minute) }
	f.status(f.logoutConfirmation(page, "confirm"), 403)
	f.service.now = time.Now
	f.status(f.userinfo(tokens["access_token"].(string)), 200)
}

func TestLogoutWithoutActiveSession(t *testing.T) {
	f := newFixture(t)
	page := f.call(f.browser, "GET", "/oauth/logout", nil, nil)
	f.status(page, 200)
	r := f.logoutConfirmation(page, "confirm")
	f.status(r, 302)
	if r.header.Get("Location") != f.server.URL+"/signed-out" {
		t.Fatal("logout without a session did not finish locally")
	}
}
