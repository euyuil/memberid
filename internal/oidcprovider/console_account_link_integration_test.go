//go:build integration

package oidcprovider

import (
	"net/url"
	"strings"
	"testing"
)

func TestConsoleAccountLinkRequiresFreshSameMember(t *testing.T) {
	for _, wrongMember := range []bool{false, true} {
		t.Run(map[bool]string{false: "same Member", true: "different Member"}[wrongMember], func(t *testing.T) {
			f, server := consoleSwitchFixture(t)
			enableDingTalk(t, f, true)
			// Age the completed fixture SMS send past its resend cooldown.
			if _, err := f.store.Database().Exec(t.Context(), `UPDATE phone_challenges SET created_at=created_at-interval '2 minutes' WHERE consumed_at IS NOT NULL`); err != nil {
				t.Fatal(err)
			}
			csrf := consoleJSON(t, f, server, "GET", "/api/session", "", "", 200)["csrf"].(string)
			consoleJSON(t, f, server, "POST", "/api/account-link", "", "", 403)
			consoleJSON(t, f, server, "POST", "/api/account-link", csrf, `{"memberId":"ignored-target","returnTo":"https://foreign.example.invalid"}`, 400)
			result := consoleJSON(t, f, server, "POST", "/api/account-link", csrf, `{}`, 200)
			address := result["authorizationUrl"].(string)
			u, _ := url.Parse(address)
			if u.Query().Get("prompt") != "login" || u.Query().Get("login_hint") != f.member.ID {
				t.Fatal("not fresh or wrong target", u.Query())
			}
			if wrongMember {
				q := u.Query()
				q.Del("login_hint")
				u.RawQuery = q.Encode()
				address = u.String()
			}
			r := f.call(f.browser, "GET", address, nil, nil)
			f.status(r, 302)
			r = f.call(f.browser, "GET", r.header.Get("Location"), nil, nil)
			f.status(r, 200)
			if !strings.Contains(r.body, `id="phone"`) {
				t.Fatal("existing SSO bypassed fresh authentication")
			}
			r = f.verifyPhone(r)
			member := f.member.ID
			if wrongMember {
				member = f.otherMember.ID
			}
			r = f.submit(r.body, "continue", url.Values{"member": {member}, "consent": {"yes"}})
			f.status(r, 303)
			r = f.call(f.browser, "GET", r.header.Get("Location"), nil, nil)
			f.status(r, 302)
			callback := r.header.Get("Location")
			r = f.call(f.browser, "GET", callback, nil, nil)
			f.status(r, 303)
			destination := r.header.Get("Location")
			if wrongMember {
				if !strings.Contains(destination, "error=login_failed") || strings.HasPrefix(destination, f.server.URL) {
					t.Fatal("different identity reached linking", destination)
				}
				return
			}
			if destination != f.server.URL+"/account?memberId="+f.member.ID {
				t.Fatal(destination)
			}
			page := f.call(f.browser, "GET", destination, nil, nil)
			f.status(page, 200)
			if !strings.Contains(page.body, "/account/link/dingtalk?") || strings.Contains(page.body, "Link phone") || strings.Contains(page.body, "Link Feishu") {
				t.Fatal("incorrect available methods")
			}
			f.status(f.call(browserClient(), "GET", destination, nil, nil), 401)
			f.status(f.call(f.browser, "GET", "/account?memberId="+f.member.ID+"&returnUri=https://foreign.example.invalid", nil, nil), 400)
			if _, err := f.store.Database().Exec(t.Context(), `UPDATE authentication_sessions SET verification=jsonb_set(verification,'{authenticatedAt}',to_jsonb(clock_timestamp()-interval '10 minutes')) WHERE revoked_at IS NULL`); err != nil {
				t.Fatal(err)
			}
			f.status(f.call(f.browser, "GET", destination, nil, nil), 401)
		})
	}
}
