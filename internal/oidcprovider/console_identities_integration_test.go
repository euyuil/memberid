//go:build integration

package oidcprovider

import (
	"encoding/json"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/zhizhun-tech/memberid/internal/identity"
)

func consoleSwitchFixture(t *testing.T) (*fixture, *httptest.Server) {
	t.Helper()
	f := newFixture(t)
	for _, member := range []identity.Member{f.member, f.otherMember} {
		if err := f.store.SetAdministrator(t.Context(), identity.OperatorPrincipal(), member.OrganizationID, member.ID, true); err != nil {
			t.Fatal(err)
		}
	}
	server := consoleFixture(t, f)
	consoleLogin(t, f, server, f.member.ID)
	return f, server
}

func startConsoleSwitch(t *testing.T, f *fixture, server *httptest.Server, memberID string) string {
	t.Helper()
	session := consoleJSON(t, f, server, "GET", "/api/session", "", "", 200)
	body, _ := json.Marshal(map[string]string{"memberId": memberID, "returnTo": "/organizations/" + f.member.OrganizationID + "/members?q=original"})
	result := consoleJSON(t, f, server, "POST", "/api/identity-switch", session["csrf"].(string), string(body), 200)
	return result["authorizationUrl"].(string)
}

func authorizeConsoleSwitch(t *testing.T, f *fixture, address string) string {
	t.Helper()
	r := f.call(f.browser, "GET", address, nil, nil)
	f.status(r, 302)
	r = f.call(f.browser, "GET", r.header.Get("Location"), nil, nil)
	// prompt=none reuses the phone session and issues a code without an SMS form.
	f.status(r, 303)
	r = f.call(f.browser, "GET", r.header.Get("Location"), nil, nil)
	f.status(r, 302)
	return r.header.Get("Location")
}

func TestConsolePhoneIdentitySwitchPreservesIndependentAuthority(t *testing.T) {
	f, server := consoleSwitchFixture(t)
	factor, err := f.store.EnsureFactor(t.Context(), "phone", "phone:e164", "+8619900000001")
	if err != nil {
		t.Fatal(err)
	}
	platform, err := f.store.CreateMember(t.Context(), identity.OperatorPrincipal(), identity.SystemOrganizationID, "", "Separate platform Member")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.store.BindFactor(t.Context(), identity.OperatorPrincipal(), platform.OrganizationID, platform.ID, factor.ID); err != nil {
		t.Fatal(err)
	}
	if err := f.store.SetAdministrator(t.Context(), identity.OperatorPrincipal(), platform.OrganizationID, platform.ID, true); err != nil {
		t.Fatal(err)
	}
	page := consoleJSON(t, f, server, "GET", "/api/identities", "", "", 200)
	if len(page["items"].([]any)) != 3 {
		t.Fatal("phone administrator identities missing", page)
	}
	for _, target := range []identity.Member{f.otherMember, platform, f.member} {
		previous := consoleJSON(t, f, server, "GET", "/api/session", "", "", 200)
		stale := browserClient()
		origin, _ := url.Parse(server.URL)
		stale.Jar.SetCookies(origin, f.browser.Jar.Cookies(origin))
		callback := authorizeConsoleSwitch(t, f, startConsoleSwitch(t, f, server, target.ID))
		f.status(f.call(browserClient(), "GET", callback, nil, nil), 400)
		result := f.call(f.browser, "GET", callback, nil, nil)
		f.status(result, 303)
		if result.header.Get("Location") != "/" {
			t.Fatal("switch retained the previous identity's page", result.header)
		}
		f.status(f.call(f.browser, "GET", callback, nil, nil), 400)
		f.status(f.call(stale, "GET", server.URL+"/api/session", nil, nil), 401)
		next := consoleJSON(t, f, server, "GET", "/api/session", "", "", 200)
		actor := next["actor"].(map[string]any)
		if actor["memberId"] != target.ID || actor["organizationId"] != target.OrganizationID || actor["platform"] != (target.ID == platform.ID) || next["csrf"] == previous["csrf"] {
			t.Fatal("switch mixed Member authority or reused CSRF", next)
		}
		consoleJSON(t, f, server, "POST", "/api/identity-switch", previous["csrf"].(string), `{}`, 403)
		consoleJSON(t, f, server, "GET", "/api/organizations/"+target.OrganizationID, "", "", 200)
		if target.ID != platform.ID {
			foreign := f.member.OrganizationID
			if foreign == target.OrganizationID {
				foreign = f.otherMember.OrganizationID
			}
			consoleJSON(t, f, server, "GET", "/api/organizations/"+foreign, "", "", 403)
			consoleJSON(t, f, server, "PATCH", "/api/organizations/"+foreign, next["csrf"].(string), `{"name":"Must not change"}`, 403)
		} else {
			consoleJSON(t, f, server, "GET", "/api/organizations/"+f.otherMember.OrganizationID, "", "", 200)
		}
	}
	var challenges, sessions, authTimes, deadlines int
	err = f.store.Database().QueryRow(t.Context(), `SELECT
 (SELECT count(*) FROM phone_challenges),(SELECT count(*) FROM authentication_sessions),
 (SELECT count(DISTINCT data->>'authTime') FROM oidc_grants),
 (SELECT count(DISTINCT absolute_expires_at) FROM oidc_grants)`).Scan(&challenges, &sessions, &authTimes, &deadlines)
	if err != nil || challenges != 1 || sessions != 1 || authTimes != 1 || deadlines != 1 {
		t.Fatal("switch reverified or extended authentication", challenges, sessions, authTimes, deadlines, err)
	}
}

func TestConsoleIdentityCandidatesRequireTheVerifiedPhoneAndAdministrator(t *testing.T) {
	f, server := consoleSwitchFixture(t)
	for _, state := range []string{"ordinary", "blocked", "disabled organization", "revoked binding", "different phone"} {
		organization, err := f.store.CreateOrganization(t.Context(), identity.OperatorPrincipal(), "", "Synthetic "+state)
		if err != nil {
			t.Fatal(err)
		}
		member, err := f.store.CreateMember(t.Context(), identity.OperatorPrincipal(), organization.ID, "", "Synthetic Member")
		if err != nil {
			t.Fatal(err)
		}
		number := "+8619900000001"
		if state == "different phone" {
			number = "+8619900000002"
		}
		factor, err := f.store.EnsureFactor(t.Context(), "phone", "phone:e164", number)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := f.store.BindFactor(t.Context(), identity.OperatorPrincipal(), organization.ID, member.ID, factor.ID); err != nil {
			t.Fatal(err)
		}
		if state != "ordinary" {
			if err := f.store.SetAdministrator(t.Context(), identity.OperatorPrincipal(), organization.ID, member.ID, true); err != nil {
				t.Fatal(err)
			}
		}
		query := "SELECT 1"
		switch state {
		case "blocked":
			query = "UPDATE members SET manual_block=true WHERE id=$1"
		case "disabled organization":
			query = "UPDATE organizations SET status='disabled' WHERE id=(SELECT organization_id FROM members WHERE id=$1)"
		case "revoked binding":
			query = "UPDATE member_auth_factor_bindings SET status='revoked',revoked_at=clock_timestamp() WHERE member_id=$1"
		}
		if query != "SELECT 1" {
			if _, err := f.store.Database().Exec(t.Context(), query, member.ID); err != nil {
				t.Fatal(err)
			}
		}
		session := consoleJSON(t, f, server, "GET", "/api/session", "", "", 200)
		body, _ := json.Marshal(map[string]string{"memberId": member.ID, "returnTo": "/"})
		consoleJSON(t, f, server, "POST", "/api/identity-switch", session["csrf"].(string), string(body), 403)
	}
	page := consoleJSON(t, f, server, "GET", "/api/identities", "", "", 200)
	if len(page["items"].([]any)) != 2 {
		t.Fatal("ineligible identity disclosed", page)
	}
	consoleJSON(t, f, server, "GET", "/api/identities?after=invalid", "", "", 400)
	var current struct{ Items []identity.ConsoleIdentity }
	raw, _ := json.Marshal(page)
	if err := json.Unmarshal(raw, &current); err != nil {
		t.Fatal(err)
	}
	next := consoleJSON(t, f, server, "GET", "/api/identities?after="+current.Items[0].MemberID, "", "", 200)
	if len(next["items"].([]any)) != 1 {
		t.Fatal("identity cursor ignored", next)
	}
	session := consoleJSON(t, f, server, "GET", "/api/session", "", "", 200)
	consoleJSON(t, f, server, "POST", "/api/identity-switch", "", `{"memberId":"`+f.otherMember.ID+`","returnTo":"/"}`, 403)
	consoleJSON(t, f, server, "POST", "/api/identity-switch", session["csrf"].(string), `{"memberId":"`+f.otherMember.ID+`","returnTo":"//example.invalid"}`, 400)
	consoleJSON(t, f, server, "POST", "/api/identity-switch", session["csrf"].(string), `{"memberId":"`+f.otherMember.ID+`","returnTo":"/","factorId":"arbitrary"}`, 400)
}

func TestConsoleIdentitySwitchRechecksCallbackAndPreservesSource(t *testing.T) {
	for _, change := range []string{"target administrator revoked", "target binding revoked", "wrong subject", "different authentication session", "logout", "insert failure"} {
		t.Run(change, func(t *testing.T) {
			f, server := consoleSwitchFixture(t)
			before := consoleJSON(t, f, server, "GET", "/api/session", "", "", 200)
			address := startConsoleSwitch(t, f, server, f.otherMember.ID)
			if change == "wrong subject" {
				u, _ := url.Parse(address)
				query := u.Query()
				query.Set("login_hint", f.member.ID)
				u.RawQuery = query.Encode()
				address = u.String()
			}
			callback := authorizeConsoleSwitch(t, f, address)
			var query string
			switch change {
			case "target administrator revoked":
				query = "DELETE FROM administrators WHERE member_id=$1"
			case "target binding revoked":
				query = "UPDATE member_auth_factor_bindings SET status='revoked',revoked_at=clock_timestamp() WHERE member_id=$1"
			case "different authentication session":
				// A new grant must retain the exact source SSO session, even when
				// another session verified the same phone and target Member.
				query = `INSERT INTO authentication_sessions SELECT 'other-session',secret_hash||'other',verification,expires_at,absolute_expires_at,revoked_at FROM authentication_sessions LIMIT 1;
 UPDATE authentication_requests SET data=jsonb_set(data,'{sessionId}','"other-session"') WHERE data->>'memberId'=$1`
			case "logout":
				consoleJSON(t, f, server, "POST", "/api/logout", before["csrf"].(string), `{}`, 200)
			case "insert failure":
				query = "ALTER TABLE console_sessions ADD CONSTRAINT reject_switch CHECK (member_id<>'" + f.otherMember.ID + "')"
			}
			if query != "" {
				var err error
				if change == "insert failure" {
					_, err = f.store.Database().Exec(t.Context(), query)
				} else if change == "different authentication session" {
					_, err = f.store.Database().Exec(t.Context(), strings.Split(query, ";")[0])
					if err == nil {
						_, err = f.store.Database().Exec(t.Context(), strings.Split(query, ";")[1], f.otherMember.ID)
					}
				} else {
					_, err = f.store.Database().Exec(t.Context(), query, f.otherMember.ID)
				}
				if err != nil {
					t.Fatal(err)
				}
			}
			r := f.call(f.browser, "GET", callback, nil, nil)
			f.status(r, 303)
			location, _ := url.Parse(r.header.Get("Location"))
			if location.Query().Get("error") == "" || location.Query().Get("q") != "original" {
				t.Fatal("failed switch lost its original page", r.header)
			}
			if change != "logout" {
				after := consoleJSON(t, f, server, "GET", "/api/session", "", "", 200)
				if after["csrf"] != before["csrf"] || after["actor"].(map[string]any)["memberId"] != f.member.ID {
					t.Fatal("failed switch replaced the source identity", after)
				}
			} else {
				consoleJSON(t, f, server, "GET", "/api/session", "", "", 401)
			}
		})
	}
}

func TestConsoleIdentitySwitchConsumesTheSourceSessionOnce(t *testing.T) {
	f, server := consoleSwitchFixture(t)
	first := f.browser
	second := browserClient()
	origin, _ := url.Parse(server.URL)
	second.Jar.SetCookies(origin, first.Jar.Cookies(origin))
	firstCallback := authorizeConsoleSwitch(t, f, startConsoleSwitch(t, f, server, f.otherMember.ID))
	f.browser = second
	secondCallback := authorizeConsoleSwitch(t, f, startConsoleSwitch(t, f, server, f.otherMember.ID))
	results := make(chan reply, 2)
	go func() { results <- f.call(first, "GET", firstCallback, nil, nil) }()
	go func() { results <- f.call(second, "GET", secondCallback, nil, nil) }()
	completed, rejected := 0, 0
	for range 2 {
		r := <-results
		f.status(r, 303)
		u, _ := url.Parse(r.header.Get("Location"))
		if u.Query().Get("error") == "identity_switch_failed" {
			rejected++
		} else if u.String() == "/" {
			completed++
		}
	}
	var sessions int
	if err := f.store.Database().QueryRow(t.Context(), "SELECT count(*) FROM console_sessions").Scan(&sessions); err != nil || sessions != 1 || completed != 1 || rejected != 1 {
		t.Fatal("competing switches reused the source session", sessions, completed, rejected, err)
	}
}
