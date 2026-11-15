//go:build integration

package oidcprovider

import (
	"encoding/base64"
	"net/url"
	"testing"
	"time"

	"github.com/euyuil/memberid/internal/authevent"
)

func TestClientRevocationEvents(t *testing.T) {
	for _, tokenType := range []string{"access_token", "refresh_token"} {
		for _, mode := range []string{"success", "business failed", "audit failed"} {
			t.Run(tokenType+"/"+mode, func(t *testing.T) {
				f := newConfiguredFixture(t, true)
				tokens := f.refreshTokens()
				token := tokens[tokenType].(string)
				recorder := enableAuthenticationEvents(t, f)
				revoke := func(client, token string) reply {
					return f.call(browserClient(), "POST", "/oauth/revoke", url.Values{"token": {token}}, map[string]string{"Authorization": "Basic " + base64.StdEncoding.EncodeToString([]byte(client+":"+f.secret))})
				}
				f.status(revoke("second-web", token), 200)
				f.status(revoke("example-web", "unknown-token"), 200)
				if mode == "business failed" {
					eventSQL(t, f, "ALTER TABLE oidc_grants ADD CONSTRAINT event_revoke_failure CHECK(revoked_at IS NULL) NOT VALID")
				}
				if mode == "audit failed" {
					eventSQL(t, f, "ALTER TABLE authentication_events ADD CONSTRAINT event_audit_failure CHECK(false) NOT VALID")
				}
				response := revoke("example-web", token)
				if mode == "business failed" {
					if response.status < 400 {
						t.Fatal("failed revocation reported success")
					}
					f.status(f.userinfo(tokens["access_token"].(string)), 200)
				} else {
					f.status(response, 200)
					f.status(revoke("example-web", token), 200)
					f.status(f.userinfo(tokens["access_token"].(string)), 401)
				}
				recorder.Close(time.Second)
				events := authenticationEvents(t, f)
				if mode == "audit failed" {
					if len(events) != 0 || recorder.Stats().RetryExhausted != 1 {
						t.Fatal(events, recorder.Stats())
					}
					return
				}
				if len(events) != 1 {
					t.Fatal("no-op revocation produced evidence", events)
				}
				event := events[0]
				if event.Type != "grant.revoke" || event.Trigger != "clientRevocation" || event.Actor.Kind != "client" || event.Actor.ID != "example-web" || event.RequestID == "" {
					t.Fatal(event)
				}
				if mode == "business failed" {
					if event.Outcome != "failed" || event.ReasonCode != "backendUnavailable" || event.GrantID != "" || event.MemberID != "" || event.OrganizationID != "" {
						t.Fatal(event)
					}
				} else {
					assertGrantEvent(t, f, event)
					if event.Outcome != "succeeded" || event.GrantID == "" {
						t.Fatal(event)
					}
				}
				assertEventRedaction(t, events, token, f.secret)
			})
		}
	}
}

func TestSharedSessionRevocationEvents(t *testing.T) {
	for _, mode := range []string{"success", "business failed", "commit failed", "audit failed"} {
		t.Run(mode, func(t *testing.T) {
			f := newFixture(t)
			first := f.tokens()
			page, verifier := f.loginPage("second-web", "openid")
			code := f.complete(page, f.otherMember.ID)
			response := f.exchange("second-web", code, verifier)
			f.status(response, 200)
			second := jsonObject(t, response)
			if f.signedClaims(first["id_token"].(string))["sid"] != f.signedClaims(second["id_token"].(string))["sid"] {
				t.Fatal("fixture did not share session")
			}
			recorder := enableAuthenticationEvents(t, f)
			switch mode {
			case "business failed":
				eventSQL(t, f, "ALTER TABLE oidc_grants ADD CONSTRAINT event_revoke_failure CHECK(revoked_at IS NULL) NOT VALID")
			case "commit failed":
				eventSQL(t, f, `CREATE FUNCTION event_commit_failure() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'synthetic commit failure' USING ERRCODE='23514'; END $$;
 CREATE CONSTRAINT TRIGGER event_commit_failure AFTER UPDATE ON authentication_sessions DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION event_commit_failure()`)
			case "audit failed":
				eventSQL(t, f, "ALTER TABLE authentication_events ADD CONSTRAINT event_audit_failure CHECK(false) NOT VALID")
			}
			logout := f.call(f.browser, "GET", "/oauth/logout", nil, nil)
			f.status(logout, 200)
			response = f.logoutConfirmation(logout, "confirm")
			failed := mode == "business failed" || mode == "commit failed"
			if failed {
				if response.status < 400 {
					t.Fatal("failed logout reported success")
				}
				f.status(f.userinfo(first["access_token"].(string)), 200)
				f.status(f.userinfo(second["access_token"].(string)), 200)
			} else {
				f.status(response, 302)
				f.status(f.userinfo(first["access_token"].(string)), 401)
				f.status(f.userinfo(second["access_token"].(string)), 401)
			}
			recorder.Close(3 * time.Second)
			events := authenticationEvents(t, f)
			if mode == "audit failed" {
				if len(events) != 0 || recorder.Stats().RetryExhausted != 3 {
					t.Fatal(events, recorder.Stats())
				}
				return
			}
			var session authevent.Event
			grants := []authevent.Event{}
			for _, event := range events {
				if event.Type == "session.revoke" {
					session = event
				} else {
					grants = append(grants, event)
				}
			}
			if session.EventID == "" || session.OrganizationID != "" || session.MemberID != "" || session.ClientID != "" || session.Actor.Kind != "factor" || session.Actor.ID != session.FactorID || session.SessionID == "" || session.Trigger != "browserLogout" {
				t.Fatal(session)
			}
			if failed {
				if len(events) != 1 || session.Outcome != "failed" {
					t.Fatal("rollback invented committed grant effects", events)
				}
				var revoked bool
				if err := f.store.Database().QueryRow(t.Context(), "SELECT revoked_at IS NOT NULL FROM authentication_sessions").Scan(&revoked); err != nil || revoked {
					t.Fatal(err, revoked)
				}
			} else {
				if len(grants) != 2 || session.Outcome != "succeeded" {
					t.Fatal(events)
				}
				owners := map[string]string{}
				for _, event := range grants {
					owners[event.OrganizationID] = event.MemberID
					if event.Type != "grant.revoke" || event.Outcome != "succeeded" || event.Trigger != "browserLogout" || event.CausationID != session.EventID || event.RequestID != session.RequestID || event.SessionID != session.SessionID || event.GrantID == "" {
						t.Fatal(event)
					}
				}
				if owners[f.member.OrganizationID] != f.member.ID || owners[f.otherMember.OrganizationID] != f.otherMember.ID {
					t.Fatal("organization ownership collapsed", owners)
				}
			}
			assertEventRedaction(t, events, first["access_token"].(string), second["access_token"].(string))
		})
	}
}

func TestLogoutBoundsEvidenceWithoutLimitingRevocation(t *testing.T) {
	f := newFixture(t)
	tokens := f.tokens()
	eventSQL(t, f, `INSERT INTO oidc_grants(id,client_id,session_id,data,expires_at,absolute_expires_at)
 SELECT n.id,g.client_id,g.session_id,g.data||jsonb_build_object('id',n.id),g.expires_at,g.absolute_expires_at
 FROM oidc_grants g CROSS JOIN (SELECT gen_random_uuid()::text AS id FROM generate_series(1,300)) n`)
	recorder := enableAuthenticationEvents(t, f)
	page := f.call(f.browser, "GET", "/oauth/logout", nil, nil)
	f.status(page, 200)
	f.status(f.logoutConfirmation(page, "confirm"), 302)
	f.status(f.userinfo(tokens["access_token"].(string)), 401)
	recorder.Close(5 * time.Second)
	var revoked int
	if err := f.store.Database().QueryRow(t.Context(), "SELECT count(*) FROM oidc_grants WHERE revoked_at IS NOT NULL").Scan(&revoked); err != nil || revoked != 301 {
		t.Fatal("audit cap limited business revocation", err, revoked)
	}
	stats := recorder.Stats()
	if stats.Written+stats.Dropped != 302 || stats.Dropped < 45 {
		t.Fatal("excess evidence was not bounded and accounted for", stats)
	}
}

func TestRepeatedSessionAndOperatorRevocationEvents(t *testing.T) {
	for _, method := range []string{"session", "operator"} {
		t.Run(method, func(t *testing.T) {
			f := newFixture(t)
			f.tokens()
			recorder := enableAuthenticationEvents(t, f)
			if method == "operator" {
				page, err := ListGrants(t.Context(), f.store, GrantFilter{Limit: 1})
				if err != nil {
					t.Fatal(err)
				}
				for range 2 {
					if _, err := RevokeGrant(authevent.RequestContext(t.Context()), f.store, page.Items[0].ID, recorder); err != nil {
						t.Fatal(err)
					}
				}
			} else {
				issuer, _ := url.Parse(f.server.URL)
				secret := ""
				for _, cookie := range f.browser.Jar.Cookies(issuer) {
					if cookie.Name == f.service.cookieName("session") {
						secret = cookie.Value
					}
				}
				var sessionID string
				if err := f.store.Database().QueryRow(t.Context(), "SELECT id FROM authentication_sessions").Scan(&sessionID); err != nil {
					t.Fatal(err)
				}
				for range 2 {
					if err := f.service.storage.endSession(authevent.RequestContext(t.Context()), sessionID, secret); err != nil {
						t.Fatal(err)
					}
				}
			}
			recorder.Close(time.Second)
			events := authenticationEvents(t, f)
			want := 1
			if method == "session" {
				want = 2
			}
			if len(events) != want {
				t.Fatal("repeat created a new state-change event", events)
			}
			if method == "operator" && (events[0].Actor.Kind != "operator" || events[0].Actor.ID != "installation" || events[0].Trigger != "operatorRequest" || events[0].Outcome != "succeeded" || events[0].MemberID != f.member.ID) {
				t.Fatal(events)
			}
		})
	}
}

func TestOperatorRevocationEventFailures(t *testing.T) {
	for _, atCommit := range []bool{false, true} {
		t.Run(map[bool]string{false: "statement", true: "commit"}[atCommit], func(t *testing.T) {
			f := newFixture(t)
			f.tokens()
			page, err := ListGrants(t.Context(), f.store, GrantFilter{Limit: 1})
			if err != nil {
				t.Fatal(err)
			}
			if atCommit {
				eventSQL(t, f, `CREATE FUNCTION event_commit_failure() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'synthetic commit failure' USING ERRCODE='23514'; END $$;
 CREATE CONSTRAINT TRIGGER event_commit_failure AFTER UPDATE ON oidc_grants DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION event_commit_failure()`)
			} else {
				eventSQL(t, f, "ALTER TABLE oidc_grants ADD CONSTRAINT event_revoke_failure CHECK(revoked_at IS NULL) NOT VALID")
			}
			recorder := enableAuthenticationEvents(t, f)
			if _, err := RevokeGrant(authevent.RequestContext(t.Context()), f.store, page.Items[0].ID, recorder); err == nil {
				t.Fatal("failed operator revocation returned success")
			}
			recorder.Close(time.Second)
			events := authenticationEvents(t, f)
			if len(events) != 1 || events[0].Type != "grant.revoke" || events[0].Outcome != "failed" || events[0].ReasonCode != "backendUnavailable" || events[0].Actor.Kind != "operator" || events[0].GrantID != page.Items[0].ID || events[0].MemberID != f.member.ID {
				t.Fatal(events)
			}
			info, err := InspectGrant(t.Context(), f.store, page.Items[0].ID)
			if err != nil || info.RevokedAt != nil {
				t.Fatal("operator failure partially committed", err)
			}
		})
	}
}
