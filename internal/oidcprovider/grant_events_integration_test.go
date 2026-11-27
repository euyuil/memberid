//go:build integration

package oidcprovider

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/zhizhun-tech/memberid/internal/authevent"
	"github.com/zhizhun-tech/memberid/internal/config"
)

func eventSQL(t *testing.T, f *fixture, sql string) {
	t.Helper()
	if _, err := f.store.Database().Exec(t.Context(), sql); err != nil {
		t.Fatal(err)
	}
}

func assertGrantEvent(t *testing.T, f *fixture, event authevent.Event) {
	t.Helper()
	if event.Actor.Kind != "client" || event.Actor.ID != "example-web" || event.ClientID != "example-web" || event.MemberID != f.member.ID || event.OrganizationID != f.member.OrganizationID || event.SessionID == "" || event.FactorID == "" || event.BindingID == "" || event.RequestID == "" || event.InteractionID == "" {
		t.Fatal("incorrect actor or established context", event)
	}
}

func assertEventRedaction(t *testing.T, events []authevent.Event, secrets ...string) {
	t.Helper()
	data, _ := json.Marshal(events)
	for _, secret := range secrets {
		if secret != "" && (strings.Contains(string(data), secret) || strings.Contains(string(data), config.SecretHash(secret))) {
			t.Fatal("credential or credential hash retained in event")
		}
	}
}

func TestGrantIssuanceEvents(t *testing.T) {
	for _, mode := range []string{"success", "factor subject", "ineligible", "eligibility read failed", "rollback", "commit failed", "audit failed"} {
		t.Run(mode, func(t *testing.T) {
			f := newFixture(t)
			clientID, subject := "example-web", f.member.ID
			if mode == "factor subject" {
				clientID, subject = "registration", ""
			}
			page, verifier := f.loginPage(clientID, "openid")
			code := f.complete(f.verifyPhone(page), subject)
			recorder := enableAuthenticationEvents(t, f)
			if len(authenticationEvents(t, f)) != 0 {
				t.Fatal("authorization code issuance invented a committed grant")
			}
			switch mode {
			case "ineligible":
				eventSQL(t, f, "UPDATE members SET manual_block=true")
			case "eligibility read failed":
				eventSQL(t, f, "ALTER TABLE authentication_factors RENAME TO unavailable_authentication_factors")
			case "rollback":
				eventSQL(t, f, "ALTER TABLE oidc_access_tokens ADD CONSTRAINT event_issue_failure CHECK(false) NOT VALID")
			case "commit failed":
				eventSQL(t, f, `CREATE FUNCTION event_commit_failure() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'synthetic commit failure' USING ERRCODE='23514'; END $$;
 CREATE CONSTRAINT TRIGGER event_commit_failure AFTER INSERT ON oidc_grants DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION event_commit_failure()`)
			case "audit failed":
				eventSQL(t, f, "ALTER TABLE authentication_events ADD CONSTRAINT event_audit_failure CHECK(false) NOT VALID")
			}
			response := f.exchange(clientID, code, verifier)
			succeeded := mode == "success" || mode == "factor subject" || mode == "audit failed"
			if (response.status == 200) != succeeded {
				t.Fatal("unexpected issuance outcome", response.status)
			}
			recorder.Close(time.Second)
			events := authenticationEvents(t, f)
			var grants, tokens int
			var consumed bool
			if err := f.store.Database().QueryRow(t.Context(), "SELECT (SELECT count(*) FROM oidc_grants),(SELECT count(*) FROM oidc_access_tokens),EXISTS(SELECT 1 FROM authentication_requests WHERE consumed_at IS NOT NULL)").Scan(&grants, &tokens, &consumed); err != nil || (grants == 1 && tokens == 1 && consumed) != succeeded || !succeeded && (grants != 0 || tokens != 0 || consumed) {
				t.Fatal("issuance transaction boundary", err, grants, tokens, consumed)
			}
			if mode == "audit failed" {
				if len(events) != 0 || recorder.Stats().RetryExhausted != 1 {
					t.Fatal(events, recorder.Stats())
				}
				f.status(f.userinfo(jsonObject(t, response)["access_token"].(string)), 200)
				return
			}
			if len(events) != 1 || events[0].Type != "oidc.grant.issue" {
				t.Fatal(events)
			}
			event := events[0]
			if mode == "factor subject" {
				if event.MemberID != "" || event.OrganizationID != "" || event.BindingID != "" || event.FactorID == "" || event.Actor.Kind != "client" || event.Actor.ID != clientID {
					t.Fatal("factor grant inferred Member", event)
				}
			} else {
				assertGrantEvent(t, f, event)
			}
			outcome, reason := "succeeded", ""
			if mode == "ineligible" {
				outcome, reason = "rejected", "invalidCredential"
			} else if !succeeded {
				outcome, reason = "failed", "backendUnavailable"
			}
			if event.Outcome != outcome || event.ReasonCode != reason || (event.GrantID != "") != succeeded {
				t.Fatal("incorrect result or uncommitted grant reference", event)
			}
			assertEventRedaction(t, events, code, verifier, f.secret)
		})
	}
}

func TestCodeEventValidationBoundary(t *testing.T) {
	f := newFixture(t)
	page, verifier := f.loginPage("example-web", "openid")
	code := f.complete(f.verifyPhone(page), f.member.ID)
	recorder := enableAuthenticationEvents(t, f)
	f.status(f.exchange("second-web", code, verifier), 400)
	f.status(f.exchange("example-web", code, config.RandomSecret()), 400)
	f.status(f.exchange("example-web", config.RandomSecret(), verifier), 400)
	f.status(f.exchange("example-web", code, verifier), 200)
	f.status(f.exchange("second-web", code, verifier), 400)
	f.status(f.exchange("example-web", code, config.RandomSecret()), 400)
	recorder.Close(time.Second)
	events := authenticationEvents(t, f)
	if len(events) != 1 || events[0].Type != "oidc.grant.issue" || events[0].Outcome != "succeeded" {
		t.Fatal("unvalidated token attempt became confirmed reuse", events)
	}
	var revoked bool
	if err := f.store.Database().QueryRow(t.Context(), "SELECT revoked_at IS NOT NULL FROM oidc_grants").Scan(&revoked); err != nil || revoked {
		t.Fatal("invalid client or PKCE revoked grant", err)
	}
}

func TestCodeExpiryBetweenLookupAndConsumptionIsNotReuse(t *testing.T) {
	f := newFixture(t)
	page, verifier := f.loginPage("example-web", "openid")
	code := f.complete(f.verifyPhone(page), f.member.ID)
	request, err := f.service.storage.AuthRequestByCode(t.Context(), code)
	if err != nil {
		t.Fatal(err)
	}
	eventSQL(t, f, "UPDATE authentication_requests SET expires_at=clock_timestamp()-interval '1 second'")
	recorder := enableAuthenticationEvents(t, f)
	_, _, _, err = f.service.storage.createCodeTokens(authevent.RequestContext(t.Context()), request.(*authorizationRequest), false)
	if err == nil {
		t.Fatal("expired code consumed")
	}
	recorder.Close(time.Second)
	events := authenticationEvents(t, f)
	if len(events) != 1 || events[0].Type != "oidc.grant.issue" || events[0].Outcome != "rejected" || events[0].GrantID != "" {
		t.Fatal(events)
	}
	assertEventRedaction(t, events, code, verifier)
}

func TestCredentialReuseEvents(t *testing.T) {
	for _, kind := range []string{"authorizationCode", "refreshToken"} {
		for _, mode := range []string{"success", "revocation failed", "commit failed", "already revoked", "audit failed"} {
			t.Run(kind+"/"+mode, func(t *testing.T) {
				f := newConfiguredFixture(t, true)
				page, verifier := f.loginPage("example-web", "openid offline_access")
				code := f.complete(f.verifyPhone(page), f.member.ID)
				initial := f.exchange("example-web", code, verifier)
				f.status(initial, 200)
				tokens := jsonObject(t, initial)
				secret := tokens["refresh_token"].(string)
				reuse := func() reply { return f.exchange("example-web", code, verifier) }
				if kind == "refreshToken" {
					f.status(f.refresh("example-web", secret, ""), 200)
					reuse = func() reply { return f.refresh("example-web", secret, "") }
				}
				recorder := enableAuthenticationEvents(t, f)
				if kind == "refreshToken" {
					f.status(f.refresh("second-web", secret, ""), 400)
					f.status(f.refresh("example-web", config.RandomSecret(), ""), 400)
				}
				switch mode {
				case "revocation failed":
					eventSQL(t, f, "ALTER TABLE oidc_grants ADD CONSTRAINT event_revoke_failure CHECK(revoked_at IS NULL) NOT VALID")
				case "commit failed":
					eventSQL(t, f, `CREATE FUNCTION event_commit_failure() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'synthetic commit failure' USING ERRCODE='23514'; END $$;
 CREATE CONSTRAINT TRIGGER event_commit_failure AFTER UPDATE ON oidc_grants DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION event_commit_failure()`)
				case "already revoked":
					eventSQL(t, f, "UPDATE oidc_grants SET revoked_at=clock_timestamp()")
				case "audit failed":
					eventSQL(t, f, "ALTER TABLE authentication_events ADD CONSTRAINT event_audit_failure CHECK(false) NOT VALID")
				}
				response := reuse()
				if response.status == 200 {
					t.Fatal("reused credential accepted")
				}
				recorder.Close(time.Second)
				events := authenticationEvents(t, f)
				var revoked bool
				wantRevoked := mode != "revocation failed" && mode != "commit failed"
				if err := f.store.Database().QueryRow(t.Context(), "SELECT revoked_at IS NOT NULL FROM oidc_grants").Scan(&revoked); err != nil || revoked != wantRevoked {
					t.Fatal("revocation transaction changed", err, revoked)
				}
				if mode == "audit failed" {
					if len(events) != 0 || recorder.Stats().RetryExhausted != 2 {
						t.Fatal(events, recorder.Stats())
					}
					return
				}
				count := 2
				if mode == "already revoked" {
					count = 1
					if kind == "refreshToken" {
						count = 0
					}
				}
				if len(events) != count {
					t.Fatal(events)
				}
				if count == 0 {
					return
				}
				detected := events[0]
				assertGrantEvent(t, f, detected)
				if detected.Type != "oidc."+kind+".reuse" || detected.Outcome != "detected" || detected.GrantID == "" {
					t.Fatal(detected)
				}
				if count == 2 {
					result := events[1]
					assertGrantEvent(t, f, result)
					outcome := "succeeded"
					if !wantRevoked {
						outcome = "failed"
					}
					if result.Type != "grant.revoke" || result.Outcome != outcome || result.CausationID != detected.EventID || result.Trigger != "replayDetection" || result.GrantID != detected.GrantID || result.RequestID != detected.RequestID || result.InteractionID != detected.InteractionID {
						t.Fatal(detected, result)
					}
				}
				assertEventRedaction(t, events, code, verifier, secret, f.secret, tokens["access_token"].(string), tokens["id_token"].(string))
			})
		}
	}
}

func TestConcurrentCodeEventsRevokeOnlyOnce(t *testing.T) {
	f := newFixture(t)
	page, verifier := f.loginPage("example-web", "openid")
	code := f.complete(f.verifyPhone(page), f.member.ID)
	recorder := enableAuthenticationEvents(t, f)
	results := make(chan reply, 8)
	for range 8 {
		go func() { results <- f.exchange("example-web", code, verifier) }()
	}
	successes := 0
	for range 8 {
		if (<-results).status == 200 {
			successes++
		}
	}
	recorder.Close(time.Second)
	counts := map[string]int{}
	for _, event := range authenticationEvents(t, f) {
		counts[event.Type]++
	}
	if successes != 1 || counts["oidc.grant.issue"] != 1 || counts["oidc.authorizationCode.reuse"] != 7 || counts["grant.revoke"] != 1 {
		t.Fatal(successes, counts)
	}
}

func TestConcurrentRefreshEventsRevokeOnlyOnce(t *testing.T) {
	f := newConfiguredFixture(t, true)
	tokens := f.refreshTokens()
	recorder := enableAuthenticationEvents(t, f)
	results := make(chan reply, 8)
	for range 8 {
		go func() { results <- f.refresh("example-web", tokens["refresh_token"].(string), "") }()
	}
	successes := 0
	for range 8 {
		if (<-results).status == 200 {
			successes++
		}
	}
	recorder.Close(time.Second)
	events := authenticationEvents(t, f)
	counts := map[string]int{}
	for _, event := range events {
		counts[event.Type]++
	}
	if successes != 1 || len(events) != 2 || counts["oidc.refreshToken.reuse"] != 1 || counts["grant.revoke"] != 1 {
		t.Fatal("normal rotation produced an issuance or duplicate revocation", successes, counts)
	}
}
