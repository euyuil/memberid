//go:build integration

package oidcprovider

import (
	"net/url"
	"strings"
	"testing"
	"time"
)

func TestSMSVerificationEventBoundaries(t *testing.T) {
	for _, mode := range []string{"success", "wrong code", "expired code", "rollback", "attempt write failed", "commit failed", "audit failed"} {
		t.Run(mode, func(t *testing.T) {
			f := newFixture(t)
			page, _ := f.loginPage("registration", "openid registration_identity")
			sent := f.submit(page.body, "send", url.Values{"phone": {"19900000003"}})
			f.status(sent, 200)
			code := f.sender.latest()
			recorder := enableAuthenticationEvents(t, f)
			sql := ""
			switch mode {
			case "wrong code", "attempt write failed":
				if code == "000000" {
					code = "111111"
				} else {
					code = "000000"
				}
				if mode == "attempt write failed" {
					sql = "ALTER TABLE phone_challenges ADD CONSTRAINT event_attempt_failure CHECK(attempts=0) NOT VALID"
				}
			case "expired code":
				sql = "UPDATE phone_challenges SET expires_at=now()-interval '1 second'"
			case "rollback":
				sql = "ALTER TABLE oidc_authorization_requests ADD CONSTRAINT event_request_failure CHECK(false) NOT VALID"
			case "commit failed":
				sql = `CREATE FUNCTION event_commit_failure() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'synthetic commit failure'; END $$;
    CREATE CONSTRAINT TRIGGER event_commit_failure AFTER INSERT ON oidc_sessions DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION event_commit_failure()`
			case "audit failed":
				sql = "ALTER TABLE authentication_events ADD CONSTRAINT event_audit_failure CHECK(false) NOT VALID"
			}
			if sql != "" {
				if _, err := f.store.Database().Exec(t.Context(), sql); err != nil {
					t.Fatal(err)
				}
			}
			result := f.submit(sent.body, "verify", url.Values{"code": {code}})
			success := mode == "success" || mode == "audit failed"
			status := 200
			if mode == "rollback" || mode == "attempt write failed" || mode == "commit failed" {
				status = 400
			}
			f.status(result, status)
			if strings.Contains(result.body, "Phone verified") != success || (result.header.Get("Set-Cookie") != "") != success {
				t.Fatal("wrong login outcome", mode)
			}
			recorder.Close(time.Second)
			events := authenticationEvents(t, f)
			if mode == "audit failed" {
				if len(events) != 0 || recorder.Stats().RetryExhausted != 1 {
					t.Fatal("audit failure was not isolated", events, recorder.Stats())
				}
			} else {
				if len(events) != 1 {
					t.Fatal(events)
				}
				event := events[0]
				outcome, reason := "succeeded", ""
				if mode == "wrong code" || mode == "expired code" {
					outcome, reason = "rejected", "invalidCredential"
				}
				if mode == "rollback" || mode == "attempt write failed" || mode == "commit failed" {
					outcome, reason = "failed", "backendUnavailable"
				}
				if event.Type != "authentication.verify" || event.Method != "sms" || event.Purpose != "login" || event.Outcome != outcome || event.ReasonCode != reason || event.MemberID != "" || event.OrganizationID != "" || event.RequestID == "" || event.InteractionID == "" {
					t.Fatal(event)
				}
				if success {
					var factorID string
					if err := f.store.Database().QueryRow(t.Context(), "SELECT verification->'factor'->>'id' FROM oidc_sessions WHERE id=$1", event.SessionID).Scan(&factorID); err != nil || factorID != event.FactorID || event.Actor.Kind != "factor" || event.Actor.ID != factorID {
						t.Fatal("invented successful identity", err, event)
					}
				} else if event.FactorID != "" || event.SessionID != "" || event.Actor.Kind != "" {
					t.Fatal("failed verification invented identity", event)
				}
			}
			var sessions, factors, consumed int
			if err := f.store.Database().QueryRow(t.Context(), "SELECT (SELECT count(*) FROM oidc_sessions),(SELECT count(*) FROM authentication_factors WHERE subject='+8619900000003'),(SELECT count(*) FROM phone_challenges WHERE consumed_at IS NOT NULL)").Scan(&sessions, &factors, &consumed); err != nil {
				t.Fatal(err)
			}
			want := 0
			if success {
				want = 1
			}
			if sessions != want || factors != want || consumed != want {
				t.Fatal("partial verification state", sessions, factors, consumed)
			}
		})
	}
}

func TestSMSAccountVerificationEvents(t *testing.T) {
	for _, mode := range []string{"success", "wrong code", "rollback", "audit failed"} {
		t.Run(mode, func(t *testing.T) {
			f, page := phoneAccountFixture(t)
			sent := sendAccountPhone(f, page)
			code := f.sender.latest()
			recorder := enableAuthenticationEvents(t, f)
			switch mode {
			case "wrong code":
				if code == "000000" {
					code = "111111"
				} else {
					code = "000000"
				}
			case "rollback":
				if _, err := f.store.Database().Exec(t.Context(), "ALTER TABLE member_auth_factor_bindings ADD CONSTRAINT event_link_failure CHECK(factor_type<>'phone') NOT VALID"); err != nil {
					t.Fatal(err)
				}
			case "audit failed":
				if _, err := f.store.Database().Exec(t.Context(), "ALTER TABLE authentication_events ADD CONSTRAINT event_audit_failure CHECK(false) NOT VALID"); err != nil {
					t.Fatal(err)
				}
			}
			result := phoneAccountSubmit(f, sent, "verify", url.Values{"code": {code}})
			f.status(result, 200)
			success := mode == "success" || mode == "audit failed"
			if strings.Contains(result.body, "Phone is linked to this Member") != success {
				t.Fatal("wrong linking outcome")
			}
			recorder.Close(time.Second)
			events := authenticationEvents(t, f)
			if mode == "audit failed" {
				if len(events) != 0 || recorder.Stats().RetryExhausted != 1 {
					t.Fatal(events, recorder.Stats())
				}
			} else {
				if len(events) != 1 {
					t.Fatal(events)
				}
				event := events[0]
				outcome, reason := "succeeded", ""
				if mode == "wrong code" {
					outcome, reason = "rejected", "invalidCredential"
				}
				if mode == "rollback" {
					outcome, reason = "failed", "backendUnavailable"
				}
				if event.Type != "authentication.verify" || event.Method != "sms" || event.Purpose != "accountLinking" || event.Outcome != outcome || event.ReasonCode != reason || event.MemberID != f.member.ID || event.OrganizationID != f.member.OrganizationID || event.Actor.Kind != "member" || event.Actor.ID != f.member.ID || event.BindingID != "" || event.RequestID == "" || event.InteractionID == "" {
					t.Fatal(event)
				}
				if success {
					var bound bool
					if err := f.store.Database().QueryRow(t.Context(), "SELECT EXISTS(SELECT 1 FROM member_auth_factor_bindings WHERE member_id=$1 AND authentication_factor_id=$2 AND factor_type='phone')", event.MemberID, event.FactorID).Scan(&bound); err != nil || !bound {
						t.Fatal("factor not committed", err)
					}
				} else if event.FactorID != "" {
					t.Fatal("uncommitted factor exposed")
				}
			}
			if !success {
				assertPhoneNotLinked(t, f)
			}
		})
	}
}
