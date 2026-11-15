//go:build integration

package oidcprovider

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/euyuil/memberid/internal/authevent"
)

func TestSAMLIssuanceEventBoundaries(t *testing.T) {
	for _, mode := range []string{"success", "session revoked", "session read failed", "rollback", "commit failed", "audit failed", "provider unavailable"} {
		t.Run(mode, func(t *testing.T) {
			s := newSAMLIdentityFixture(t)
			method := "phone"
			if mode == "provider unavailable" {
				method = "dingtalk"
			}
			page := s.authenticate(method)
			recorder := enableAuthenticationEvents(t, s.fixture)
			switch mode {
			case "session revoked":
				eventSQL(t, s.fixture, "UPDATE authentication_sessions SET revoked_at=clock_timestamp()")
			case "session read failed":
				eventSQL(t, s.fixture, "ALTER TABLE authentication_sessions RENAME TO unavailable_authentication_sessions")
			case "rollback":
				eventSQL(t, s.fixture, "ALTER TABLE authentication_requests ADD CONSTRAINT synthetic_issue_failure CHECK(consumed_at IS NULL) NOT VALID")
			case "commit failed":
				eventSQL(t, s.fixture, `CREATE FUNCTION synthetic_saml_commit_failure() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'private database diagnostic' USING ERRCODE='23514'; END $$;
 CREATE CONSTRAINT TRIGGER synthetic_saml_commit_failure AFTER UPDATE ON authentication_requests DEFERRABLE INITIALLY DEFERRED FOR EACH ROW WHEN (NEW.consumed_at IS NOT NULL) EXECUTE FUNCTION synthetic_saml_commit_failure()`)
			case "audit failed":
				eventSQL(t, s.fixture, "ALTER TABLE authentication_events ADD CONSTRAINT synthetic_audit_failure CHECK(false) NOT VALID")
			case "provider unavailable":
				s.ding.directoryError = errors.New("private provider diagnostic")
			}
			result := s.completeSAML(page)
			succeeded := mode == "success" || mode == "audit failed"
			if strings.Contains(result.body, "SAMLResponse") != succeeded {
				t.Fatal("unexpected assertion delivery", result.status)
			}
			var consumed bool
			if err := s.store.Database().QueryRow(t.Context(), "SELECT consumed_at IS NOT NULL FROM authentication_requests WHERE id=$1", hidden(t, page.body, "request")).Scan(&consumed); err != nil || consumed != succeeded {
				t.Fatal("event and issuance transaction disagree", err)
			}
			recorder.Close(time.Second)
			events := authenticationEvents(t, s.fixture)
			if mode == "audit failed" {
				if len(events) != 0 || recorder.Stats().RetryExhausted != 1 {
					t.Fatal("audit availability changed successful authentication")
				}
				return
			}
			if len(events) != 1 {
				t.Fatalf("expected one issuance event, got %d", len(events))
			}
			event := events[0]
			outcome, reason := "failed", "backendUnavailable"
			if succeeded {
				outcome, reason = "succeeded", ""
			}
			if mode == "session revoked" {
				outcome, reason = "rejected", "ineligible"
			}
			if mode == "provider unavailable" {
				reason = "providerUnavailable"
			}
			if event.Type != "saml.assertion.issue" || event.Outcome != outcome || event.ReasonCode != reason {
				t.Fatal("incorrect issuance outcome", event.Type, event.Outcome, event.ReasonCode)
			}
			if event.OrganizationID != s.member.OrganizationID || event.MemberID != s.member.ID || event.FactorID != s.factors[method] || event.SessionID == "" || event.ClientID != s.sp.ID || event.InteractionID == "" || event.RequestID == "" || event.GrantID != "" {
				t.Fatal("missing or invented SAML context")
			}
			if succeeded && (event.Actor != (authevent.Actor{Kind: "member", ID: s.member.ID}) || event.Method != "sms" || event.BindingID == "") {
				t.Fatal("missing established authentication context")
			}
			assertEventRedaction(t, events, s.password, hidden(t, page.body, "csrf"), "private database diagnostic", "private provider diagnostic", "https://untrusted.example.test/not-a-redirect")
			if succeeded {
				assertEventRedaction(t, events, hidden(t, result.body, "SAMLResponse"))
			}
		})
	}
}
