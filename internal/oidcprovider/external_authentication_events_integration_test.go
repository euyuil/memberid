//go:build integration

package oidcprovider

import (
	"encoding/base64"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/zhizhun-tech/memberid/internal/config"
	"github.com/zhizhun-tech/memberid/internal/identity"
)

func beginFeishuEvent(t *testing.T, f *fixture) string {
	t.Helper()
	provider := new(testFeishu)
	key, _ := base64.StdEncoding.DecodeString(f.service.configuration.Secrets.ProviderKey)
	apps, err := identity.NewFeishuApplications(f.store, key, provider)
	if err != nil {
		t.Fatal(err)
	}
	f.service.feishu = apps
	if err := f.store.SetAdministrator(t.Context(), identity.OperatorPrincipal(), f.member.OrganizationID, f.member.ID, true); err != nil {
		t.Fatal(err)
	}
	server := consoleProviderFixture(t, f, new(testDingTalk), provider)
	consoleLogin(t, f, server, f.member.ID)
	csrf := consoleJSON(t, f, server, "GET", "/api/session", "", "", 200)["csrf"].(string)
	body := `{"displayName":"Feishu","clientId":"cli_first","tenantId":"example-tenant","clientSecret":"` + config.RandomSecret() + `","expectedRevision":0,"enabled":true}`
	app := consoleJSON(t, f, server, "POST", "/api/organizations/"+f.member.OrganizationID+"/providers/feishu", csrf, body, 200)["id"].(string)
	f.browser = browserClient()
	page, _ := f.loginPage("example-web", "openid")
	started := f.submit(page.body, "feishu", url.Values{"organization": {f.member.OrganizationID}, "provider": {app}})
	upstream, err := url.Parse(f.externalDestination(started, "feishu"))
	if err != nil {
		t.Fatal(err)
	}
	return feishuCallbackPath + "?" + url.Values{"state": {upstream.Query().Get("state")}, "code": {"synthetic-code"}}.Encode()
}

func TestExternalVerificationEvents(t *testing.T) {
	for _, method := range []string{"dingtalk", "feishu"} {
		for _, mode := range []string{"success and replay", "provider failure", "canceled", "provider callback error", "wrong browser", "request lookup failed", "organization disabled", "rollback", "audit failed"} {
			t.Run(method+"/"+mode, func(t *testing.T) {
				f := newFixture(t)
				path := ""
				if method == "dingtalk" {
					enableDingTalk(t, f, true)
					_, _, path = beginDingTalk(t, f, "example-web", "openid", f.member.OrganizationID)
				} else {
					path = beginFeishuEvent(t, f)
				}
				parsed, _ := url.Parse(path)
				query := parsed.Query()
				switch mode {
				case "provider failure":
					query.Set("code", "invalid-provider-code")
					if method == "dingtalk" {
						query.Set("authCode", "invalid-provider-code")
					}
				case "canceled":
					query.Del("code")
					query.Del("authCode")
					query.Set("error", "access_denied")
					query.Set("error_description", "private callback description")
				case "provider callback error":
					query.Del("code")
					query.Del("authCode")
					query.Set("error", "server_error")
				}
				parsed.RawQuery = query.Encode()
				path = parsed.String()
				recorder := enableAuthenticationEvents(t, f)
				if mode == "request lookup failed" {
					if _, err := f.store.Database().Exec(t.Context(), "ALTER TABLE authentication_requests RENAME TO unavailable_authorization_requests"); err != nil {
						t.Fatal(err)
					}
				}
				if mode == "organization disabled" {
					if _, err := f.store.Database().Exec(t.Context(), "UPDATE organizations SET status='disabled' WHERE id=$1", f.member.OrganizationID); err != nil {
						t.Fatal(err)
					}
				}
				if mode == "rollback" {
					if _, err := f.store.Database().Exec(t.Context(), "ALTER TABLE authentication_sessions ADD CONSTRAINT event_external_failure CHECK(false) NOT VALID"); err != nil {
						t.Fatal(err)
					}
				}
				if mode == "audit failed" {
					if _, err := f.store.Database().Exec(t.Context(), "ALTER TABLE authentication_events ADD CONSTRAINT event_audit_failure CHECK(false) NOT VALID"); err != nil {
						t.Fatal(err)
					}
				}
				browser := f.browser
				if mode == "wrong browser" {
					browser = browserClient()
				}
				result := f.call(browser, "GET", path, nil, nil)
				status := 200
				success := mode == "success and replay" || mode == "audit failed"
				if success {
					status = 303
				}
				if mode == "wrong browser" || mode == "request lookup failed" {
					status = 400
				}
				if mode == "rollback" {
					status = 403
				}
				f.status(result, status)
				if (result.header.Get("Set-Cookie") != "") != success {
					t.Fatal("session cookie before commit")
				}
				if mode == "success and replay" {
					f.status(f.call(f.browser, "GET", path, nil, nil), 400)
				}
				recorder.Close(time.Second)
				events := authenticationEvents(t, f)
				if mode == "audit failed" {
					if len(events) != 0 || recorder.Stats().RetryExhausted != 1 {
						t.Fatal(events, recorder.Stats())
					}
					return
				}
				count := 1
				if mode == "success and replay" {
					count = 2
				}
				if len(events) != count {
					t.Fatal(events)
				}
				event := events[0]
				outcome, reason := "succeeded", ""
				switch mode {
				case "provider failure", "provider callback error":
					outcome, reason = "failed", "providerUnavailable"
				case "canceled":
					outcome, reason = "rejected", "canceled"
				case "wrong browser":
					outcome, reason = "rejected", "invalidCredential"
					if method == "dingtalk" {
						reason = "ineligible"
					}
				case "rollback", "request lookup failed":
					outcome, reason = "failed", "backendUnavailable"
				case "organization disabled":
					outcome, reason = "rejected", "ineligible"
				}
				if event.Type != "authentication.verify" || event.Method != method || event.Purpose != "login" || event.Outcome != outcome || event.ReasonCode != reason || event.RequestID == "" {
					t.Fatal(event)
				}
				if mode == "wrong browser" || mode == "request lookup failed" {
					if event.OrganizationID != "" || event.ClientID != "" || event.InteractionID != "" || event.ProviderID != "" {
						t.Fatal("unvalidated workflow ownership", event)
					}
				} else if event.OrganizationID != f.member.OrganizationID || event.InteractionID == "" || event.ProviderID == "" {
					t.Fatal("lost validated workflow", event)
				}
				if success {
					var bound, sessionSafe bool
					if err := f.store.Database().QueryRow(t.Context(), `SELECT EXISTS(SELECT 1 FROM member_auth_factor_bindings WHERE id::text=$1 AND member_id=$2 AND authentication_factor_id=$3 AND organization_id=$4),
      EXISTS(SELECT 1 FROM authentication_sessions WHERE id=$5 AND verification->'factor'->>'id'=$3 AND NOT (verification?'memberId' OR verification?'MemberID'))`, event.BindingID, event.MemberID, event.FactorID, event.OrganizationID, event.SessionID).Scan(&bound, &sessionSafe); err != nil || !bound || !sessionSafe || event.Actor.Kind != "member" || event.Actor.ID != event.MemberID {
						t.Fatal("uncommitted or shared Member authority", err, event)
					}
					replay := events[1]
					if replay.Outcome != "rejected" || replay.Actor.Kind != "" || replay.MemberID != "" || replay.SessionID != "" || replay.OrganizationID != "" {
						t.Fatal("callback replay became authentication", replay)
					}
				} else if event.MemberID != "" || event.Actor.Kind != "" || event.FactorID != "" || event.BindingID != "" || event.SessionID != "" {
					t.Fatal("failure invented established identity", event)
				}
				var leaked bool
				if err := f.store.Database().QueryRow(t.Context(), "SELECT EXISTS(SELECT 1 FROM authentication_events WHERE data::text LIKE '%synthetic-code%' OR data::text LIKE '%private callback%' OR data::text LIKE '%invalid-provider-code%')").Scan(&leaked); err != nil || leaked {
					t.Fatal("private callback data retained", err)
				}
			})
		}
	}
}

func TestDingTalkLinkVerificationEvents(t *testing.T) {
	for _, mode := range []string{"success", "provider failure", "canceled", "rollback", "audit failed"} {
		t.Run(mode, func(t *testing.T) {
			f, provider, _, page := accountFixture(t)
			path := startAccount(f, page)
			recorder := enableAuthenticationEvents(t, f)
			switch mode {
			case "provider failure":
				provider.fail = true
			case "canceled":
				parsed, _ := url.Parse(path)
				query := parsed.Query()
				query.Del("authCode")
				query.Set("error", "access_denied")
				parsed.RawQuery = query.Encode()
				path = parsed.String()
			case "rollback":
				if _, err := f.store.Database().Exec(t.Context(), "ALTER TABLE account_link_requests ADD CONSTRAINT event_link_failure CHECK(state<>'completed') NOT VALID"); err != nil {
					t.Fatal(err)
				}
			case "audit failed":
				if _, err := f.store.Database().Exec(t.Context(), "ALTER TABLE authentication_events ADD CONSTRAINT event_audit_failure CHECK(false) NOT VALID"); err != nil {
					t.Fatal(err)
				}
			}
			result := f.call(f.browser, "GET", path, nil, nil)
			f.status(result, 200)
			success := mode == "success" || mode == "audit failed"
			if strings.Contains(result.body, "DingTalk is linked to this Member") != success {
				t.Fatal("link outcome changed")
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
				t.Fatal(events)
			}
			event := events[0]
			outcome, reason := "succeeded", ""
			switch mode {
			case "provider failure":
				outcome, reason = "failed", "providerUnavailable"
			case "canceled":
				outcome, reason = "rejected", "canceled"
			case "rollback":
				outcome, reason = "failed", "backendUnavailable"
			}
			if event.Type != "authentication.verify" || event.Purpose != "accountLinking" || event.Method != "dingtalk" || event.Outcome != outcome || event.ReasonCode != reason || event.MemberID != f.member.ID || event.OrganizationID != f.member.OrganizationID || event.Actor.ID != f.member.ID || event.Actor.Kind != "member" || event.ProviderID == "" {
				t.Fatal(event)
			}
			if success {
				var bound bool
				if err := f.store.Database().QueryRow(t.Context(), "SELECT EXISTS(SELECT 1 FROM member_auth_factor_bindings WHERE id::text=$1 AND member_id=$2 AND authentication_factor_id=$3 AND factor_type='dingtalk')", event.BindingID, event.MemberID, event.FactorID).Scan(&bound); err != nil || !bound {
					t.Fatal("missing committed target", err)
				}
			} else {
				if event.BindingID != "" || event.FactorID != "" {
					t.Fatal("failed link exposed target", event)
				}
				assertUnlinked(t, f)
			}
		})
	}
}
