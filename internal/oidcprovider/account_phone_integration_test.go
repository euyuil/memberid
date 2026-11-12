//go:build integration

package oidcprovider

import (
	"context"
	"encoding/base64"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"testing"

	"github.com/euyuil/memberid/internal/identity"
)

const linkPhoneNumber = "19900000003"

func phoneAccountFixture(t *testing.T) (*fixture, reply) {
	t.Helper()
	f := newConfiguredFixture(t, true)
	enableDingTalk(t, f, true)
	f.service.configuration.Clients[0].AccountReturnURIs = []string{accountReturn}
	_, verifier, callbackPath := beginDingTalk(t, f, "example-web", "openid offline_access", f.member.OrganizationID)
	response := f.call(f.browser, "GET", callbackPath, nil, nil)
	f.status(response, 303)
	login := f.call(f.browser, "GET", response.header.Get("Location"), nil, nil)
	member, err := f.store.Member(t.Context(), f.member.OrganizationID, admittedMember(t, f, f.member.OrganizationID))
	if err != nil {
		t.Fatal(err)
	}
	f.member = member
	f.status(f.exchange("example-web", f.complete(login, member.ID), verifier), 200)
	page := f.call(f.browser, "GET", phoneAccountPath+"?"+url.Values{"memberId": {member.ID}, "client_id": {"example-web"}, "returnUri": {accountReturn}}.Encode(), nil, nil)
	f.status(page, 200)
	return f, page
}

func phoneAccountSubmit(f *fixture, page reply, action string, extra url.Values) reply {
	f.t.Helper()
	form := url.Values{"request": {hidden(f.t, page.body, "request")}, "csrf": {hidden(f.t, page.body, "csrf")}, "action": {action}}
	for key, value := range extra {
		form[key] = value
	}
	return f.call(f.browser, "POST", phoneAccountPath, form, map[string]string{"Origin": f.server.URL})
}
func sendAccountPhone(f *fixture, page reply) reply {
	f.t.Helper()
	result := phoneAccountSubmit(f, page, "send", url.Values{"phone": {linkPhoneNumber}})
	f.status(result, 200)
	if !strings.Contains(result.body, "Enter the verification code") {
		f.t.Fatal("phone challenge not started", result.body)
	}
	return result
}
func assertPhoneNotLinked(t *testing.T, f *fixture) {
	t.Helper()
	var bindings, factors int
	if err := f.store.Database().QueryRow(t.Context(), "SELECT (SELECT count(*) FROM member_auth_factor_bindings WHERE member_id=$1 AND factor_type='phone'),(SELECT count(*) FROM authentication_factors WHERE subject=$2)", f.member.ID, "+86"+linkPhoneNumber).Scan(&bindings, &factors); err != nil || bindings != 0 || factors != 0 {
		t.Fatal("failed account request left partial identity", err)
	}
}
func loginState(t *testing.T, f *fixture) string {
	t.Helper()
	var state string
	if err := f.store.Database().QueryRow(t.Context(), "SELECT jsonb_build_object('sessions',(SELECT jsonb_agg(to_jsonb(s) ORDER BY id) FROM oidc_sessions s),'grants',(SELECT jsonb_agg(to_jsonb(g) ORDER BY id) FROM oidc_grants g))::text").Scan(&state); err != nil {
		t.Fatal(err)
	}
	return state
}

func TestPhoneAccountPreservesSessionGrantAndSubject(t *testing.T) {
	f, page := phoneAccountFixture(t)
	before := loginState(t, f)
	sent := sendAccountPhone(f, page)
	code := f.sender.latest()
	linked := phoneAccountSubmit(f, sent, "verify", url.Values{"code": {code}, "phone": {"19900000004"}})
	f.status(linked, 200)
	if !strings.Contains(linked.body, "Phone is linked to this Member") || linked.header.Get("Set-Cookie") != "" || !strings.Contains(linked.body, `href="`+accountReturn+`"`) {
		t.Fatal("incorrect success response", linked.body)
	}
	if after := loginState(t, f); before != after {
		t.Fatal("link changed session, authentication time, or grant")
	}
	factor, err := f.store.PhoneFactor(t.Context(), linkPhoneNumber)
	if err != nil {
		t.Fatal(err)
	}
	bindings, err := f.store.Bindings(t.Context(), f.member.OrganizationID, f.member.ID)
	if err != nil || len(bindings) != 2 {
		t.Fatal("expected one new binding", err)
	}
	found := false
	for _, binding := range bindings {
		if binding.FactorID == factor.ID {
			found = true
		}
	}
	if !found {
		t.Fatal("submitted phone overrode server challenge")
	}
	f.status(phoneAccountSubmit(f, sent, "verify", url.Values{"code": {code}}), 400)
	// A later standard phone login resolves to the same independent Member.
	f.browser = browserClient()
	login, verifier := f.loginPage("example-web", "openid phone offline_access")
	if _, err := f.store.Database().Exec(t.Context(), "UPDATE phone_challenges SET created_at=created_at-interval '61 seconds'"); err != nil {
		t.Fatal(err)
	}
	login = f.submit(login.body, "send", url.Values{"phone": {linkPhoneNumber}})
	f.status(login, 200)
	login = f.submit(login.body, "verify", url.Values{"code": {f.sender.latest()}})
	f.status(login, 200)
	tokens := f.exchange("example-web", f.complete(login, f.member.ID), verifier)
	f.status(tokens, 200)
	values := jsonObject(t, tokens)
	if claims := f.signedClaims(values["id_token"].(string)); claims["sub"] != f.member.ID {
		t.Fatal("phone login changed subject")
	}
	f.status(f.refresh("example-web", values["refresh_token"].(string), ""), 200)
}

func TestPhoneAccountBrowserClientAndFormBoundaries(t *testing.T) {
	f, page := phoneAccountFixture(t)
	path := phoneAccountPath + "?memberId=" + f.member.ID
	f.status(f.call(browserClient(), "GET", path, nil, nil), 401)
	for _, query := range []url.Values{
		{"memberId": {f.otherMember.ID}},
		{"memberId": {f.member.ID}, "returnUri": {accountReturn}},
		{"memberId": {f.member.ID}, "client_id": {"example-web"}, "returnUri": {accountReturn + "/other"}},
		{"memberId": {f.member.ID}, "client_id": {"registration"}, "returnUri": {accountReturn}},
		{"memberId": {f.member.ID}, "client_id": {"second-web"}, "returnUri": {accountReturn}},
	} {
		result := f.call(f.browser, "GET", phoneAccountPath+"?"+query.Encode(), nil, nil)
		if result.status != 400 && result.status != 403 {
			t.Fatal("invalid account accepted", result.status)
		}
	}
	form := url.Values{"request": {hidden(t, page.body, "request")}, "csrf": {hidden(t, page.body, "csrf")}, "action": {"send"}, "phone": {linkPhoneNumber}}
	for _, origin := range []string{"", "https://other.example.test"} {
		f.status(f.call(f.browser, "POST", phoneAccountPath, form, map[string]string{"Origin": origin}), 403)
	}
	form.Set("csrf", "wrong")
	f.status(f.call(f.browser, "POST", phoneAccountPath, form, map[string]string{"Origin": f.server.URL}), 403)
	form.Set("csrf", hidden(t, page.body, "csrf"))
	copied := browserClient()
	issuer, _ := url.Parse(f.server.URL)
	for _, cookie := range f.browser.Jar.Cookies(issuer) {
		if cookie.Name == f.service.cookieName("session") {
			copied.Jar.SetCookies(issuer, []*http.Cookie{cookie})
		}
	}
	f.status(f.call(copied, "POST", phoneAccountPath, form, map[string]string{"Origin": f.server.URL}), 403)
	f.status(f.call(f.browser, "POST", accountPath, form, map[string]string{"Origin": f.server.URL}), 403)
	other := f.call(f.browser, "GET", accountPath+"?memberId="+f.member.ID, nil, nil)
	f.status(other, 200)
	f.status(phoneAccountSubmit(f, other, "send", url.Values{"phone": {linkPhoneNumber}}), 403)
	form.Set("memberId", f.otherMember.ID)
	f.status(f.call(f.browser, "POST", phoneAccountPath, form, map[string]string{"Origin": f.server.URL}), 403)
	assertPhoneNotLinked(t, f)
}

func TestPhoneAccountCancellationAttemptsAndConcurrentVerification(t *testing.T) {
	f, page := phoneAccountFixture(t)
	sent := sendAccountPhone(f, page)
	reopened := f.call(f.browser, "GET", phoneAccountPath+"?"+url.Values{"memberId": {f.member.ID}, "client_id": {"example-web"}, "returnUri": {accountReturn}}.Encode(), nil, nil)
	f.status(reopened, 200)
	if hidden(t, reopened.body, "request") != hidden(t, sent.body, "request") {
		t.Fatal("reopen replaced pending challenge")
	}
	code := f.sender.latest()
	wrong := "000000"
	if code == wrong {
		wrong = "111111"
	}
	for range 5 {
		f.status(phoneAccountSubmit(f, sent, "verify", url.Values{"code": {wrong}}), 200)
	}
	denied := phoneAccountSubmit(f, sent, "verify", url.Values{"code": {code}})
	f.status(denied, 200)
	assertPhoneNotLinked(t, f)
	canceled := phoneAccountSubmit(f, sent, "cancel", nil)
	f.status(canceled, 303)
	f.status(phoneAccountSubmit(f, sent, "verify", url.Values{"code": {code}}), 400)
	page = f.call(f.browser, "GET", canceled.header.Get("Location"), nil, nil)
	if hidden(t, page.body, "request") == hidden(t, sent.body, "request") {
		t.Fatal("cancel did not replace request")
	}
	if _, err := f.store.Database().Exec(t.Context(), "UPDATE phone_challenges SET created_at=created_at-interval '61 seconds'"); err != nil {
		t.Fatal(err)
	}
	sent = sendAccountPhone(f, page)
	code = f.sender.latest()
	var group sync.WaitGroup
	replies := make(chan reply, 2)
	for range 2 {
		group.Go(func() { replies <- phoneAccountSubmit(f, sent, "verify", url.Values{"code": {code}}) })
	}
	group.Wait()
	close(replies)
	successes := 0
	for result := range replies {
		if strings.Contains(result.body, "Phone is linked to this Member") {
			successes++
		}
	}
	if successes != 1 {
		t.Fatal("concurrent verification was not single-use", successes)
	}
	var completed int
	if err := f.store.Database().QueryRow(t.Context(), "SELECT count(*) FROM account_link_requests WHERE state='completed'").Scan(&completed); err != nil || completed != 1 {
		t.Fatal("wrong completed requests", err)
	}
}

func TestPhoneAccountRejectsEligibilityChanges(t *testing.T) {
	for _, change := range []string{"session revoked", "stale authentication", "member blocked", "departure", "source revoked", "source disabled", "organization disabled", "application revoked", "request canceled", "request expired", "return removed"} {
		t.Run(change, func(t *testing.T) {
			f, page := phoneAccountFixture(t)
			sent := sendAccountPhone(f, page)
			query := ""
			switch change {
			case "session revoked":
				query = "UPDATE oidc_sessions SET revoked_at=clock_timestamp()"
			case "stale authentication":
				query = "UPDATE oidc_sessions SET verification=jsonb_set(verification,'{authenticatedAt}',to_jsonb(clock_timestamp()-interval '6 minutes'))"
			case "member blocked":
				query = "UPDATE members SET manual_block=true"
			case "departure":
				query = "UPDATE members SET external_departure=true"
			case "source revoked":
				query = "UPDATE member_auth_factor_bindings SET status='revoked',revoked_at=clock_timestamp() WHERE factor_type='dingtalk'"
			case "source disabled":
				query = "UPDATE authentication_factors SET status='disabled' WHERE type='dingtalk'"
			case "organization disabled":
				query = "UPDATE organizations SET status='disabled'"
			case "application revoked":
				query = "UPDATE dingtalk_applications SET authorization_status='revoked'"
			case "request canceled":
				query = "UPDATE account_link_requests SET state='canceled'"
			case "request expired":
				query = "UPDATE account_link_requests SET expires_at=clock_timestamp()-interval '1 second'"
			case "return removed":
				f.service.configuration.Clients[0].AccountReturnURIs = nil
			}
			if query != "" {
				if _, err := f.store.Database().Exec(t.Context(), query); err != nil {
					t.Fatal(err)
				}
			}
			result := phoneAccountSubmit(f, sent, "verify", url.Values{"code": {f.sender.latest()}})
			if strings.Contains(result.body, "Phone is linked to this Member") {
				t.Fatal("accepted changed eligibility")
			}
			assertPhoneNotLinked(t, f)
		})
	}
}

func TestPhoneAccountDoesNotTransferOrRestoreBindings(t *testing.T) {
	for _, mode := range []string{"other member", "occupied slot", "revoked slot", "disabled factor"} {
		t.Run(mode, func(t *testing.T) {
			f, page := phoneAccountFixture(t)
			sent := sendAccountPhone(f, page)
			phone := linkPhoneNumber
			if mode == "occupied slot" || mode == "revoked slot" {
				phone = "19900000004"
			}
			factor, err := f.store.EnsureFactor(t.Context(), "phone", "phone:e164", "+86"+phone)
			if err != nil {
				t.Fatal(err)
			}
			member := f.member
			if mode == "other member" {
				member, err = f.store.CreateMember(t.Context(), f.member.OrganizationID, "", "Another Member")
				if err != nil {
					t.Fatal(err)
				}
			}
			if mode == "disabled factor" {
				_, err = f.store.Database().Exec(t.Context(), "UPDATE authentication_factors SET status='disabled' WHERE id=$1", factor.ID)
			} else {
				_, err = f.store.BindFactor(t.Context(), member.OrganizationID, member.ID, factor.ID)
			}
			if err != nil {
				t.Fatal(err)
			}
			if mode == "revoked slot" {
				if err := f.store.RevokeBinding(t.Context(), member.OrganizationID, member.ID, factor.ID); err != nil {
					t.Fatal(err)
				}
			}
			var before string
			if err := f.store.Database().QueryRow(t.Context(), "SELECT jsonb_agg(to_jsonb(b) ORDER BY id)::text FROM member_auth_factor_bindings b").Scan(&before); err != nil {
				t.Fatal(err)
			}
			result := phoneAccountSubmit(f, sent, "verify", url.Values{"code": {f.sender.latest()}})
			f.status(result, 200)
			if strings.Contains(result.body, "Phone is linked to this Member") {
				t.Fatal("conflicting factor linked")
			}
			var after string
			if err := f.store.Database().QueryRow(t.Context(), "SELECT jsonb_agg(to_jsonb(b) ORDER BY id)::text FROM member_auth_factor_bindings b").Scan(&after); err != nil || before != after {
				t.Fatal("binding transferred, restored, or replaced", err)
			}
		})
	}
}

func TestPhoneAccountAllowsIndependentOrganizations(t *testing.T) {
	f, page := phoneAccountFixture(t)
	other, err := f.store.CreateMember(t.Context(), f.otherMember.OrganizationID, "", "Separate Member")
	if err != nil {
		t.Fatal(err)
	}
	factor, err := f.store.EnsureFactor(t.Context(), "phone", "phone:e164", "+86"+linkPhoneNumber)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.store.BindFactor(t.Context(), other.OrganizationID, other.ID, factor.ID); err != nil {
		t.Fatal(err)
	}
	sent := sendAccountPhone(f, page)
	result := phoneAccountSubmit(f, sent, "verify", url.Values{"code": {f.sender.latest()}})
	f.status(result, 200)
	if !strings.Contains(result.body, "Phone is linked to this Member") {
		t.Fatal("independent organization blocked", result.body)
	}
	members, err := f.store.EligibleMembers(t.Context(), factor.ID)
	if err != nil || len(members) != 2 || members[0].ID == members[1].ID || members[0].OrganizationID == members[1].OrganizationID {
		t.Fatal("independent Members merged", err)
	}
}

type accountPhoneSender func(context.Context, string, string) error

func (sender accountPhoneSender) Send(ctx context.Context, phone, code string) error {
	return sender(ctx, phone, code)
}

func TestPhoneAccountDeliveryFailureAndCancellationCannotReviveChallenge(t *testing.T) {
	for _, cancel := range []bool{false, true} {
		name := "failed delivery"
		if cancel {
			name = "canceled during delivery"
		}
		t.Run(name, func(t *testing.T) {
			f, page := phoneAccountFixture(t)
			key, _ := base64.StdEncoding.DecodeString(f.service.configuration.Secrets.PhoneCodeKey)
			verifier, err := identity.NewPhoneVerifier(f.store, key, accountPhoneSender(func(ctx context.Context, phone, code string) error {
				if cancel {
					f.status(phoneAccountSubmit(f, page, "cancel", nil), 303)
					return f.sender.Send(ctx, phone, code)
				}
				return errors.New("synthetic provider diagnostic must remain private")
			}))
			if err != nil {
				t.Fatal(err)
			}
			f.service.phone = verifier
			result := phoneAccountSubmit(f, page, "send", url.Values{"phone": {linkPhoneNumber}})
			if cancel {
				f.status(result, 400)
			} else {
				f.status(result, 200)
				if !strings.Contains(result.body, "Unable to send") || strings.Contains(result.body, "synthetic provider diagnostic") {
					t.Fatal("delivery failure exposed or ignored")
				}
			}
			replay := phoneAccountSubmit(f, page, "verify", url.Values{"code": {f.sender.latest()}})
			f.status(replay, 400)
			assertPhoneNotLinked(t, f)
			var ready bool
			if err := f.store.Database().QueryRow(t.Context(), "SELECT ready FROM phone_challenges").Scan(&ready); err != nil || ready != cancel {
				t.Fatal("wrong delivery readiness", err)
			}
		})
	}
}
