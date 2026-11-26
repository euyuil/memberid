//go:build integration

package oidcprovider

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/euyuil/memberid/internal/config"
	"github.com/euyuil/memberid/internal/identity"
)

func TestManageOIDCApplicationWithoutRestart(t *testing.T) {
	f := newFixture(t)
	ctx := t.Context()
	operator := identity.OperatorPrincipal()
	admin, err := f.store.CreateMember(ctx, operator, identity.SystemOrganizationID, "", "Platform operator")
	if err != nil {
		t.Fatal(err)
	}
	factor, err := f.store.EnsureFactor(ctx, "phone", "phone:e164", "+8619900000001")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.store.BindFactor(ctx, operator, admin.OrganizationID, admin.ID, factor.ID); err != nil {
		t.Fatal(err)
	}
	if err := f.store.SetAdministrator(ctx, operator, admin.OrganizationID, admin.ID, true); err != nil {
		t.Fatal(err)
	}
	server := consoleFixture(t, f)
	consoleLoginTo(t, f, server, admin.ID, "/oidc-applications")
	csrf := consoleJSON(t, f, server, "GET", "/api/session", "", "", 200)["csrf"].(string)
	const base = "/api/oidc-applications"
	consoleJSON(t, f, server, "PATCH", base+"/console", csrf, `{"expectedRevision":1,"enabled":false}`, 403)
	consoleJSON(t, f, server, "POST", base+"/console/rotate-secret", csrf, `{"expectedRevision":1}`, 403)
	payload := fmt.Sprintf(`{"clientId":"managed","displayName":"Managed application","organizationId":%q,"redirectUris":[%q],"refresh":true}`, f.member.OrganizationID, callback)
	consoleJSON(t, f, server, "POST", base, "bad-csrf", payload, 403)
	created := consoleJSON(t, f, server, "POST", base, csrf, payload, 200)
	firstSecret := created["clientSecret"].(string)
	list, err := json.Marshal(consoleJSON(t, f, server, "GET", base, "", "", 200))
	if err != nil || !strings.Contains(string(list), `"clientId":"managed"`) || strings.Contains(string(list), firstSecret) || strings.Contains(string(list), config.SecretHash(firstSecret)) {
		t.Fatal("registered application missing or credential exposed", err)
	}
	discovery := f.call(f.browser, "GET", "/.well-known/openid-configuration", nil, nil)
	f.status(discovery, 200)
	if !strings.Contains(discovery.body, "refresh_token") {
		t.Fatal("discovery did not advertise dynamically enabled renewal")
	}

	// Resolve a newly registered client from an authentication process that was
	// already serving before it was registered. Keep the independent console grant.
	f.secret = firstSecret
	page, verifier := f.loginPage("managed", "openid profile offline_access")
	if strings.Contains(page.body, `id="phone"`) {
		page = f.verifyPhone(page)
	}
	code := f.complete(page, f.member.ID)
	tokens := f.exchange("managed", code, verifier)
	f.status(tokens, 200)
	result := jsonObject(t, tokens)
	accessToken, refreshToken := result["access_token"].(string), result["refresh_token"].(string)

	rotated := consoleJSON(t, f, server, "POST", base+"/managed/rotate-secret", csrf, `{"expectedRevision":1}`, 200)
	nextSecret := rotated["clientSecret"].(string)
	if nextSecret == firstSecret {
		t.Fatal("rotation reused the credential")
	}
	f.status(f.refresh("managed", refreshToken, ""), 401)
	f.secret = nextSecret
	refreshed := f.refresh("managed", refreshToken, "")
	f.status(refreshed, 200)
	refreshToken = jsonObject(t, refreshed)["refresh_token"].(string)
	consoleJSON(t, f, server, "PATCH", base+"/managed", csrf, `{"expectedRevision":1,"enabled":false}`, 409)
	consoleJSON(t, f, server, "PATCH", base+"/managed", csrf, `{"expectedRevision":2,"enabled":false}`, 200)
	f.status(f.userinfo(accessToken), 401)
	f.status(f.refresh("managed", refreshToken, ""), 401)
	consoleJSON(t, f, server, "PATCH", base+"/managed", csrf, `{"expectedRevision":3,"enabled":true}`, 200)
	f.invalidRefresh("managed", refreshToken)

	events, err := json.Marshal(consoleJSON(t, f, server, "GET", "/api/events", "", "", 200))
	if err != nil || !strings.Contains(string(events), "oidc.application.credential.rotate") ||
		strings.Contains(string(events), firstSecret) || strings.Contains(string(events), config.SecretHash(nextSecret)) {
		t.Fatal("audit entry missing or credential exposed", err)
	}
}

func TestOIDCApplicationPolicyManagement(t *testing.T) {
	f := newFixture(t)
	ctx := t.Context()
	operator := identity.OperatorPrincipal()
	admin, err := f.store.CreateMember(ctx, operator, identity.SystemOrganizationID, "", "Policy administrator")
	if err != nil {
		t.Fatal(err)
	}
	factor, err := f.store.EnsureFactor(ctx, "phone", "phone:e164", "+8619900000001")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = f.store.BindFactor(ctx, operator, admin.OrganizationID, admin.ID, factor.ID); err != nil {
		t.Fatal(err)
	}
	if err = f.store.SetAdministrator(ctx, operator, admin.OrganizationID, admin.ID, true); err != nil {
		t.Fatal(err)
	}
	server := consoleFixture(t, f)
	consoleLogin(t, f, server, admin.ID)
	csrf := consoleJSON(t, f, server, "GET", "/api/session", "", "", 200)["csrf"].(string)
	const base = "/api/oidc-applications"
	const scope = "member:evidence"
	const audience = "https://api.example.test"
	payload := fmt.Sprintf(`{"clientId":"policy","displayName":"Policy application","redirectUris":[%q],"accountReturnUris":["https://app.example.invalid/account"],"preauthorized":true,"refresh":true,"evidenceScope":%q,"evidenceAudience":%q}`, callback, scope, audience)
	consoleJSON(t, f, server, "POST", base, csrf, strings.Replace(payload, audience, "", 1), 400)
	created := consoleJSON(t, f, server, "POST", base, csrf, payload, 200)
	application := created["application"].(map[string]any)
	if application["preauthorized"] != true || application["subjectKind"] != "member" || len(application["accountReturnUris"].([]any)) != 1 || application["evidenceScope"] != scope || application["evidenceAudience"] != audience {
		t.Fatal("policy missing", application)
	}
	f.secret = created["clientSecret"].(string)
	page, verifier := f.loginPage("policy", "openid offline_access "+scope)
	if strings.Contains(page.body, `id="phone"`) {
		page = f.verifyPhone(page)
	}
	if !strings.Contains(page.body, `name="consent" type="checkbox" value="yes" checked`) {
		t.Fatal("live policy did not skip consent")
	}
	token := f.exchange("policy", f.complete(page, f.member.ID), verifier)
	f.status(token, 200)
	tokens := jsonObject(t, token)
	checkEvidence := func(access any, wantAudience string) {
		t.Helper()
		claims := f.signedClaims(access.(string))
		aud, _ := claims["aud"].([]any)
		authn, _ := claims["authentication"].(map[string]any)
		if len(aud) != 1 || aud[0] != wantAudience || claims["organizationId"] != f.member.OrganizationID || claims["memberId"] != f.member.ID ||
			claims["bindingId"] == nil || authn["factorType"] != "phone" || authn["factorId"] == nil {
			t.Fatal("unexpected evidence token claims")
		}
	}
	checkEvidence(tokens["access_token"], audience)
	page, verifier = f.loginPage("policy", "openid offline_access")
	ordinary := f.exchange("policy", f.complete(page, f.member.ID), verifier)
	f.status(ordinary, 200)
	ordinaryTokens := jsonObject(t, ordinary)
	if f.signedClaims(ordinaryTokens["access_token"].(string))["authentication"] != nil {
		t.Fatal("ordinary scope released authentication evidence")
	}
	update := map[string]any{"expectedRevision": 1, "displayName": "Updated policy", "redirectUris": []string{callback}, "refresh": true}
	send := func(status int) map[string]any {
		t.Helper()
		b, _ := json.Marshal(update)
		return consoleJSON(t, f, server, "PATCH", base+"/policy", csrf, string(b), status)
	}
	send(200) // Older callers do not erase policy fields they did not send.
	stored, err := f.store.OIDCClient(ctx, "policy")
	if err != nil || !stored.Client.Preauthorized || len(stored.Client.AccountReturnURIs) != 1 || stored.Client.EvidenceScope != scope || stored.Client.EvidenceAudience != audience {
		t.Fatal("omitted policy was lost", err)
	}
	update["expectedRevision"] = 2
	update["accountReturnUris"] = []string{"https://app.example.invalid/*"}
	update["preauthorized"] = false
	send(400)
	stored, _ = f.store.OIDCClient(ctx, "policy")
	if stored.Revision != 2 || !stored.Client.Preauthorized {
		t.Fatal("invalid update changed policy")
	}
	update["accountReturnUris"] = []string{}
	update["evidenceScope"] = scope
	send(400) // Both policy fields must be supplied on edit.
	update["evidenceScope"], update["evidenceAudience"] = "profile", audience
	send(400)
	update["evidenceScope"] = scope
	update["evidenceAudience"] = audience + "?tenant=example"
	send(400)
	const newAudience = "https://reports.example.test"
	update["evidenceAudience"] = newAudience
	send(200)
	send(409)
	stored, _ = f.store.OIDCClient(ctx, "policy")
	if stored.Client.Preauthorized || len(stored.Client.AccountReturnURIs) != 0 {
		t.Fatal("explicit policy removal ignored")
	}
	f.invalidRefresh("policy", tokens["refresh_token"].(string))
	f.status(f.refresh("policy", ordinaryTokens["refresh_token"].(string), ""), 200)
	page, verifier = f.loginPage("policy", "openid offline_access "+scope)
	if !strings.Contains(page.body, `name="consent" type="checkbox" value="yes" required`) {
		t.Fatal("live policy did not restore consent")
	}
	token = f.exchange("policy", f.complete(page, f.member.ID), verifier)
	f.status(token, 200)
	updatedTokens := jsonObject(t, token)
	checkEvidence(updatedTokens["access_token"], newAudience)
	update["expectedRevision"], update["evidenceScope"], update["evidenceAudience"] = 3, "", ""
	send(200)
	stored, err = f.store.OIDCClient(ctx, "policy")
	if err != nil || stored.Client.EvidenceScope != "" || stored.Client.EvidenceAudience != "" {
		t.Fatal("explicit evidence removal was not persisted", err)
	}
	update["expectedRevision"], update["evidenceScope"], update["evidenceAudience"] = 4, scope, newAudience
	send(200)
	// Restoring the policy must not reactivate a grant revoked by its removal.
	f.invalidRefresh("policy", updatedTokens["refresh_token"].(string))
	events, _ := json.Marshal(consoleJSON(t, f, server, "GET", "/api/events", "", "", 200))
	if !strings.Contains(string(events), newAudience) || !strings.Contains(string(events), scope) {
		t.Fatal("evidence policy missing from management history")
	}
	consoleJSON(t, f, server, "PATCH", base+"/policy", csrf, `{"expectedRevision":5,"enabled":false,"evidenceScope":"","evidenceAudience":""}`, 400)
	patch := fmt.Sprintf(`{"expectedRevision":1,"displayName":"Example","redirectUris":[%q],"evidenceScope":%q,"evidenceAudience":%q}`, callback, scope, audience)
	consoleJSON(t, f, server, "PATCH", base+"/console", csrf, patch, 403)
	consoleJSON(t, f, server, "PATCH", base+"/registration", csrf, patch, 403)
	consoleJSON(t, f, server, "PATCH", base+"/policy", csrf, `{"expectedRevision":3,"enabled":false,"preauthorized":true}`, 400)
	consoleJSON(t, f, server, "PATCH", base+"/console", csrf, `{"expectedRevision":1,"displayName":"Console","redirectUris":["https://app.example.invalid/callback"],"preauthorized":false}`, 403)
	// Organization administrators cannot configure installation-wide applications.
	if err = f.store.SetAdministrator(ctx, operator, f.member.OrganizationID, f.member.ID, true); err != nil {
		t.Fatal(err)
	}
	consoleLogin(t, f, server, f.member.ID)
	csrf = consoleJSON(t, f, server, "GET", "/api/session", "", "", 200)["csrf"].(string)
	consoleJSON(t, f, server, "GET", base, "", "", 403)
	consoleJSON(t, f, server, "POST", base, csrf, payload, 403)
	update["expectedRevision"] = 5
	send(403)
}
