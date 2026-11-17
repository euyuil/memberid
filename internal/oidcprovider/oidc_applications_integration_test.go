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
	if strings.Contains(page.body, `name="member" disabled`) {
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
