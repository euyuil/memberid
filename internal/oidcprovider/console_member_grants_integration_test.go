//go:build integration

package oidcprovider

import (
	"encoding/json"
	"net/url"
	"strings"
	"testing"

	"github.com/zhizhun-tech/memberid/internal/identity"
)

func TestConsoleMemberGrantsAreScopedMetadata(t *testing.T) {
	f := newConfiguredFixture(t, true)
	tokens := f.refreshTokens()
	for _, tc := range []struct{ client, scopes, member string }{{"example-web", "openid profile", f.member.ID}, {"second-web", "openid", f.otherMember.ID}, {"registration", "openid registration_identity", ""}} {
		page, verifier := f.loginPage(tc.client, tc.scopes)
		code := f.complete(page, tc.member)
		f.status(f.exchange(tc.client, code, verifier), 200)
	}
	if err := f.store.SetAdministrator(t.Context(), identity.OperatorPrincipal(), f.member.OrganizationID, f.member.ID, true); err != nil {
		t.Fatal(err)
	}
	server := consoleFixture(t, f)
	consoleLogin(t, f, server, f.member.ID)
	base := "/api/organizations/" + f.member.OrganizationID + "/members/" + f.member.ID + "/grants"
	result := consoleJSON(t, f, server, "GET", base, "", "", 200)
	items := result["items"].([]any)
	if len(items) != 3 {
		t.Fatal("foreign or factor grants entered member view", items)
	}
	appIDs := []string{}
	for _, raw := range items {
		item := raw.(map[string]any)
		if len(item) != 7 || item["state"] != "active" || item["authenticatedAt"] == nil || item["expiresAt"] == nil {
			t.Fatal(item)
		}
		if item["clientId"] == "example-web" {
			appIDs = append(appIDs, item["id"].(string))
		} else if item["clientId"] != f.consoleID {
			t.Fatal(item)
		}
	}
	encoded, _ := json.Marshal(result)
	for _, forbidden := range []string{tokens["access_token"].(string), tokens["refresh_token"].(string), "sessionId", "factorId", "authenticationFactorId", "secretHash", "secret_hash"} {
		if strings.Contains(string(encoded), forbidden) {
			t.Fatal("private grant data exposed")
		}
	}
	first := consoleJSON(t, f, server, "GET", base+"?limit=1", "", "", 200)
	after := first["nextAfter"].(string)
	if len(first["items"].([]any)) != 1 || after == "" {
		t.Fatal(first)
	}
	remaining := consoleJSON(t, f, server, "GET", base+"?limit=100&after="+url.QueryEscape(after), "", "", 200)
	if len(remaining["items"].([]any)) != 2 || remaining["nextAfter"] != nil {
		t.Fatal(remaining)
	}
	consoleJSON(t, f, server, "GET", base+"?limit=101", "", "", 400)
	consoleJSON(t, f, server, "GET", "/api/organizations/"+f.otherMember.OrganizationID+"/members/"+f.otherMember.ID+"/grants", "", "", 403)
	consoleJSON(t, f, server, "GET", "/api/organizations/"+f.member.OrganizationID+"/members/"+f.otherMember.ID+"/grants", "", "", 404)
	empty, err := f.store.CreateMember(t.Context(), identity.OperatorPrincipal(), f.member.OrganizationID, "", "No grants")
	if err != nil {
		t.Fatal(err)
	}
	none := consoleJSON(t, f, server, "GET", "/api/organizations/"+empty.OrganizationID+"/members/"+empty.ID+"/grants", "", "", 200)
	if len(none["items"].([]any)) != 0 {
		t.Fatal(none)
	}
	if _, err := f.store.Database().Exec(t.Context(), `UPDATE oidc_grants SET revoked_at=clock_timestamp() WHERE id=$1`, appIDs[0]); err != nil {
		t.Fatal(err)
	}
	if _, err := f.store.Database().Exec(t.Context(), `UPDATE oidc_grants SET expires_at=clock_timestamp()-interval '1 second' WHERE id=$1`, appIDs[1]); err != nil {
		t.Fatal(err)
	}
	result = consoleJSON(t, f, server, "GET", base, "", "", 200)
	for _, raw := range result["items"].([]any) {
		item := raw.(map[string]any)
		if item["id"] == appIDs[0] && item["state"] != "revoked" || item["id"] == appIDs[1] && item["state"] != "expired" {
			t.Fatal(item)
		}
	}
	// An operator grant-inspection principal cannot enter the Member console boundary.
	if _, err := identity.NewManagementService(f.store, nil, nil, 0).MemberGrants(t.Context(), identity.OperatorPrincipal(), f.member.OrganizationID, f.member.ID, "", 50); err != identity.ErrForbidden {
		t.Fatal(err)
	}
}
