//go:build integration

package oidcprovider

import (
	"strings"
	"testing"

	"github.com/euyuil/memberid/internal/identity"
)

func TestConsoleProviderCredentialCheck(t *testing.T) {
	f := newFixture(t)
	if err := f.store.SetAdministrator(t.Context(), identity.OperatorPrincipal(), f.member.OrganizationID, f.member.ID, true); err != nil {
		t.Fatal(err)
	}
	server := consoleFixture(t, f)
	consoleLogin(t, f, server, f.member.ID)
	csrf := consoleJSON(t, f, server, "GET", "/api/session", "", "", 200)["csrf"].(string)
	base := "/api/organizations/" + f.member.OrganizationID + "/providers"
	directory := consoleJSON(t, f, server, "GET", base, "", "", 200)
	if !strings.HasSuffix(directory["feishuLinkCallback"].(string), "/account/feishu/callback") || !strings.HasSuffix(directory["dingTalkLinkCallback"].(string), "/account/dingtalk/callback") {
		t.Fatal(directory)
	}
	app := consoleJSON(t, f, server, "POST", base+"/feishu", csrf, `{"displayName":"Example check","tenantId":"example-tenant","clientId":"cli_example","clientSecret":"synthetic-provider-secret","enabled":false}`, 200)
	path := base + "/feishu/" + app["id"].(string) + "/check"
	consoleJSON(t, f, server, "POST", path, "", "", 403)
	result := consoleJSON(t, f, server, "POST", path, csrf, "", 200)
	if result["status"] != "accepted" || result["revision"] != app["revision"] || len(result) != 3 {
		t.Fatal(result)
	}
	consoleJSON(t, f, server, "POST", "/api/organizations/"+f.otherMember.OrganizationID+"/providers/feishu/"+app["id"].(string)+"/check", csrf, "", 403)
}
