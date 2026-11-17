//go:build integration

package oidcprovider

import (
	"strings"
	"testing"

	"github.com/euyuil/memberid/internal/identity"
)

func TestConsoleLiveSAMLMetadata(t *testing.T) {
	f := newFixture(t)
	if err := f.store.SetAdministrator(t.Context(), identity.OperatorPrincipal(), f.member.OrganizationID, f.member.ID, true); err != nil {
		t.Fatal(err)
	}
	server := consoleFixture(t, f)
	consoleLogin(t, f, server, f.member.ID)
	path := "/api/organizations/" + f.member.OrganizationID + "/saml-identity-provider"
	unavailable := consoleJSON(t, f, server, "GET", path, "", "", 200)
	if unavailable["status"] != "unavailable" || unavailable["certificate"] != nil {
		t.Fatal(unavailable)
	}
	enableSAML(t, f)
	// The console was initialized before SAML was enabled: inspect the live issuer,
	// not the console process's startup snapshot or signing-key configuration.
	result := consoleJSON(t, f, server, "GET", path, "", "", 200)
	certificate, ok := result["certificate"].(map[string]any)
	if result["status"] != "available" || !ok || !strings.HasPrefix(certificate["pem"].(string), "-----BEGIN CERTIFICATE-----") || result["entityId"] != f.server.URL+"/saml/metadata" {
		t.Fatal(result)
	}
	consoleJSON(t, f, server, "GET", "/api/organizations/"+f.otherMember.OrganizationID+"/saml-identity-provider", "", "", 403)
}
