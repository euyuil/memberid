//go:build integration

package oidcprovider

import (
	"net/url"
	"testing"

	"github.com/crewjam/saml"
	"github.com/euyuil/memberid/internal/identity"
)

func assertSAMLEmail(t *testing.T, response saml.Response, expected string) {
	t.Helper()
	if response.Assertion == nil {
		t.Fatal("missing success assertion")
	}
	count := 0
	for _, statement := range response.Assertion.AttributeStatements {
		for _, attribute := range statement.Attributes {
			if attribute.Name == "Email" {
				count++
				if attribute.NameFormat != "urn:oasis:names:tc:SAML:2.0:attrname-format:basic" || len(attribute.Values) != 1 || attribute.Values[0].Value != expected {
					t.Fatal("incorrect managed email attribute")
				}
			}
			if attribute.Name == "EmailVerified" || attribute.Name == "email_verified" {
				t.Fatal("invented mailbox verification")
			}
		}
	}
	if expected == "" && count != 0 || expected != "" && count != 1 {
		t.Fatal("incorrect email release count", count)
	}
}

func TestSAMLManagedEmailReleaseAndCurrentValue(t *testing.T) {
	f := newFixture(t)
	sp := enableSAML(t, f)
	setEmail := func(address string, revision int64) {
		t.Helper()
		if _, err := f.store.PutMemberEmail(t.Context(), identity.OperatorPrincipal(), f.member.OrganizationID, f.member.ID, identity.MemberEmailInput{Address: address, Revision: revision}); err != nil {
			t.Fatal(err)
		}
	}
	setEmail("first@example.test", 0)
	page := f.verifyPhone(samlPage(t, f, sp))
	complete := func(page reply, expected string) saml.Response {
		t.Helper()
		response := verifySAMLResponse(t, f, sp, f.submit(page.body, "continue", url.Values{"member": {f.member.ID}, "consent": {"yes"}}))
		assertSAMLEmail(t, response, expected)
		return response
	}
	first := complete(page, "")
	sp.Attributes = []string{"DisplayName", "Email"}
	var err error
	sp, err = f.store.PutSAMLServiceProvider(t.Context(), identity.OperatorPrincipal(), sp, false)
	if err != nil {
		t.Fatal(err)
	}
	page = samlPage(t, f, sp)
	setEmail("changed@example.test", 1)
	second := complete(page, "changed@example.test")
	if second.Assertion.Subject.NameID.Value != first.Assertion.Subject.NameID.Value {
		t.Fatal("email changed NameID")
	}
	page = samlPage(t, f, sp)
	setEmail("", 2)
	complete(page, "")
	// Equal emails across independent organizations never identify one Member.
	setEmail("shared@example.test", 3)
	if _, err := f.store.PutMemberEmail(t.Context(), identity.OperatorPrincipal(), f.otherMember.OrganizationID, f.otherMember.ID, identity.MemberEmailInput{Address: "shared@example.test"}); err != nil {
		t.Fatal(err)
	}
	other := sp
	other.ID, other.EntityID, other.OrganizationID, other.Revision = "", "https://other.example.test/metadata", f.otherMember.OrganizationID, 0
	other, err = f.store.PutSAMLServiceProvider(t.Context(), identity.OperatorPrincipal(), other, false)
	if err != nil {
		t.Fatal(err)
	}
	page = samlPage(t, f, other)
	response := verifySAMLResponse(t, f, other, f.submit(page.body, "continue", url.Values{"member": {f.otherMember.ID}, "consent": {"yes"}}))
	assertSAMLEmail(t, response, "shared@example.test")
	if response.Assertion.Subject.NameID.Value == first.Assertion.Subject.NameID.Value {
		t.Fatal("email merged organization identities")
	}
}

func TestMemberEmailConsoleAuthority(t *testing.T) {
	f := newFixture(t)
	if err := f.store.SetAdministrator(t.Context(), identity.OperatorPrincipal(), f.member.OrganizationID, f.member.ID, true); err != nil {
		t.Fatal(err)
	}
	server := consoleFixture(t, f)
	consoleLoginTo(t, f, server, f.member.ID, "/organizations/"+f.member.OrganizationID+"/members/"+f.member.ID)
	csrf := consoleJSON(t, f, server, "GET", "/api/session", "", "", 200)["csrf"].(string)
	base := "/api/organizations/" + f.member.OrganizationID + "/members/" + f.member.ID
	body := `{"address":"managed@example.test","revision":0}`
	consoleJSON(t, f, server, "PUT", base+"/email", "wrong", body, 403)
	consoleJSON(t, f, server, "PUT", "/api/organizations/"+f.otherMember.OrganizationID+"/members/"+f.otherMember.ID+"/email", csrf, body, 403)
	consoleJSON(t, f, server, "PATCH", base, csrf, `{"email":"forged@example.test"}`, 400)
	consoleJSON(t, f, server, "PUT", base+"/email", csrf, `{"address":"managed@example.test","revision":0,"mailboxVerified":true}`, 400)
	value := consoleJSON(t, f, server, "PUT", base+"/email", csrf, body, 200)
	if value["updatedBy"] != f.member.ID || value["mailboxVerified"] != false {
		t.Fatal("console email provenance", value)
	}
	detail := consoleJSON(t, f, server, "GET", base, "", "", 200)
	if detail["email"].(map[string]any)["address"] != "managed@example.test" {
		t.Fatal("missing email detail")
	}
	consoleJSON(t, f, server, "PUT", base+"/email", csrf, body, 409)
	if _, err := f.store.Database().Exec(t.Context(), "DELETE FROM administrators WHERE member_id=$1", f.member.ID); err != nil {
		t.Fatal(err)
	}
	consoleJSON(t, f, server, "PUT", base+"/email", csrf, `{"address":"revoked@example.test","revision":1}`, 401)
}
