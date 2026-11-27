package identity

import (
	"strings"
	"testing"
)

func TestMemberEmailMailboxProfile(t *testing.T) {
	for input, want := range map[string]string{"": "", "Example+tag@EXAMPLE.TEST": "Example+tag@example.test", "a.b@sub.example.test": "a.b@sub.example.test"} {
		got, err := normalizeMemberEmail(input)
		if err != nil || got != want {
			t.Fatalf("%q: got %q, %v", input, got, err)
		}
	}
	for _, input := range []string{" user@example.test", "user@example.test\n", "Name <user@example.test>", "user@example.test,other@example.test", "\"quoted\"@example.test", "a(comment)@example.test", "a@[127.0.0.1]", "a@localhost", "a@-example.test", "a@example..test", "a@example.test.", ".a@example.test", "a..b@example.test", "用户@example.test", "a@例子.test", strings.Repeat("a", 65) + "@example.test", strings.Repeat("a", 250) + "@example.test"} {
		if _, err := normalizeMemberEmail(input); err == nil {
			t.Errorf("accepted unsupported mailbox %q", input)
		}
	}
}

func TestSAMLAttributeAllowlist(t *testing.T) {
	organizationID, _ := NewID(OrganizationKind)
	sp := SAMLServiceProvider{ID: "email-sp", OrganizationID: organizationID, EntityID: "https://sp.example.test", ACSURL: "https://sp.example.test/acs", AllowUnsignedRequests: true}
	for _, attributes := range [][]string{nil, {"Email"}, {"DisplayName", "Email", "OrganizationID"}} {
		sp.Attributes = attributes
		if err := sp.Validate(false); err != nil {
			t.Fatal(attributes, err)
		}
	}
	for _, attributes := range [][]string{{"Email", "Email"}, {"email"}, {"EmailVerified"}, {"DisplayName", "Email", "phone"}} {
		sp.Attributes = attributes
		if err := sp.Validate(false); err == nil {
			t.Fatal("accepted unintended claims", attributes)
		}
	}
}
