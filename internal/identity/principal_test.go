package identity

import (
	"encoding/json"
	"errors"
	"testing"

	"github.com/zhizhun-tech/memberid/internal/authorization"
)

func TestUntrustedPrincipalsCannotUseInstallationMutations(t *testing.T) {
	org, _ := NewID(OrganizationKind)
	memberID, err := NewID(MemberKind)
	if err != nil {
		t.Fatal(err)
	}
	factorID, err := NewID(FactorKind)
	if err != nil {
		t.Fatal(err)
	}
	var decoded Principal
	if err := json.Unmarshal([]byte(`{"kind":"operator","memberId":"","platform":true}`), &decoded); err != nil {
		t.Fatal(err)
	}
	principals := map[string]Principal{
		"empty": {}, "HTTP fields": decoded,
		"Account Member":     AccountPrincipal("synthetic-session", memberID, factorID, "00000000-0000-4000-8000-000000000001"),
		"Member":             (ManagementActor{MemberID: memberID, GrantID: "synthetic-grant", Platform: true}).Principal(),
		"Console references": ManagementPrincipal(memberID, "synthetic-grant"),
	}
	// No database is needed: installation-only entry points must reject these
	// identities before performing any persistence or provider work.
	store := &Store{}
	for name, principal := range principals {
		t.Run(name, func(t *testing.T) {
			operations := map[string]func() error{
				"create organization": func() error { _, err := store.CreateOrganization(t.Context(), principal, "", "Example"); return err },
				"create member": func() error {
					_, err := store.CreateMember(t.Context(), principal, org, "", "Example")
					return err
				},
				"update organization": func() error {
					_, err := store.UpdateOrganization(t.Context(), principal, org, OrganizationChange{})
					return err
				},
				"update member": func() error {
					_, err := store.UpdateMember(t.Context(), principal, org, memberID, MemberChange{})
					return err
				},
				"update receipt": func() error {
					_, _, err := store.UpdateMemberOnce(t.Context(), principal, org, memberID, "", MemberChange{})
					return err
				},
				"bind": func() error {
					_, err := store.BindFactor(t.Context(), principal, org, memberID, "")
					return err
				},
				"revoke binding": func() error { return store.RevokeBinding(t.Context(), principal, org, memberID, "") },
				"enroll": func() error {
					_, err := store.EnrollOrganization(t.Context(), principal, OrganizationEnrollment{})
					return err
				},
				"provider credentials": func() error {
					_, err := (&DingTalkApplications{}).Configure(t.Context(), principal, org, DingTalkApplicationInput{})
					return err
				},
				"system admission": func() error { return store.PrepareSystemDingTalkAdmission(t.Context(), principal, memberID, "") },
			}
			for operation, run := range operations {
				if err := run(); !errors.Is(err, ErrForbidden) {
					t.Errorf("%s: %v", operation, err)
				}
			}
		})
	}
}

func TestEmptyPrincipalCannotAcquireManagementAuthority(t *testing.T) {
	org, _ := NewID(OrganizationKind)
	if err := authorizeAll(t.Context(), nil, Principal{}, authorization.Requirement{Target: "organizations/" + org, Action: "get"}); !errors.Is(err, ErrForbidden) {
		t.Fatal("empty principal acquired authority", err)
	}
	if _, err := (Principal{}).auditID(); !errors.Is(err, ErrForbidden) {
		t.Fatal("empty principal received an audit identity", err)
	}
}
