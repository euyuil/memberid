package identity

import (
	"encoding/json"
	"errors"
	"testing"
)

func TestUntrustedPrincipalsCannotUseInstallationMutations(t *testing.T) {
	memberID, err := NewID(MemberKind)
	if err != nil {
		t.Fatal(err)
	}
	var decoded Principal
	if err := json.Unmarshal([]byte(`{"kind":"operator","memberId":"","platform":true}`), &decoded); err != nil {
		t.Fatal(err)
	}
	principals := map[string]Principal{
		"empty": {}, "HTTP fields": decoded,
		"Member": (ManagementActor{MemberID: memberID, GrantID: "synthetic-grant", Platform: true}).Principal(),
	}
	// No database is needed: installation-only entry points must reject these
	// identities before performing any persistence or provider work.
	store := &Store{}
	for name, principal := range principals {
		t.Run(name, func(t *testing.T) {
			operations := map[string]func() error{
				"create organization": func() error { _, err := store.CreateOrganization(t.Context(), principal, "", "Example"); return err },
				"create member": func() error {
					_, err := store.CreateMember(t.Context(), principal, SystemOrganizationID, "", "Example")
					return err
				},
				"update organization": func() error {
					_, err := store.UpdateOrganization(t.Context(), principal, SystemOrganizationID, OrganizationChange{})
					return err
				},
				"update member": func() error {
					_, err := store.UpdateMember(t.Context(), principal, SystemOrganizationID, memberID, MemberChange{})
					return err
				},
				"update receipt": func() error {
					_, _, err := store.UpdateMemberOnce(t.Context(), principal, SystemOrganizationID, memberID, "", MemberChange{})
					return err
				},
				"bind": func() error {
					_, err := store.BindFactor(t.Context(), principal, SystemOrganizationID, memberID, "")
					return err
				},
				"revoke binding": func() error { return store.RevokeBinding(t.Context(), principal, SystemOrganizationID, memberID, "") },
				"enroll": func() error {
					_, err := store.EnrollOrganization(t.Context(), principal, OrganizationEnrollment{})
					return err
				},
				"provider credentials": func() error {
					_, err := (&DingTalkApplications{}).Configure(t.Context(), principal, SystemOrganizationID, DingTalkApplicationInput{})
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
	if err := authorizeManagement(t.Context(), nil, Principal{}, SystemOrganizationID, false); !errors.Is(err, ErrForbidden) {
		t.Fatal("empty principal acquired authority", err)
	}
	if err := authorizeManagement(t.Context(), nil, InstallationManagerPrincipal(), SystemOrganizationID, false); !errors.Is(err, ErrForbidden) {
		t.Fatal("installation manager acquired a Member/CLI administrator entry point", err)
	}
	if _, err := (Principal{}).auditID(); !errors.Is(err, ErrForbidden) {
		t.Fatal("empty principal received an audit identity", err)
	}
}
