package identity

import (
	"errors"
	"testing"
)

func TestManagementServiceRejectsOtherEntryContexts(t *testing.T) {
	store := &Store{}
	service := NewManagementService(store, nil, nil)
	org, _ := NewID(OrganizationKind)
	member, _ := NewID(MemberKind)
	factor, _ := NewID(FactorKind)
	account := AccountPrincipal("session", member, factor, "00000000-0000-4000-8000-000000000001")
	for _, principal := range []Principal{{}, OperatorPrincipal(), InstallationManagerPrincipal(), account} {
		operations := []func() error{
			func() error { _, err := service.Organizations(t.Context(), principal, "", 50); return err },
			func() error { _, err := service.Member(t.Context(), principal, org, member); return err },
			func() error {
				_, err := service.Manage(t.Context(), principal, "member.update", org, member, ManagementChange{})
				return err
			},
			func() error { return service.SetAdministrator(t.Context(), principal, org, member, true) },
			func() error {
				_, err := service.ConfigureProvider(t.Context(), principal, org, "dingtalk", "", ProviderInput{})
				return err
			},
		}
		for index, operation := range operations {
			if err := operation(); !errors.Is(err, ErrForbidden) {
				t.Fatalf("entry context %d, operation %d: %v", principal.kind, index, err)
			}
		}
	}
	if err := store.SetAdministrator(t.Context(), ManagementPrincipal(member, "grant"), org, member, true); !errors.Is(err, ErrForbidden) {
		t.Fatal("Member acquired the operator-only assignment entry", err)
	}
}
