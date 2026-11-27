//go:build integration

package identity

import (
	"errors"
	"testing"

	"github.com/jackc/pgx/v5"
)

func TestPasswordUsernameCaseSharesReservationAndAttemptLimit(t *testing.T) {
	store := testStore(t)
	ctx := t.Context()
	op := OperatorPrincipal()
	org, first := organizationAndMember(t, store)
	second, err := store.CreateMember(ctx, op, org.ID, "", "Second member")
	if err != nil {
		t.Fatal(err)
	}
	results := make(chan error, 2)
	for id, name := range map[string]string{first.ID: "Casey", second.ID: "CASEY"} {
		go func() {
			_, err := store.SetMemberPassword(ctx, op, org.ID, id, name)
			results <- err
		}()
	}
	a, b := <-results, <-results
	if !(a == nil && errors.Is(b, ErrConflict) || b == nil && errors.Is(a, ErrConflict)) {
		t.Fatalf("concurrent case variants returned %v, %v", a, b)
	}
	for i := 0; i < 10; i++ {
		if err := store.VerifyPasswordAndApply(ctx, org.ID, "casey", "incorrect", nil); !errors.Is(err, ErrPasswordCredential) {
			t.Fatalf("attempt %d: %v", i+1, err)
		}
	}
	if err := store.VerifyPasswordAndApply(ctx, org.ID, "CaSeY", "incorrect", nil); !errors.Is(err, ErrRateLimited) {
		t.Fatalf("mixed-case attempt after limit: %v", err)
	}
}

func TestAdminMemberLoginNameLifecycle(t *testing.T) {
	s := testStore(t)
	ctx := t.Context()
	org, first := organizationAndMember(t, s)
	admin, factor := administratorMember(t, s, org.ID, 8)
	actor := administratorActor(t, s, admin, factor).Principal()
	platformMember, platformFactor := administratorMember(t, s, s.SystemOrganizationID(), 9)
	platform := administratorActor(t, s, platformMember, platformFactor).Principal()
	service := NewManagementService(s, nil, nil, 0)
	set := func(id, old, name string) error {
		return service.ChangeMemberLoginName(ctx, actor, org.ID, id, old, name)
	}
	results := make(chan error, 2)
	for _, name := range []string{"Casey", "CASEY"} {
		go func() { results <- set(first.ID, "", name) }()
	}
	a, b := <-results, <-results
	if !(a == nil && errors.Is(b, ErrConflict) || b == nil && errors.Is(a, ErrConflict)) {
		t.Fatal("first assignment race", a, b)
	}
	if enabled, err := s.HasPasswordCredentials(ctx, org.ID); err != nil || enabled {
		t.Fatal("name alone enabled password entry", err)
	}
	if err := s.SetAdministrator(ctx, OperatorPrincipal(), org.ID, first.ID, true); !errors.Is(err, ErrIneligible) {
		t.Fatal("name-only member was eligible for promotion", err)
	}
	name := "casey"
	if _, err := service.GenerateMemberPassword(ctx, actor, org.ID, first.ID, &name); !errors.Is(err, ErrForbidden) {
		t.Fatal("local administrator issued a password", err)
	}
	wrong := "another"
	if _, err := service.GenerateMemberPassword(ctx, platform, org.ID, first.ID, &wrong); !errors.Is(err, ErrConflict) {
		t.Fatal("provisioning replaced a name", err)
	}
	initial, err := service.GenerateMemberPassword(ctx, platform, org.ID, first.ID, &name)
	if err != nil {
		t.Fatal(err)
	}
	results = make(chan error, 2)
	for _, next := range []string{"north", "south"} {
		go func() { results <- set(first.ID, "casey", next) }()
	}
	a, b = <-results, <-results
	if !(a == nil && errors.Is(b, ErrConflict) || b == nil && errors.Is(a, ErrConflict)) {
		t.Fatal("rename race", a, b)
	}
	detail, err := service.Member(ctx, actor, org.ID, first.ID)
	if err != nil {
		t.Fatal(err)
	}
	if err := set(admin.ID, "", "casey"); err != nil {
		t.Fatal(err)
	}
	if err := set(first.ID, detail.LoginUsername, "casey"); !errors.Is(err, ErrPasswordUsernameTaken) {
		t.Fatal("occupied name", err)
	}
	newPassword, err := s.SetMemberPassword(ctx, OperatorPrincipal(), org.ID, admin.ID, "CASEY")
	if err != nil {
		t.Fatal(err)
	}
	if err := s.VerifyPasswordAndApply(ctx, org.ID, "casey", initial.Password, nil); !errors.Is(err, ErrPasswordCredential) {
		t.Fatal("old password followed reassigned name", err)
	}
	for _, tc := range []struct{ name, password, member string }{{"casey", newPassword, admin.ID}, {detail.LoginUsername, initial.Password, first.ID}} {
		if err := s.VerifyPasswordAndApply(ctx, org.ID, tc.name, tc.password, func(_ pgx.Tx, a MemberAdmission) error {
			if a.MemberID != tc.member {
				t.Fatal("credential changed identity")
			}
			return nil
		}); err != nil {
			t.Fatal(err)
		}
	}
}
