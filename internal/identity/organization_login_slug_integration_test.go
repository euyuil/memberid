//go:build integration

package identity

import (
	"errors"
	"strings"
	"testing"
)

func TestOrganizationSlugReservations(t *testing.T) {
	store := testStore(t)
	first, _ := organizationAndMember(t, store)
	second, _ := organizationAndMember(t, store)
	ctx := t.Context()
	assign := func(id, slug string) error { return store.AssignOrganizationSlug(ctx, OperatorPrincipal(), id, slug) }
	if err := store.AssignOrganizationSlug(ctx, Principal{}, first.ID, "example"); !errors.Is(err, ErrForbidden) {
		t.Fatalf("assignment without operator authority: %v", err)
	}
	for _, slug := range []string{"", "Kelvin", "SYSTEM", " example", "a--b", "a-", "-a", "a/b", "a_b", "团队", "system", strings.Repeat("a", 64)} {
		if err := assign(first.ID, slug); !errors.Is(err, ErrInvalid) {
			t.Fatalf("assigned invalid slug %q: %v", slug, err)
		}
	}
	if err := assign(store.SystemOrganizationID(), "example"); !errors.Is(err, ErrInvalid) {
		t.Fatal("system organization accepted an alias", err)
	}
	results := make(chan error, 2)
	for id, slug := range map[string]string{first.ID: "Example-2", second.ID: "EXAMPLE-2"} {
		go func() { results <- assign(id, slug) }()
	}
	var ok, conflicts int
	for range 2 {
		switch err := <-results; {
		case err == nil:
			ok++
		case errors.Is(err, ErrConflict):
			conflicts++
		default:
			t.Fatal(err)
		}
	}
	if ok != 1 || conflicts != 1 {
		t.Fatalf("concurrent assignment returned %d successes and %d conflicts", ok, conflicts)
	}
	id, err := store.LoginOrganizationIDBySlug(ctx, "example-2")
	if err != nil || id != first.ID && id != second.ID {
		t.Fatal(id, err)
	}
	if err := assign(id, "replacement"); !errors.Is(err, ErrConflict) {
		t.Fatal("existing organization acquired a second slug", err)
	}
	disabled := "disabled"
	if _, err := store.UpdateOrganization(ctx, OperatorPrincipal(), id, OrganizationChange{Status: &disabled}); err != nil {
		t.Fatal(err)
	}
	if _, err := store.LoginOrganizationIDBySlug(ctx, "example-2"); !errors.Is(err, ErrNotFound) {
		t.Fatal("disabled organization resolved", err)
	}
	other := first.ID
	if id == other {
		other = second.ID
	}
	if err := assign(other, "example-2"); !errors.Is(err, ErrConflict) {
		t.Fatal("disabled organization's slug was reused", err)
	}
}
