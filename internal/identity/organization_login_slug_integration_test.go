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
	service := NewManagementService(store, nil, nil, 0)
	admins := map[string]Principal{}
	for n, org := range []string{first.ID, second.ID, store.SystemOrganizationID()} {
		m, f := administratorMember(t, store, org, n+1)
		admins[org] = administratorActor(t, store, m, f).Principal()
	}
	platform := admins[store.SystemOrganizationID()]
	assign := func(id, slug string) error { return service.ChangeOrganizationSlug(ctx, admins[id], id, "", slug) }
	for _, principal := range []Principal{Principal{}, OperatorPrincipal(), platform, admins[second.ID]} {
		if err := service.ChangeOrganizationSlug(ctx, principal, first.ID, "", "example"); !errors.Is(err, ErrForbidden) {
			t.Fatalf("unauthorized first assignment: %v", err)
		}
	}
	for _, slug := range []string{"", "Kelvin", "SYSTEM", " example", "a--b", "a-", "-a", "a/b", "a_b", "团队", "system", strings.Repeat("a", 64)} {
		if err := assign(first.ID, slug); !errors.Is(err, ErrInvalid) {
			t.Fatalf("assigned invalid slug %q: %v", slug, err)
		}
	}
	if err := assign(store.SystemOrganizationID(), "example"); !errors.Is(err, ErrForbidden) {
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
	if err := service.ChangeOrganizationSlug(ctx, admins[id], id, "example-2", "new-team"); !errors.Is(err, ErrForbidden) {
		t.Fatal("owner renamed existing slug", err)
	}
	if err := assign(other, "occupied"); err != nil {
		t.Fatal(err)
	}
	rename := func(from, to string) error { return service.ChangeOrganizationSlug(ctx, platform, id, from, to) }
	if err := rename("example-2", "occupied"); !errors.Is(err, ErrConflict) {
		t.Fatal("occupied rename", err)
	}
	if err := rename("stale", "new-team"); !errors.Is(err, ErrConflict) {
		t.Fatal("stale rename", err)
	}
	if err := rename("Example-2", "NEW-team"); err != nil {
		t.Fatal(err)
	}
	if suffix, err := store.OrganizationLoginSuffix(ctx, id); err != nil || suffix != "new-team" {
		t.Fatal(suffix, err)
	}
	if err := service.ChangeOrganizationSlug(ctx, platform, other, "occupied", "example-2"); err != nil {
		t.Fatal(err)
	}
	if got, err := store.LoginOrganizationIDBySlug(ctx, "example-2"); got != other || err != nil {
		t.Fatal(got, err)
	}
	events, err := store.ManagementEvents(ctx, id, "", 0)
	if err != nil || len(events) == 0 || events[0].Action != "organization.slug.update" || events[0].Actor != platform.memberID {
		t.Fatal("missing rename audit", events, err)
	}
}
