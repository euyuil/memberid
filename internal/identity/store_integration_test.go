//go:build integration

package identity

import (
	"context"
	"errors"
	"sync"
	"testing"

	"github.com/euyuil/memberid/internal/testdb"
	"github.com/jackc/pgx/v5"
)

func testStore(t *testing.T) *Store {
	t.Helper()
	databaseURL := testdb.Create(t)
	if err := Initialize(t.Context(), databaseURL); err != nil {
		t.Fatal(err)
	}
	store, err := Open(t.Context(), databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(store.Close)
	return store
}

func organizationAndMember(t *testing.T, store *Store) (Organization, Member) {
	t.Helper()
	organization, err := store.CreateOrganization(t.Context(), OperatorPrincipal(), "", "Example organization")
	if err != nil {
		t.Fatal(err)
	}
	member, err := store.CreateMember(t.Context(), OperatorPrincipal(), organization.ID, "", "Example member")
	if err != nil {
		t.Fatal(err)
	}
	return organization, member
}

func TestInitializeRefusesExistingData(t *testing.T) {
	databaseURL := testdb.Create(t)
	connection, err := pgx.Connect(t.Context(), databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close(context.Background())
	if _, err := connection.Exec(t.Context(), "CREATE TABLE retained(value text); INSERT INTO retained VALUES('keep')"); err != nil {
		t.Fatal(err)
	}
	if err := Initialize(t.Context(), databaseURL); !errors.Is(err, ErrDatabaseNotEmpty) {
		t.Fatalf("initialization error = %v", err)
	}
	var value string
	if err := connection.QueryRow(t.Context(), "SELECT value FROM retained").Scan(&value); err != nil || value != "keep" {
		t.Fatalf("existing data changed: %q, %v", value, err)
	}
	if _, err := Open(t.Context(), databaseURL); !errors.Is(err, ErrSchemaRequired) {
		t.Fatalf("unexpected open error: %v", err)
	}
}

func TestConcurrentInitialization(t *testing.T) {
	databaseURL := testdb.Create(t)
	results := make(chan error, 2)
	for range 2 {
		go func() { results <- Initialize(t.Context(), databaseURL) }()
	}
	var completed, refused int
	for range 2 {
		switch err := <-results; {
		case err == nil:
			completed++
		case errors.Is(err, ErrDatabaseNotEmpty):
			refused++
		default:
			t.Fatal(err)
		}
	}
	if completed != 1 || refused != 1 {
		t.Fatalf("completed=%d, refused=%d", completed, refused)
	}
}

func TestOrganizationIsolationAndExplicitBindings(t *testing.T) {
	store := testStore(t)
	first, firstMember := organizationAndMember(t, store)
	second, secondMember := organizationAndMember(t, store)
	factor, err := store.EnsureFactor(t.Context(), "phone", "example-sms", "synthetic-contact")
	if err != nil {
		t.Fatal(err)
	}
	var bindings int
	if err := store.pool.QueryRow(t.Context(), "SELECT count(*) FROM member_auth_factor_bindings").Scan(&bindings); err != nil || bindings != 0 {
		t.Fatalf("factor inferred a binding: %d, %v", bindings, err)
	}
	for _, pair := range [][2]string{{first.ID, firstMember.ID}, {second.ID, secondMember.ID}} {
		if _, err := store.BindFactor(t.Context(), OperatorPrincipal(), pair[0], pair[1], factor.ID); err != nil {
			t.Fatal(err)
		}
	}
	if firstMember.ID == secondMember.ID {
		t.Fatal("different organizations shared a Member identity")
	}
	if _, err := store.Member(t.Context(), second.ID, firstMember.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("cross-organization member lookup: %v", err)
	}
	if _, err := store.BindFactor(t.Context(), OperatorPrincipal(), second.ID, firstMember.ID, factor.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("cross-organization binding: %v", err)
	}
	if _, err := store.SetManualBlock(t.Context(), OperatorPrincipal(), second.ID, firstMember.ID, true); !errors.Is(err, ErrNotFound) {
		t.Fatalf("cross-organization mutation: %v", err)
	}
	other, err := store.CreateMember(t.Context(), OperatorPrincipal(), first.ID, "", "Different member")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.BindFactor(t.Context(), OperatorPrincipal(), first.ID, other.ID, factor.ID); !errors.Is(err, ErrConflict) {
		t.Fatalf("same organization shared a factor: %v", err)
	}
	if _, err := store.pool.Exec(t.Context(), "INSERT INTO member_auth_factor_bindings(member_id,organization_id,authentication_factor_id,factor_type) VALUES($1,$2,$3,'dingtalk')", firstMember.ID, second.ID, factor.ID); err == nil {
		t.Fatal("database accepted an inconsistent binding")
	}
}

func TestIndependentBlockSources(t *testing.T) {
	store := testStore(t)
	organization, member := organizationAndMember(t, store)
	if _, err := store.SetManualBlock(t.Context(), OperatorPrincipal(), organization.ID, member.ID, true); err != nil {
		t.Fatal(err)
	}
	if _, err := store.SetExternalDeparture(t.Context(), organization.ID, member.ID, true); err != nil {
		t.Fatal(err)
	}
	updated, err := store.SetExternalDeparture(t.Context(), organization.ID, member.ID, false)
	if err != nil || updated.Status != "blocked" || len(updated.BlockSources) != 1 || updated.BlockSources[0] != "manual" {
		t.Fatalf("provider update cleared manual block: %+v, %v", updated, err)
	}
	if _, err := store.SetExternalDeparture(t.Context(), organization.ID, member.ID, true); err != nil {
		t.Fatal(err)
	}
	updated, err = store.SetManualBlock(t.Context(), OperatorPrincipal(), organization.ID, member.ID, false)
	if err != nil || updated.Status != "blocked" || len(updated.BlockSources) != 1 || updated.BlockSources[0] != "externalDeparture" {
		t.Fatalf("manual update cleared departure: %+v, %v", updated, err)
	}
	updated, err = store.SetExternalDeparture(t.Context(), organization.ID, member.ID, false)
	if err != nil || updated.Status != "active" || updated.ID != member.ID {
		t.Fatalf("identity changed or stayed blocked: %+v, %v", updated, err)
	}
}

func TestBindingReplayAndRevocation(t *testing.T) {
	store := testStore(t)
	organization, member := organizationAndMember(t, store)
	factor, err := store.EnsureFactor(t.Context(), "phone", "example-sms", "first-contact")
	if err != nil {
		t.Fatal(err)
	}
	first, err := store.BindFactor(t.Context(), OperatorPrincipal(), organization.ID, member.ID, factor.ID)
	if err != nil {
		t.Fatal(err)
	}
	repeated, err := store.BindFactor(t.Context(), OperatorPrincipal(), organization.ID, member.ID, factor.ID)
	if err != nil || !repeated.CreatedAt.Equal(first.CreatedAt) {
		t.Fatalf("binding replay changed the relationship: %+v, %v", repeated, err)
	}
	if err := store.RevokeBinding(t.Context(), OperatorPrincipal(), organization.ID, member.ID, factor.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := store.BindFactor(t.Context(), OperatorPrincipal(), organization.ID, member.ID, factor.ID); !errors.Is(err, ErrConflict) {
		t.Fatalf("revoked binding reactivated: %v", err)
	}
	other, err := store.EnsureFactor(t.Context(), "phone", "example-sms", "second-contact")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.BindFactor(t.Context(), OperatorPrincipal(), organization.ID, member.ID, other.ID); !errors.Is(err, ErrConflict) {
		t.Fatalf("revoked slot replaced: %v", err)
	}
	retained, err := store.Member(t.Context(), organization.ID, member.ID)
	if err != nil || retained.ID != member.ID {
		t.Fatal("binding changes changed Member identity")
	}
}

func TestConcurrentFactorAndBindingCreation(t *testing.T) {
	store := testStore(t)
	organization, firstMember := organizationAndMember(t, store)
	secondMember, err := store.CreateMember(t.Context(), OperatorPrincipal(), organization.ID, "", "Second member")
	if err != nil {
		t.Fatal(err)
	}
	const workers = 12
	factors := make(chan Factor, workers)
	failures := make(chan error, workers)
	var group sync.WaitGroup
	for range workers {
		group.Go(func() {
			factor, err := store.EnsureFactor(t.Context(), "phone", "example-sms", "shared-contact")
			if err != nil {
				failures <- err
				return
			}
			factors <- factor
		})
	}
	group.Wait()
	close(factors)
	close(failures)
	for err := range failures {
		t.Fatal(err)
	}
	var factorID string
	for factor := range factors {
		if factorID != "" && factorID != factor.ID {
			t.Fatal("concurrent verification created duplicate factors")
		}
		factorID = factor.ID
	}
	type outcome struct {
		binding Binding
		err     error
	}
	results := make(chan outcome, workers)
	for index := range workers {
		memberID := firstMember.ID
		if index%2 == 1 {
			memberID = secondMember.ID
		}
		group.Go(func() {
			binding, err := store.BindFactor(t.Context(), OperatorPrincipal(), organization.ID, memberID, factorID)
			results <- outcome{binding, err}
		})
	}
	group.Wait()
	close(results)
	var winner string
	var conflicts int
	for result := range results {
		if errors.Is(result.err, ErrConflict) {
			conflicts++
			continue
		}
		if result.err != nil {
			t.Fatal(result.err)
		}
		if winner != "" && winner != result.binding.MemberID {
			t.Fatal("concurrent binding assigned a factor to two Members")
		}
		winner = result.binding.MemberID
	}
	if winner == "" || conflicts != workers/2 {
		t.Fatalf("winner=%q conflicts=%d", winner, conflicts)
	}
}
