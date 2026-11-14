//go:build integration

package identity

import (
	"errors"
	"reflect"
	"strings"
	"testing"
)

func TestConcurrentMemberUpdateAndHistoricalReplay(t *testing.T) {
	store := testStore(t)
	organization, member := organizationAndMember(t, store)
	updateID := "abcd0000-abcd-4abc-8abc-000000000001"
	name, blocked := "Updated member", true
	change := MemberChange{DisplayName: &name, ManualBlocked: &blocked}
	type outcome struct {
		receipt MemberUpdateReceipt
		created bool
		err     error
	}
	results := make(chan outcome, 12)
	for range 12 {
		go func() {
			receipt, created, err := store.UpdateMemberOnce(t.Context(), OperatorPrincipal(), organization.ID, member.ID, updateID, change)
			results <- outcome{receipt, created, err}
		}()
	}
	var first MemberUpdateReceipt
	createdCount := 0
	for index := range 12 {
		result := <-results
		if result.err != nil {
			t.Fatal(result.err)
		}
		if result.created {
			createdCount++
		}
		if index == 0 {
			first = result.receipt
		} else if !reflect.DeepEqual(first, result.receipt) {
			t.Fatal("concurrent retry changed receipt")
		}
	}
	if createdCount != 1 || first.ID != updateID || first.OrganizationID != organization.ID || first.MemberID != member.ID || first.Member.DisplayName != name || first.Member.Status != "blocked" || first.CreatedAt.IsZero() {
		t.Fatal("update did not commit exactly once")
	}
	renamed, unblocked := "Later member name", false
	if _, _, err := store.UpdateMemberOnce(t.Context(), OperatorPrincipal(), organization.ID, member.ID, "00000000-0000-4000-8000-000000000002", MemberChange{DisplayName: &renamed, ManualBlocked: &unblocked}); err != nil {
		t.Fatal(err)
	}
	if _, err := store.SetExternalDeparture(t.Context(), organization.ID, member.ID, true); err != nil {
		t.Fatal(err)
	}
	reopened, err := Open(t.Context(), store.pool.Config().ConnString())
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	replayed, created, err := reopened.UpdateMemberOnce(t.Context(), OperatorPrincipal(), organization.ID, member.ID, strings.ToUpper(updateID), change)
	if err != nil || created || !reflect.DeepEqual(first, replayed) {
		t.Fatal("restarted retry lost historical receipt", err)
	}
	current, err := store.Member(t.Context(), organization.ID, member.ID)
	if err != nil || current.DisplayName != renamed || !reflect.DeepEqual(current.BlockSources, []string{"externalDeparture"}) {
		t.Fatal("old retry reapplied an update", err)
	}
	retrieved, err := reopened.MemberUpdate(t.Context(), organization.ID, member.ID, updateID)
	if err != nil || !reflect.DeepEqual(first, retrieved) {
		t.Fatal("receipt lookup changed", err)
	}
	otherOrganization, otherMember := organizationAndMember(t, store)
	for _, target := range [][2]string{{otherOrganization.ID, member.ID}, {organization.ID, otherMember.ID}} {
		if _, err := store.MemberUpdate(t.Context(), target[0], target[1], updateID); !errors.Is(err, ErrNotFound) {
			t.Fatal("receipt crossed identity boundary", err)
		}
		if _, _, err := store.UpdateMemberOnce(t.Context(), OperatorPrincipal(), target[0], target[1], updateID, change); !errors.Is(err, ErrConflict) {
			t.Fatal("update identifier was reused for another identity", err)
		}
	}
	for _, different := range []MemberChange{{DisplayName: &renamed, ManualBlocked: &blocked}, {DisplayName: &name}, {ManualBlocked: &unblocked}} {
		if _, _, err := store.UpdateMemberOnce(t.Context(), OperatorPrincipal(), organization.ID, member.ID, updateID, different); !errors.Is(err, ErrConflict) {
			t.Fatal("accepted operation was replaced", err)
		}
	}
}

func TestMemberUpdateRollsBackWhenReceiptCannotCommit(t *testing.T) {
	store := testStore(t)
	organization, member := organizationAndMember(t, store)
	updateID := "00000000-0000-4000-8000-000000000003"
	// This constraint belongs only to the disposable test database. It fails the
	// receipt insert after the member mutation, exercising the transaction boundary.
	if _, err := store.pool.Exec(t.Context(), "ALTER TABLE member_updates ADD CONSTRAINT reject_test_receipt CHECK (id <> '00000000-0000-4000-8000-000000000003'::uuid)"); err != nil {
		t.Fatal(err)
	}
	name, blocked := "Must roll back", true
	change := MemberChange{DisplayName: &name, ManualBlocked: &blocked}
	if _, created, err := store.UpdateMemberOnce(t.Context(), OperatorPrincipal(), organization.ID, member.ID, updateID, change); err == nil || created {
		t.Fatal("failed receipt reported success")
	}
	current, err := store.Member(t.Context(), organization.ID, member.ID)
	if err != nil || !reflect.DeepEqual(current, member) {
		t.Fatal("failed receipt left a partial mutation", err)
	}
	var revision int64
	if err := store.pool.QueryRow(t.Context(), "SELECT eligibility_revision FROM members WHERE id=$1", member.ID).Scan(&revision); err != nil || revision != 0 {
		t.Fatal("failed receipt advanced eligibility revision", err)
	}
	if _, err := store.MemberUpdate(t.Context(), organization.ID, member.ID, updateID); !errors.Is(err, ErrNotFound) {
		t.Fatal("failed operation reserved its identifier", err)
	}
	if _, err := store.pool.Exec(t.Context(), "ALTER TABLE member_updates DROP CONSTRAINT reject_test_receipt"); err != nil {
		t.Fatal(err)
	}
	if _, created, err := store.UpdateMemberOnce(t.Context(), OperatorPrincipal(), organization.ID, member.ID, updateID, change); err != nil || !created {
		t.Fatal("rolled-back operation could not retry", err)
	}
}

func TestConflictingConcurrentMemberUpdatesCannotShareIdentifier(t *testing.T) {
	store := testStore(t)
	organization, member := organizationAndMember(t, store)
	type outcome struct {
		receipt MemberUpdateReceipt
		created bool
		err     error
	}
	results := make(chan outcome, 2)
	for _, name := range []string{"First candidate", "Second candidate"} {
		go func() {
			receipt, created, err := store.UpdateMemberOnce(t.Context(), OperatorPrincipal(), organization.ID, member.ID, "00000000-0000-4000-8000-000000000004", MemberChange{DisplayName: &name})
			results <- outcome{receipt, created, err}
		}()
	}
	var winner MemberUpdateReceipt
	accepted, conflicts := 0, 0
	for range 2 {
		result := <-results
		if result.err == nil && result.created {
			accepted++
			winner = result.receipt
		} else if errors.Is(result.err, ErrConflict) {
			conflicts++
		} else {
			t.Fatal("unexpected competing update result", result.err)
		}
	}
	current, err := store.Member(t.Context(), organization.ID, member.ID)
	if err != nil || accepted != 1 || conflicts != 1 || !reflect.DeepEqual(current, winner.Member) {
		t.Fatal("conflicting update changed the accepted result", err)
	}
}
