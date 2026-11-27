//go:build integration

package identity

import (
	"errors"
	"strings"
	"testing"
)

func enrollmentInput(t *testing.T, store *Store) OrganizationEnrollment {
	t.Helper()
	factor, err := store.EnsureFactor(t.Context(), "phone", "phone:e164", "+8619900000001")
	if err != nil {
		t.Fatal(err)
	}
	return OrganizationEnrollment{IdempotencyKey: "abcd0000-abcd-4abc-8abc-000000000099", Name: "Example organization", BindingID: "abcd0000-abcd-4abc-8abc-000000000001", FactorID: factor.ID}
}

func TestConcurrentEnrollmentAndImmutableReceipt(t *testing.T) {
	store := testStore(t)
	input := enrollmentInput(t, store)
	type outcome struct {
		receipt EnrollmentReceipt
		err     error
	}
	results := make(chan outcome, 12)
	for range 12 {
		go func() {
			receipt, err := store.EnrollOrganization(t.Context(), OperatorPrincipal(), input)
			results <- outcome{receipt, err}
		}()
	}
	var first EnrollmentReceipt
	for index := range 12 {
		result := <-results
		if result.err != nil {
			t.Fatal(result.err)
		}
		if index == 0 {
			first = result.receipt
		} else if result.receipt != first {
			t.Fatal("replay changed receipt")
		}
	}
	if !ValidID(first.OrganizationID, OrganizationKind) || !ValidID(first.MemberID, MemberKind) || first.BindingID != input.BindingID || first.FactorID != input.FactorID || first.CreatedAt.IsZero() {
		t.Fatalf("incorrect receipt: %+v", first)
	}
	uppercase := input
	uppercase.IdempotencyKey = strings.ToUpper(input.IdempotencyKey)
	uppercase.BindingID = strings.ToUpper(input.BindingID)
	canonical, err := store.EnrollOrganization(t.Context(), OperatorPrincipal(), uppercase)
	if err != nil || canonical != first {
		t.Fatal("UUID casing changed the accepted identity", err)
	}
	members, err := store.Members(t.Context(), first.OrganizationID, "", 100)
	if err != nil || len(members.Items) != 1 || members.Items[0].ID != first.MemberID || members.Items[0].DisplayName != "Member" {
		t.Fatal("enrollment did not create exactly one independent Member", err)
	}
	eligibility, err := store.Eligibility(t.Context(), first.OrganizationID, first.MemberID, input.FactorID, "phone")
	if err != nil || !eligibility.Eligible || eligibility.BindingID != input.BindingID {
		t.Fatal("enrollment binding missing", err)
	}
	if _, err := store.SetManualBlock(t.Context(), OperatorPrincipal(), first.OrganizationID, first.MemberID, true); err != nil {
		t.Fatal(err)
	}
	if err := store.RevokeBinding(t.Context(), OperatorPrincipal(), first.OrganizationID, first.MemberID, input.FactorID); err != nil {
		t.Fatal(err)
	}
	renamed := "Renamed organization"
	if _, err := store.UpdateOrganization(t.Context(), OperatorPrincipal(), first.OrganizationID, OrganizationChange{Name: &renamed}); err != nil {
		t.Fatal(err)
	}
	if _, err := store.pool.Exec(t.Context(), "UPDATE authentication_factors SET status='disabled' WHERE id=$1", input.FactorID); err != nil {
		t.Fatal(err)
	}
	replay, err := store.EnrollOrganization(t.Context(), OperatorPrincipal(), input)
	if err != nil || replay != first {
		t.Fatal("accepted request lost its receipt after later changes", err)
	}
	eligibility, err = store.Eligibility(t.Context(), first.OrganizationID, first.MemberID, input.FactorID, "phone")
	if err != nil || eligibility.Eligible {
		t.Fatal("replay restored login eligibility", err)
	}
	stored, err := store.Enrollment(t.Context(), first.OrganizationID)
	if err != nil || stored != first {
		t.Fatal("receipt lookup changed accepted identity", err)
	}
	for _, change := range []func(*OrganizationEnrollment){
		func(v *OrganizationEnrollment) { v.Name = "Different organization" },
		func(v *OrganizationEnrollment) { v.FactorID, _ = NewID(FactorKind) },
		func(v *OrganizationEnrollment) { v.BindingID = "00000000-0000-4000-8000-000000000002" },
	} {
		different := input
		change(&different)
		if _, err := store.EnrollOrganization(t.Context(), OperatorPrincipal(), different); !errors.Is(err, ErrConflict) {
			t.Fatal("mismatched replay accepted", err)
		}
	}
}

func TestEnrollmentCollisionRollsBackAndCanRetry(t *testing.T) {
	store := testStore(t)
	input := enrollmentInput(t, store)
	first, err := store.EnrollOrganization(t.Context(), OperatorPrincipal(), input)
	if err != nil {
		t.Fatal(err)
	}
	second := input
	second.IdempotencyKey = "00000000-0000-4000-8000-000000000099"
	if _, err := store.EnrollOrganization(t.Context(), OperatorPrincipal(), second); !errors.Is(err, ErrConflict) {
		t.Fatal("duplicate binding accepted", err)
	}
	var organizations, members, receipts int
	if err := store.pool.QueryRow(t.Context(), "SELECT (SELECT count(*) FROM organizations), (SELECT count(*) FROM members), (SELECT count(*) FROM organization_enrollments)").Scan(&organizations, &members, &receipts); err != nil || organizations != 2 || members != 1 || receipts != 1 {
		t.Fatal("binding collision left partial data", organizations, members, receipts, err)
	}
	second.BindingID = "00000000-0000-4000-8000-000000000002"
	retry, err := store.EnrollOrganization(t.Context(), OperatorPrincipal(), second)
	if err != nil || retry.MemberID == first.MemberID || retry.OrganizationID == first.OrganizationID {
		t.Fatal("retry after rollback did not allocate independent identities", err)
	}
}

func TestEnrollmentRequiresActiveVerifiedPhone(t *testing.T) {
	for _, kind := range []string{"missing", "disabled", "dingtalk", "namespace"} {
		t.Run(kind, func(t *testing.T) {
			store := testStore(t)
			input := enrollmentInput(t, store)
			want := ErrIneligible
			switch kind {
			case "missing":
				input.FactorID, _ = NewID(FactorKind)
				want = ErrNotFound
			case "disabled":
				if _, err := store.pool.Exec(t.Context(), "UPDATE authentication_factors SET status='disabled' WHERE id=$1", input.FactorID); err != nil {
					t.Fatal(err)
				}
			case "dingtalk":
				factor, err := store.EnsureFactor(t.Context(), "dingtalk", "example-provider", "example-subject")
				if err != nil {
					t.Fatal(err)
				}
				input.FactorID = factor.ID
			case "namespace":
				factor, err := store.EnsureFactor(t.Context(), "phone", "unverified-import", "example-contact")
				if err != nil {
					t.Fatal(err)
				}
				input.FactorID = factor.ID
			}
			if _, err := store.EnrollOrganization(t.Context(), OperatorPrincipal(), input); !errors.Is(err, want) {
				t.Fatalf("error=%v, want %v", err, want)
			}
			var count int
			if err := store.pool.QueryRow(t.Context(), "SELECT count(*) FROM organization_enrollments").Scan(&count); err != nil || count != 0 {
				t.Fatal("rejected request left a receipt", err)
			}
		})
	}
}

func TestEnrollmentInputValidation(t *testing.T) {
	store := testStore(t)
	input := enrollmentInput(t, store)
	for _, change := range []func(*OrganizationEnrollment){
		func(v *OrganizationEnrollment) { v.Name = " " },
		func(v *OrganizationEnrollment) { v.Name = strings.Repeat("x", 129) },
		func(v *OrganizationEnrollment) { v.BindingID = "not-a-uuid" },
		func(v *OrganizationEnrollment) { v.IdempotencyKey = "" },
		func(v *OrganizationEnrollment) { v.IdempotencyKey = "malformed" },
	} {
		invalid := input
		change(&invalid)
		if _, err := store.EnrollOrganization(t.Context(), OperatorPrincipal(), invalid); !errors.Is(err, ErrInvalid) {
			t.Fatal("invalid request accepted", err)
		}
	}
}

func TestConflictingConcurrentEnrollmentsAcceptOneTuple(t *testing.T) {
	store := testStore(t)
	first := enrollmentInput(t, store)
	second := first
	second.BindingID = "00000000-0000-4000-8000-000000000002"
	start := make(chan struct{})
	type outcome struct {
		receipt EnrollmentReceipt
		err     error
	}
	results := make(chan outcome, 2)
	for _, input := range []OrganizationEnrollment{first, second} {
		go func() {
			<-start
			receipt, err := store.EnrollOrganization(t.Context(), OperatorPrincipal(), input)
			results <- outcome{receipt, err}
		}()
	}
	close(start)
	var winner EnrollmentReceipt
	var rejected int
	for range 2 {
		result := <-results
		if errors.Is(result.err, ErrConflict) {
			rejected++
			continue
		}
		if result.err != nil {
			t.Fatal(result.err)
		}
		if winner.OrganizationID != "" {
			t.Fatal("accepted conflicting tuples")
		}
		winner = result.receipt
	}
	if rejected != 1 || !ValidID(winner.OrganizationID, OrganizationKind) {
		t.Fatal("missing unique accepted result")
	}
	members, err := store.Members(t.Context(), winner.OrganizationID, "", 100)
	if err != nil || len(members.Items) != 1 || members.Items[0].ID != winner.MemberID {
		t.Fatal("conflicting request left partial Member", err)
	}
}
