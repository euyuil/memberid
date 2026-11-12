//go:build integration

package identity

import (
	"errors"
	"strings"
	"testing"
)

func enrollmentInput(t *testing.T, store *Store) OrganizationEnrollment {
	t.Helper()
	organizationID, err := NewID(OrganizationKind)
	if err != nil {
		t.Fatal(err)
	}
	memberID, err := NewID(MemberKind)
	if err != nil {
		t.Fatal(err)
	}
	factor, err := store.EnsureFactor(t.Context(), "phone", "phone:e164", "+8619900000001")
	if err != nil {
		t.Fatal(err)
	}
	return OrganizationEnrollment{OrganizationID: organizationID, Name: "Example organization", MemberID: memberID, BindingID: "abcd0000-abcd-4abc-8abc-000000000001", FactorID: factor.ID}
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
		go func() { receipt, err := store.EnrollOrganization(t.Context(), input); results <- outcome{receipt, err} }()
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
	if first.OrganizationID != input.OrganizationID || first.MemberID != input.MemberID || first.BindingID != input.BindingID || first.FactorID != input.FactorID || first.CreatedAt.IsZero() {
		t.Fatalf("incorrect receipt: %+v", first)
	}
	uppercase := input
	uppercase.BindingID = strings.ToUpper(input.BindingID)
	canonical, err := store.EnrollOrganization(t.Context(), uppercase)
	if err != nil || canonical != first {
		t.Fatal("UUID casing changed the accepted identity", err)
	}
	members, err := store.Members(t.Context(), input.OrganizationID, "", 100)
	if err != nil || len(members.Items) != 1 || members.Items[0].ID != input.MemberID || members.Items[0].DisplayName != "Member" {
		t.Fatal("enrollment did not create exactly one independent Member", err)
	}
	eligibility, err := store.Eligibility(t.Context(), input.OrganizationID, input.MemberID, input.FactorID, "phone")
	if err != nil || !eligibility.Eligible || eligibility.BindingID != input.BindingID {
		t.Fatal("enrollment binding missing", err)
	}
	if _, err := store.SetManualBlock(t.Context(), input.OrganizationID, input.MemberID, true); err != nil {
		t.Fatal(err)
	}
	if err := store.RevokeBinding(t.Context(), input.OrganizationID, input.MemberID, input.FactorID); err != nil {
		t.Fatal(err)
	}
	renamed := "Renamed organization"
	if _, err := store.UpdateOrganization(t.Context(), input.OrganizationID, OrganizationChange{Name: &renamed}); err != nil {
		t.Fatal(err)
	}
	if _, err := store.pool.Exec(t.Context(), "UPDATE authentication_factors SET status='disabled' WHERE id=$1", input.FactorID); err != nil {
		t.Fatal(err)
	}
	replay, err := store.EnrollOrganization(t.Context(), input)
	if err != nil || replay != first {
		t.Fatal("accepted request lost its receipt after later changes", err)
	}
	eligibility, err = store.Eligibility(t.Context(), input.OrganizationID, input.MemberID, input.FactorID, "phone")
	if err != nil || eligibility.Eligible {
		t.Fatal("replay restored login eligibility", err)
	}
	stored, err := store.Enrollment(t.Context(), input.OrganizationID)
	if err != nil || stored != first {
		t.Fatal("receipt lookup changed accepted identity", err)
	}
	for _, change := range []func(*OrganizationEnrollment){
		func(v *OrganizationEnrollment) { v.Name = "Different organization" },
		func(v *OrganizationEnrollment) { v.MemberID, _ = NewID(MemberKind) },
		func(v *OrganizationEnrollment) { v.FactorID, _ = NewID(FactorKind) },
		func(v *OrganizationEnrollment) { v.BindingID = "00000000-0000-4000-8000-000000000002" },
	} {
		different := input
		change(&different)
		if _, err := store.EnrollOrganization(t.Context(), different); !errors.Is(err, ErrConflict) {
			t.Fatal("mismatched replay accepted", err)
		}
	}
}

func TestEnrollmentCollisionRollsBackAndCanRetry(t *testing.T) {
	store := testStore(t)
	existingOrganization, existingMember := organizationAndMember(t, store)
	input := enrollmentInput(t, store)
	input.MemberID = existingMember.ID
	if _, err := store.EnrollOrganization(t.Context(), input); !errors.Is(err, ErrMemberIDConflict) {
		t.Fatal("existing Member was adopted", err)
	}
	if _, err := store.Organization(t.Context(), input.OrganizationID); !errors.Is(err, ErrNotFound) {
		t.Fatal("partial organization remained", err)
	}
	if _, err := store.Enrollment(t.Context(), input.OrganizationID); !errors.Is(err, ErrNotFound) {
		t.Fatal("failed request reserved a receipt", err)
	}
	retained, err := store.Member(t.Context(), existingOrganization.ID, existingMember.ID)
	if err != nil || retained.ID != existingMember.ID || retained.OrganizationID != existingOrganization.ID {
		t.Fatal("collision changed existing identity", err)
	}
	input.MemberID, err = NewID(MemberKind)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.EnrollOrganization(t.Context(), input); err != nil {
		t.Fatal("safe retry failed", err)
	}
	second := enrollmentInput(t, store)
	// A duplicate binding identifier must roll back the entire second enrollment.
	if _, err := store.EnrollOrganization(t.Context(), second); !errors.Is(err, ErrConflict) {
		t.Fatal("duplicate binding accepted", err)
	}
	if _, err := store.Organization(t.Context(), second.OrganizationID); !errors.Is(err, ErrNotFound) {
		t.Fatal("binding collision left partial data", err)
	}
	second.BindingID = "00000000-0000-4000-8000-000000000002"
	if _, err := store.EnrollOrganization(t.Context(), second); err != nil {
		t.Fatal(err)
	}
	if second.MemberID == input.MemberID {
		t.Fatal("shared factor merged independent Members")
	}
}

func TestEnrollmentRequiresActiveVerifiedPhoneAndNewOrganization(t *testing.T) {
	for _, kind := range []string{"missing", "disabled", "dingtalk", "namespace", "existing organization"} {
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
			case "existing organization":
				if _, err := store.CreateOrganization(t.Context(), input.OrganizationID, input.Name); err != nil {
					t.Fatal(err)
				}
				want = ErrConflict
			}
			if _, err := store.EnrollOrganization(t.Context(), input); !errors.Is(err, want) {
				t.Fatalf("error=%v, want %v", err, want)
			}
			if _, err := store.Enrollment(t.Context(), input.OrganizationID); !errors.Is(err, ErrNotFound) {
				t.Fatal("rejected request left a receipt", err)
			}
		})
	}
}

func TestEnrollmentInputValidation(t *testing.T) {
	store := testStore(t)
	input := enrollmentInput(t, store)
	for _, change := range []func(*OrganizationEnrollment){func(v *OrganizationEnrollment) { v.Name = " " }, func(v *OrganizationEnrollment) { v.Name = strings.Repeat("x", 129) }, func(v *OrganizationEnrollment) { v.BindingID = "not-a-uuid" }, func(v *OrganizationEnrollment) { v.MemberID = v.OrganizationID }} {
		invalid := input
		change(&invalid)
		if _, err := store.EnrollOrganization(t.Context(), invalid); !errors.Is(err, ErrInvalid) {
			t.Fatal("invalid request accepted", err)
		}
	}
}

func TestConflictingConcurrentEnrollmentsAcceptOneTuple(t *testing.T) {
	store := testStore(t)
	first := enrollmentInput(t, store)
	second := first
	var err error
	second.MemberID, err = NewID(MemberKind)
	if err != nil {
		t.Fatal(err)
	}
	second.BindingID = "00000000-0000-4000-8000-000000000002"
	start := make(chan struct{})
	type outcome struct {
		input   OrganizationEnrollment
		receipt EnrollmentReceipt
		err     error
	}
	results := make(chan outcome, 2)
	for _, input := range []OrganizationEnrollment{first, second} {
		go func() {
			<-start
			receipt, err := store.EnrollOrganization(t.Context(), input)
			results <- outcome{input, receipt, err}
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
	if rejected != 1 || winner.OrganizationID != first.OrganizationID {
		t.Fatal("missing unique accepted result")
	}
	members, err := store.Members(t.Context(), first.OrganizationID, "", 100)
	if err != nil || len(members.Items) != 1 || members.Items[0].ID != winner.MemberID {
		t.Fatal("conflicting request left partial Member", err)
	}
}
