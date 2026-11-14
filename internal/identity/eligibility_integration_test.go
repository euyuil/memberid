//go:build integration

package identity

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"slices"
	"testing"

	"github.com/euyuil/memberid/internal/dingtalk"
)

func boundPhone(t *testing.T, store *Store, organizationID, memberID, number string) Factor {
	t.Helper()
	factor, err := store.EnsureFactor(t.Context(), "phone", "phone:e164", number)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.BindFactor(t.Context(), OperatorPrincipal(), organizationID, memberID, factor.ID); err != nil {
		t.Fatal(err)
	}
	return factor
}

func TestEligibleMemberIDsBoundedOrganizationSelection(t *testing.T) {
	store := testStore(t)
	first, member := organizationAndMember(t, store)
	second, other := organizationAndMember(t, store)
	factor := boundPhone(t, store, first.ID, member.ID, "+12025550101")
	if _, err := store.BindFactor(t.Context(), OperatorPrincipal(), second.ID, other.ID, factor.ID); err != nil {
		t.Fatal(err)
	}
	unbound, err := store.CreateMember(t.Context(), OperatorPrincipal(), first.ID, "", "Unbound Member")
	if err != nil {
		t.Fatal(err)
	}
	missing, err := NewID(MemberKind)
	if err != nil {
		t.Fatal(err)
	}
	candidates := []string{other.ID, unbound.ID, missing, member.ID}
	for _, scope := range []struct{ organizationID, memberID string }{{first.ID, member.ID}, {second.ID, other.ID}} {
		got, err := store.EligibleMemberIDs(t.Context(), scope.organizationID, candidates)
		if err != nil || !slices.Equal(got, []string{scope.memberID}) {
			t.Fatalf("organization isolation: %v %v", got, err)
		}
	}
	unknownOrganization, err := NewID(OrganizationKind)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := store.EligibleMemberIDs(t.Context(), unknownOrganization, candidates); err != nil || got == nil || len(got) != 0 {
		t.Fatalf("missing organization: %v %v", got, err)
	}
	var maximum []string
	for range 100 {
		id, err := NewID(MemberKind)
		if err != nil {
			t.Fatal(err)
		}
		maximum = append(maximum, id)
	}
	if got, err := store.EligibleMemberIDs(t.Context(), first.ID, maximum); err != nil || got == nil || len(got) != 0 {
		t.Fatalf("maximum candidate list: %v %v", got, err)
	}
	for _, candidates := range [][]string{nil, {}, {"invalid"}, {member.ID, member.ID}, append(maximum, member.ID)} {
		if got, err := store.EligibleMemberIDs(t.Context(), first.ID, candidates); !errors.Is(err, ErrInvalid) || got != nil {
			t.Fatal("invalid candidates accepted", err)
		}
	}
	if _, err := store.EligibleMemberIDs(t.Context(), member.ID, []string{member.ID}); !errors.Is(err, ErrInvalid) {
		t.Fatal("wrong organization identifier kind accepted", err)
	}
}

func TestEligibilityQueriesShareCurrentBindingGates(t *testing.T) {
	for _, change := range []string{"manual block", "external departure", "disabled factor", "revoked binding", "disabled organization"} {
		t.Run(change, func(t *testing.T) {
			store := testStore(t)
			organization, member := organizationAndMember(t, store)
			factor := boundPhone(t, store, organization.ID, member.ID, "+12025550102")
			check := func(want bool) {
				t.Helper()
				batch, err := store.EligibleMemberIDs(t.Context(), organization.ID, []string{member.ID})
				if err != nil || (len(batch) == 1) != want {
					t.Fatalf("aggregate eligibility: %v %v", batch, err)
				}
				binding, err := store.Eligibility(t.Context(), organization.ID, member.ID, factor.ID, "phone")
				if err != nil || binding.Eligible != want {
					t.Fatalf("binding eligibility: %+v %v", binding, err)
				}
				selected, err := store.EligibleMembers(t.Context(), factor.ID)
				if err != nil || (len(selected) == 1) != want {
					t.Fatalf("login selection: %v %v", selected, err)
				}
				_, err = MemberEvidence(t.Context(), store.pool, factor.ID, member.ID, organization.ID)
				if want && err != nil || !want && !errors.Is(err, ErrNotFound) {
					t.Fatalf("transaction evidence: %v", err)
				}
			}
			check(true)
			var err error
			switch change {
			case "manual block":
				_, err = store.SetManualBlock(t.Context(), OperatorPrincipal(), organization.ID, member.ID, true)
			case "external departure":
				_, err = store.SetExternalDeparture(t.Context(), organization.ID, member.ID, true)
			case "disabled factor":
				_, err = store.pool.Exec(t.Context(), "UPDATE authentication_factors SET status='disabled' WHERE id=$1", factor.ID)
			case "revoked binding":
				err = store.RevokeBinding(t.Context(), OperatorPrincipal(), organization.ID, member.ID, factor.ID)
			case "disabled organization":
				status := "disabled"
				_, err = store.UpdateOrganization(t.Context(), OperatorPrincipal(), organization.ID, OrganizationChange{Status: &status})
			}
			if err != nil {
				t.Fatal(err)
			}
			check(false)
		})
	}
}

func TestMemberEligibilityUsesAnyBindingWithoutAuthenticatingOne(t *testing.T) {
	for _, change := range []string{"factor unavailable", "wrong namespace", "missing application", "revoked application"} {
		t.Run(change, func(t *testing.T) {
			store, apps, organization, _ := applicationFixture(t)
			app, err := apps.Configure(t.Context(), OperatorPrincipal(), organization.ID, DingTalkApplicationInput{CorpID: "example-corp", ClientID: "example-client", ClientSecret: rand.Text()})
			if err != nil {
				t.Fatal(err)
			}
			member, err := store.CreateMember(t.Context(), OperatorPrincipal(), organization.ID, "", "Example Member")
			if err != nil {
				t.Fatal(err)
			}
			phone := boundPhone(t, store, organization.ID, member.ID, "+12025550103")
			external, err := store.EnsureFactor(t.Context(), "dingtalk", app.Namespace, "example-union")
			if err != nil {
				t.Fatal(err)
			}
			if _, err := store.BindFactor(t.Context(), OperatorPrincipal(), organization.ID, member.ID, external.ID); err != nil {
				t.Fatal(err)
			}
			check := func(want bool) {
				t.Helper()
				got, err := store.EligibleMemberIDs(t.Context(), organization.ID, []string{member.ID})
				if err != nil || (len(got) == 1) != want || len(got) > 1 {
					t.Fatalf("eligible Member must occur once: %v %v", got, err)
				}
			}
			check(true)
			if err := store.RevokeBinding(t.Context(), OperatorPrincipal(), organization.ID, member.ID, phone.ID); err != nil {
				t.Fatal(err)
			}
			check(true)
			if result, err := store.Eligibility(t.Context(), organization.ID, member.ID, phone.ID, "phone"); err != nil || result.Eligible {
				t.Fatal("aggregate result authenticated a revoked binding", err)
			}
			switch change {
			case "factor unavailable":
				_, err = store.pool.Exec(t.Context(), "UPDATE authentication_factors SET status='disabled' WHERE id=$1", external.ID)
			case "wrong namespace":
				_, err = store.pool.Exec(t.Context(), "UPDATE authentication_factors SET namespace='other-namespace' WHERE id=$1", external.ID)
			case "missing application":
				_, err = store.pool.Exec(t.Context(), "DELETE FROM dingtalk_applications WHERE organization_id=$1", organization.ID)
			case "revoked application":
				apps.checker = checkDingTalkFunc(func(context.Context, string, string, string) error { return dingtalk.ErrAuthorizationDenied })
				_, err = apps.SynchronizeAuthorization(t.Context(), organization.ID)
			}
			if err != nil {
				t.Fatal(err)
			}
			check(false)
		})
	}
}

func TestMemberEligibilityObservesOneStatementSnapshot(t *testing.T) {
	store := testStore(t)
	organization, first := organizationAndMember(t, store)
	second, err := store.CreateMember(t.Context(), OperatorPrincipal(), organization.ID, "", "Second Member")
	if err != nil {
		t.Fatal(err)
	}
	for i, member := range []Member{first, second} {
		boundPhone(t, store, organization.ID, member.ID, fmt.Sprintf("+120255501%02d", i+10))
	}
	if _, err := store.SetManualBlock(t.Context(), OperatorPrincipal(), organization.ID, second.ID, true); err != nil {
		t.Fatal(err)
	}
	members := []string{first.ID, second.ID}
	done := make(chan error, 1)
	go func() {
		for i := range 100 {
			// Each committed state has exactly one usable Member.
			if _, err := store.pool.Exec(t.Context(), "UPDATE members SET manual_block=(id=$1) WHERE organization_id=$2", members[i%2], organization.ID); err != nil {
				done <- err
				return
			}
		}
		done <- nil
	}()
	defer func() {
		if err := <-done; err != nil {
			t.Error(err)
		}
	}()
	for range 100 {
		got, err := store.EligibleMemberIDs(t.Context(), organization.ID, members)
		if err != nil || len(got) != 1 || !slices.Contains(members, got[0]) {
			t.Fatalf("mixed eligibility snapshots: %v %v", got, err)
		}
	}
}
