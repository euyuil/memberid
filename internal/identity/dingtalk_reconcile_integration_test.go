//go:build integration

package identity

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/euyuil/memberid/internal/dingtalk"
)

func reconciliationFixture(t *testing.T) (*Store, *DingTalkApplications, *DingTalkDirectory, *DingTalkVerifier, DingTalkApplication, Member) {
	t.Helper()
	store, apps, verifier, app := verifierFixture(t)
	verified, err := admitLogin(t.Context(), verifier, verifiedLogin(t, verifier, app))
	if err != nil {
		t.Fatal(err)
	}
	members, err := store.EligibleMembers(t.Context(), verified.Factor.ID)
	if err != nil || len(members) != 1 {
		t.Fatal(err)
	}
	directory, err := NewDingTalkDirectory(apps, directoryDingTalkFunc(func(context.Context, string, string, string, string) (dingtalk.Member, error) {
		return dingtalk.Member{UnionID: "example-union", UserID: "example-employee", DisplayName: "New provider name", DepartmentIDs: []string{}}, nil
	}))
	if err != nil {
		t.Fatal(err)
	}
	return store, apps, directory, verifier, app, members[0]
}

func TestReconcilePreservesManualBlockAndIndependentIdentity(t *testing.T) {
	store, _, directory, _, app, member := reconciliationFixture(t)
	if _, err := store.SetManualBlock(t.Context(), app.OrganizationID, member.ID, true); err != nil {
		t.Fatal(err)
	}
	if _, err := store.SetExternalDeparture(t.Context(), app.OrganizationID, member.ID, true); err != nil {
		t.Fatal(err)
	}
	result, err := directory.Reconcile(t.Context(), app.OrganizationID)
	if err != nil || result.Present != 1 || result.Checked != 1 {
		t.Fatal("verified return failed", err)
	}
	current, err := store.Member(t.Context(), app.OrganizationID, member.ID)
	if err != nil || current.Status != "blocked" || len(current.BlockSources) != 1 || current.BlockSources[0] != "manual" || current.DisplayName != member.DisplayName {
		t.Fatal("synchronization changed manual identity policy", err)
	}
	var departments string
	if err := store.pool.QueryRow(t.Context(), "SELECT department_ids::text FROM dingtalk_identities WHERE member_id=$1", member.ID).Scan(&departments); err != nil || departments != "[]" {
		t.Fatal("verified empty departments lost", err)
	}
	directory.provider = directoryDingTalkFunc(func(context.Context, string, string, string, string) (dingtalk.Member, error) {
		return dingtalk.Member{}, dingtalk.ErrNotMember
	})
	result, err = directory.Reconcile(t.Context(), app.OrganizationID)
	if err != nil || result.Departed != 1 {
		t.Fatal("definitive nonmembership not retained", err)
	}
	current, err = store.Member(t.Context(), app.OrganizationID, member.ID)
	if err != nil || len(current.BlockSources) != 2 {
		t.Fatal("nonmembership erased independent manual block", err)
	}
	directory.provider = directoryDingTalkFunc(func(context.Context, string, string, string, string) (dingtalk.Member, error) {
		return dingtalk.Member{}, dingtalk.ErrUnavailable
	})
	result, err = directory.Reconcile(t.Context(), app.OrganizationID)
	if !errors.Is(err, ErrSynchronizationIncomplete) || result.Unavailable != 1 {
		t.Fatal("outage reported complete", err)
	}
	current, err = store.Member(t.Context(), app.OrganizationID, member.ID)
	if err != nil || len(current.BlockSources) != 2 {
		t.Fatal("outage erased stored evidence", err)
	}
	var count int
	for _, table := range []string{"oidc_sessions", "oidc_grants", "oidc_refresh_tokens"} {
		if err := store.pool.QueryRow(t.Context(), "SELECT count(*) FROM "+table).Scan(&count); err != nil || count != 0 {
			t.Fatal("background synchronization created authentication state", err)
		}
	}
}

func TestReconcileRejectsChangesDuringProviderIO(t *testing.T) {
	for _, kind := range []string{"manual cycle", "departure cycle", "organization cycle", "rotation", "authorization", "binding", "fresh login"} {
		t.Run(kind, func(t *testing.T) {
			store, apps, directory, verifier, app, member := reconciliationFixture(t)
			directory.provider = directoryDingTalkFunc(func(context.Context, string, string, string, string) (dingtalk.Member, error) {
				switch kind {
				case "manual cycle":
					for _, blocked := range []bool{true, false} {
						if _, err := store.SetManualBlock(t.Context(), app.OrganizationID, member.ID, blocked); err != nil {
							t.Fatal(err)
						}
					}
				case "departure cycle":
					for _, departed := range []bool{true, false} {
						if _, err := store.SetExternalDeparture(t.Context(), app.OrganizationID, member.ID, departed); err != nil {
							t.Fatal(err)
						}
					}
				case "organization cycle":
					for _, status := range []string{"disabled", "enabled"} {
						if _, err := store.UpdateOrganization(t.Context(), app.OrganizationID, OrganizationChange{Status: &status}); err != nil {
							t.Fatal(err)
						}
					}
				case "rotation":
					if _, err := apps.Configure(t.Context(), app.OrganizationID, DingTalkApplicationInput{CorpID: app.CorpID, ClientID: app.ClientID, ClientSecret: "new-synthetic-secret", ExpectedRevision: app.Revision}); err != nil {
						t.Fatal(err)
					}
				case "authorization":
					if _, err := apps.SynchronizeAuthorization(t.Context(), app.OrganizationID); err != nil {
						t.Fatal(err)
					}
				case "binding":
					bindings, err := store.Bindings(t.Context(), app.OrganizationID, member.ID)
					if err != nil || len(bindings) != 1 {
						t.Fatal(err)
					}
					if err := store.RevokeBinding(t.Context(), app.OrganizationID, member.ID, bindings[0].FactorID); err != nil {
						t.Fatal(err)
					}
				case "fresh login":
					current, err := verifier.Application(t.Context(), app.OrganizationID)
					if err != nil {
						t.Fatal(err)
					}
					if _, err := admitLogin(t.Context(), verifier, verifiedLogin(t, verifier, current)); err != nil {
						t.Fatal(err)
					}
				}
				return dingtalk.Member{}, dingtalk.ErrNotMember
			})
			result, err := directory.Reconcile(t.Context(), app.OrganizationID)
			if !errors.Is(err, ErrSynchronizationIncomplete) || result.Conflicts != 1 || result.Departed != 0 {
				t.Fatal("stale result applied", err)
			}
			current, err := store.Member(t.Context(), app.OrganizationID, member.ID)
			if err != nil || current.Status != "active" {
				t.Fatal("stale result blocked Member", err)
			}
		})
	}
}

func TestReconcileDoesNotInferDepartureOrReassignIdentifiers(t *testing.T) {
	store, _, directory, _, app, member := reconciliationFixture(t)
	for _, kind := range []string{"unknown", "conflict", "changed identifier"} {
		t.Run(kind, func(t *testing.T) {
			directory.provider = directoryDingTalkFunc(func(context.Context, string, string, string, string) (dingtalk.Member, error) {
				switch kind {
				case "unknown":
					return dingtalk.Member{}, dingtalk.ErrUnavailable
				case "conflict":
					return dingtalk.Member{}, dingtalk.ErrIdentityConflict
				}
				return dingtalk.Member{UnionID: "example-union", UserID: "changed-employee"}, nil
			})
			result, err := directory.Reconcile(t.Context(), app.OrganizationID)
			if !errors.Is(err, ErrSynchronizationIncomplete) || result.Present+result.Departed != 0 {
				t.Fatal("uncertain identity was applied", err)
			}
			current, err := store.Member(t.Context(), app.OrganizationID, member.ID)
			if err != nil || current.Status != "active" {
				t.Fatal("uncertain lookup inferred departure", err)
			}
			var employee string
			if err := store.pool.QueryRow(t.Context(), "SELECT external_member_id FROM dingtalk_identities WHERE member_id=$1", member.ID).Scan(&employee); err != nil || employee != "example-employee" {
				t.Fatal("synchronization reassigned identity", err)
			}
		})
	}
}

func TestReconcilePaginatesAndContinuesAfterUnknownFailures(t *testing.T) {
	store, _, directory, verifier, app, _ := reconciliationFixture(t)
	for index := 1; index <= 100; index++ {
		verifier.provider = loginDingTalkFunc(func(context.Context, string, string, string, string) (dingtalk.Member, error) {
			return dingtalk.Member{UnionID: fmt.Sprintf("union-%d", index), UserID: fmt.Sprintf("employee-%d", index)}, nil
		})
		if _, err := admitLogin(t.Context(), verifier, verifiedLogin(t, verifier, app)); err != nil {
			t.Fatal(err)
		}
	}
	directory.provider = directoryDingTalkFunc(func(_ context.Context, _, _, _, union string) (dingtalk.Member, error) {
		if union == "example-union" {
			return dingtalk.Member{}, dingtalk.ErrUnavailable
		}
		var index int
		if _, err := fmt.Sscanf(union, "union-%d", &index); err != nil {
			t.Fatal(err)
		}
		return dingtalk.Member{UnionID: union, UserID: fmt.Sprintf("employee-%d", index)}, nil
	})
	result, err := directory.Reconcile(t.Context(), app.OrganizationID)
	if !errors.Is(err, ErrSynchronizationIncomplete) || result.Checked != 101 || result.Present != 100 || result.Unavailable != 1 {
		t.Fatal("pagination or partial failure lost Members", result, err)
	}
	var count int
	if err := store.pool.QueryRow(t.Context(), "SELECT count(*) FROM members WHERE external_departure").Scan(&count); err != nil || count != 0 {
		t.Fatal("unknown lookup marked departure", err)
	}
}

func TestReconcileApplicationDenialStopsMemberWork(t *testing.T) {
	_, apps, directory, _, app, _ := reconciliationFixture(t)
	calls := 0
	directory.provider = directoryDingTalkFunc(func(context.Context, string, string, string, string) (dingtalk.Member, error) {
		calls++
		return dingtalk.Member{}, dingtalk.ErrAuthorizationDenied
	})
	result, err := directory.Reconcile(t.Context(), app.OrganizationID)
	if err != nil || result.Application.AuthorizationStatus != "revoked" || calls != 1 {
		t.Fatal("directory denial not recorded", err)
	}
	apps.checker = checkDingTalkFunc(func(context.Context, string, string, string) error { return dingtalk.ErrAuthorizationDenied })
	result, err = directory.Reconcile(t.Context(), app.OrganizationID)
	if err != nil || result.Application.AuthorizationStatus != "revoked" || result.Checked != 0 || calls != 1 {
		t.Fatal("revoked application queried Members", err)
	}
}

func TestReconciliationPassContinuesAcrossOrganizations(t *testing.T) {
	store, apps, first, _ := applicationFixture(t)
	organizations := []Organization{first}
	for range 2 {
		organization, _ := organizationAndMember(t, store)
		organizations = append(organizations, organization)
	}
	for index, organization := range organizations {
		if _, err := apps.Configure(t.Context(), organization.ID, DingTalkApplicationInput{CorpID: "example-corp", ClientID: fmt.Sprintf("client-%d", index), ClientSecret: "synthetic-secret"}); err != nil {
			t.Fatal(err)
		}
	}
	disabled := "disabled"
	if _, err := store.UpdateOrganization(t.Context(), organizations[2].ID, OrganizationChange{Status: &disabled}); err != nil {
		t.Fatal(err)
	}
	calls := map[string]int{}
	apps.checker = checkDingTalkFunc(func(_ context.Context, _, client, _ string) error {
		calls[client]++
		if client == "client-0" {
			return dingtalk.ErrUnavailable
		}
		return nil
	})
	directory, err := NewDingTalkDirectory(apps, directoryDingTalkFunc(func(context.Context, string, string, string, string) (dingtalk.Member, error) {
		t.Fatal("reconciliation invented a Member")
		return dingtalk.Member{}, nil
	}))
	if err != nil {
		t.Fatal(err)
	}
	if err := directory.reconcileAll(t.Context()); !errors.Is(err, ErrSynchronizationIncomplete) {
		t.Fatal("partial application failure reported complete", err)
	}
	if calls["client-0"] != 1 || calls["client-1"] != 1 || calls["client-2"] != 0 {
		t.Fatal("one application failure prevented another check or checked a disabled organization")
	}
}
