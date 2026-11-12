//go:build integration

package identity

import (
	"context"
	"crypto/rand"
	"errors"
	"testing"

	"github.com/euyuil/memberid/internal/dingtalk"
)

func TestDingTalkAuthorizationEvidenceAndPhoneEligibility(t *testing.T) {
	store, apps, organization, _ := applicationFixture(t)
	input := DingTalkApplicationInput{CorpID: "example-corp", ClientID: "example-client", ClientSecret: rand.Text()}
	initial, err := apps.Configure(t.Context(), organization.ID, input)
	if err != nil {
		t.Fatal(err)
	}
	member, err := store.CreateMember(t.Context(), organization.ID, "", "Example member")
	if err != nil {
		t.Fatal(err)
	}
	factor, err := store.EnsureFactor(t.Context(), "phone", "phone:e164", "+8613800000000")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = store.BindFactor(t.Context(), organization.ID, member.ID, factor.ID); err != nil {
		t.Fatal(err)
	}
	other, otherMember := organizationAndMember(t, store)
	if _, err = store.BindFactor(t.Context(), other.ID, otherMember.ID, factor.ID); err != nil {
		t.Fatal(err)
	}
	apps.checker = checkDingTalkFunc(func(context.Context, string, string, string) error { return dingtalk.ErrUnavailable })
	if _, err = apps.SynchronizeAuthorization(t.Context(), organization.ID); !errors.Is(err, ErrProviderUnavailable) {
		t.Fatal(err)
	}
	unchanged, err := apps.Inspect(t.Context(), organization.ID)
	if err != nil || unchanged != initial {
		t.Fatal("outage changed stored authorization", err)
	}
	apps.checker = checkDingTalkFunc(func(context.Context, string, string, string) error { return dingtalk.ErrAuthorizationDenied })
	revoked, err := apps.SynchronizeAuthorization(t.Context(), organization.ID)
	if err != nil || revoked.AuthorizationStatus != "revoked" || revoked.AuthorizationRevision != initial.AuthorizationRevision+1 || revoked.Revision != initial.Revision {
		t.Fatal("denial did not record separate authorization revision", err)
	}
	if value, err := store.Eligibility(t.Context(), organization.ID, member.ID, factor.ID, "phone"); err != nil || value.Eligible {
		t.Fatal("phone bypassed confirmed organization revocation", err)
	}
	if _, err := MemberEvidence(t.Context(), store.pool, factor.ID, member.ID, organization.ID); !errors.Is(err, ErrNotFound) {
		t.Fatal("issuance evidence bypassed revocation", err)
	}
	choices, err := store.EligibleMembers(t.Context(), factor.ID)
	if err != nil || len(choices) != 1 || choices[0].ID != otherMember.ID {
		t.Fatal("revocation crossed organization boundary", err)
	}
	// An invalid replacement credential is not evidence about the stored credential.
	input.ExpectedRevision = initial.Revision
	input.ClientSecret = rand.Text()
	if _, err := apps.Configure(t.Context(), organization.ID, input); !errors.Is(err, ErrProviderUnavailable) {
		t.Fatal(err)
	}
	current, err := apps.Inspect(t.Context(), organization.ID)
	if err != nil || current != revoked {
		t.Fatal("failed candidate modified authorization", err)
	}
	if _, err = store.SetManualBlock(t.Context(), organization.ID, member.ID, true); err != nil {
		t.Fatal(err)
	}
	apps.checker = checkDingTalkFunc(func(context.Context, string, string, string) error { return nil })
	active, err := apps.SynchronizeAuthorization(t.Context(), organization.ID)
	if err != nil || active.AuthorizationStatus != "active" || active.AuthorizationRevision != revoked.AuthorizationRevision+1 || active.AuthorizationVerifiedAt.Before(revoked.AuthorizationVerifiedAt) {
		t.Fatal("fresh authorization not restored", err)
	}
	if value, err := store.Eligibility(t.Context(), organization.ID, member.ID, factor.ID, "phone"); err != nil || value.Eligible {
		t.Fatal("authorization recovery removed manual block", err)
	}
	if _, err = store.SetManualBlock(t.Context(), organization.ID, member.ID, false); err != nil {
		t.Fatal(err)
	}
	if value, err := store.Eligibility(t.Context(), organization.ID, member.ID, factor.ID, "phone"); err != nil || !value.Eligible {
		t.Fatal("fresh recovery did not restore eligible identity", err)
	}
}

func TestDingTalkAuthorizationRejectsSupersededObservations(t *testing.T) {
	for _, kind := range []string{"observation", "rotation", "lifecycle"} {
		t.Run(kind, func(t *testing.T) {
			store, apps, organization, key := applicationFixture(t)
			input := DingTalkApplicationInput{CorpID: "example-corp", ClientID: "example-client", ClientSecret: rand.Text()}
			app, err := apps.Configure(t.Context(), organization.ID, input)
			if err != nil {
				t.Fatal(err)
			}
			started := make(chan struct{})
			release := make(chan struct{})
			slow, err := NewDingTalkApplications(store, key, checkDingTalkFunc(func(context.Context, string, string, string) error {
				close(started)
				<-release
				return dingtalk.ErrAuthorizationDenied
			}))
			if err != nil {
				t.Fatal(err)
			}
			result := make(chan error, 1)
			go func() { _, err := slow.SynchronizeAuthorization(t.Context(), organization.ID); result <- err }()
			<-started
			switch kind {
			case "observation":
				_, err = apps.SynchronizeAuthorization(t.Context(), organization.ID)
			case "rotation":
				input.ExpectedRevision = app.Revision
				input.ClientSecret = rand.Text()
				_, err = apps.Configure(t.Context(), organization.ID, input)
			case "lifecycle":
				for _, status := range []string{"disabled", "enabled"} {
					if _, err = store.UpdateOrganization(t.Context(), organization.ID, OrganizationChange{Status: &status}); err != nil {
						break
					}
				}
			}
			close(release)
			if err != nil {
				t.Fatal(err)
			}
			if err := <-result; !errors.Is(err, ErrConflict) {
				t.Fatal("stale denial overwrote a newer decision", err)
			}
			current, err := apps.Inspect(t.Context(), organization.ID)
			if err != nil || current.AuthorizationStatus != "active" {
				t.Fatal("stale result changed eligibility", err)
			}
		})
	}
}

func TestDingTalkLoginRecordsOnlyCurrentAuthorizationDenial(t *testing.T) {
	for _, kind := range []string{"denied", "outage", "superseded"} {
		t.Run(kind, func(t *testing.T) {
			_, apps, verifier, app := verifierFixture(t)
			verifier.provider = loginDingTalkFunc(func(context.Context, string, string, string, string) (dingtalk.Member, error) {
				if kind == "outage" {
					return dingtalk.Member{}, dingtalk.ErrUnavailable
				}
				if kind == "superseded" {
					if _, err := apps.SynchronizeAuthorization(t.Context(), app.OrganizationID); err != nil {
						return dingtalk.Member{}, err
					}
				}
				return dingtalk.Member{}, dingtalk.ErrAuthorizationDenied
			})
			_, err := verifier.Verify(t.Context(), app.LoginContext(), "synthetic-code")
			want := ErrIneligible
			if kind == "outage" {
				want = ErrProviderUnavailable
			}
			if kind == "superseded" {
				want = ErrConflict
			}
			if !errors.Is(err, want) {
				t.Fatal("incorrect denied login result", err)
			}
			current, err := apps.Inspect(t.Context(), app.OrganizationID)
			if err != nil {
				t.Fatal(err)
			}
			if (current.AuthorizationStatus == "revoked") != (kind == "denied") {
				t.Fatal("invalid authorization observation")
			}
			if kind == "denied" {
				if _, err := verifier.Application(t.Context(), app.OrganizationID); !errors.Is(err, ErrIneligible) {
					t.Fatal("revoked application offered login", err)
				}
			}
		})
	}
}

func TestDingTalkLoginProofDoesNotSurviveOrganizationDisablement(t *testing.T) {
	store, _, verifier, app := verifierFixture(t)
	proof := verifiedLogin(t, verifier, app)
	for _, status := range []string{"disabled", "enabled"} {
		if _, err := store.UpdateOrganization(t.Context(), app.OrganizationID, OrganizationChange{Status: &status}); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := admitLogin(t.Context(), verifier, proof); !errors.Is(err, ErrIneligible) {
		t.Fatal("old proof survived disable and re-enable", err)
	}
	if _, err := verifier.Verify(t.Context(), app.LoginContext(), "synthetic-code"); !errors.Is(err, ErrIneligible) {
		t.Fatal("old callback survived disable and re-enable", err)
	}
	current, err := verifier.Application(t.Context(), app.OrganizationID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := admitLogin(t.Context(), verifier, verifiedLogin(t, verifier, current)); err != nil {
		t.Fatal("fresh login could not use re-enabled organization", err)
	}
}

func TestDingTalkConfigurationRecoveryAndObservationConflict(t *testing.T) {
	store, apps, organization, key := applicationFixture(t)
	input := DingTalkApplicationInput{CorpID: "example-corp", ClientID: "example-client", ClientSecret: rand.Text()}
	first, err := apps.Configure(t.Context(), organization.ID, input)
	if err != nil {
		t.Fatal(err)
	}
	apps.checker = checkDingTalkFunc(func(context.Context, string, string, string) error { return dingtalk.ErrAuthorizationDenied })
	revoked, err := apps.SynchronizeAuthorization(t.Context(), organization.ID)
	if err != nil {
		t.Fatal(err)
	}
	input.ExpectedRevision = first.Revision
	apps.checker = checkDingTalkFunc(func(context.Context, string, string, string) error { return nil })
	recovered, err := apps.Configure(t.Context(), organization.ID, input)
	if err != nil || recovered.AuthorizationStatus != "active" || recovered.Revision != first.Revision || recovered.AuthorizationRevision != revoked.AuthorizationRevision+1 || recovered.Namespace != first.Namespace {
		t.Fatal("recovery changed credentials or stable binding", err)
	}
	started := make(chan struct{})
	release := make(chan struct{})
	slow, err := NewDingTalkApplications(store, key, checkDingTalkFunc(func(context.Context, string, string, string) error { close(started); <-release; return nil }))
	if err != nil {
		t.Fatal(err)
	}
	input.ClientSecret = rand.Text()
	result := make(chan error, 1)
	go func() { _, err := slow.Configure(t.Context(), organization.ID, input); result <- err }()
	<-started
	apps.checker = checkDingTalkFunc(func(context.Context, string, string, string) error { return dingtalk.ErrAuthorizationDenied })
	_, syncErr := apps.SynchronizeAuthorization(t.Context(), organization.ID)
	close(release)
	if syncErr != nil {
		t.Fatal(syncErr)
	}
	if err := <-result; !errors.Is(err, ErrConflict) {
		t.Fatal("late configuration overwrote newer authorization", err)
	}
	current, err := apps.Inspect(t.Context(), organization.ID)
	if err != nil || current.AuthorizationStatus != "revoked" || current.Revision != first.Revision {
		t.Fatal("stale configuration changed stored state", err)
	}
}
