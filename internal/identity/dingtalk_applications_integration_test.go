//go:build integration

package identity

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

type checkDingTalkFunc func(context.Context, string, string, string) error

func (fn checkDingTalkFunc) CheckAuthorization(ctx context.Context, corp, client, secret string) error {
	return fn(ctx, corp, client, secret)
}

func applicationFixture(t *testing.T) (*Store, *DingTalkApplications, Organization, []byte) {
	t.Helper()
	store := testStore(t)
	organization, _ := organizationAndMember(t, store)
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}
	apps, err := NewDingTalkApplications(store, key, checkDingTalkFunc(func(context.Context, string, string, string) error { return nil }))
	if err != nil {
		t.Fatal(err)
	}
	return store, apps, organization, key
}

func TestDingTalkConfigurationEncryptionAndRotation(t *testing.T) {
	store, apps, organization, key := applicationFixture(t)
	input := DingTalkApplicationInput{CorpID: "example-corp", ClientID: "example-client", ClientSecret: rand.Text()}
	first, err := apps.Configure(t.Context(), OperatorPrincipal(), organization.ID, input)
	if err != nil || first.Revision != 1 || first.Namespace == "" {
		t.Fatal("initial configuration failed", err)
	}
	loaded, err := apps.Load(t.Context(), organization.ID)
	if err != nil || loaded.Secret != input.ClientSecret || loaded.DingTalkApplication != first {
		t.Fatal("credential load failed", err)
	}
	encoded, err := json.Marshal(loaded)
	if err != nil || bytes.Contains(encoded, []byte(input.ClientSecret)) || bytes.Contains(encoded, []byte("Secret")) {
		t.Fatal("credential leaked to JSON")
	}
	var encrypted []byte
	if err := store.pool.QueryRow(t.Context(), "SELECT secret_ciphertext FROM dingtalk_applications WHERE organization_id=$1", organization.ID).Scan(&encrypted); err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(encrypted, []byte(input.ClientSecret)) {
		t.Fatal("plaintext stored in database")
	}
	wrongKey := append([]byte(nil), key...)
	wrongKey[0] ^= 1
	wrong, err := NewDingTalkApplications(store, wrongKey, apps.checker)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := wrong.Load(t.Context(), organization.ID); !errors.Is(err, ErrProviderConfiguration) {
		t.Fatal("wrong encryption key accepted", err)
	}
	if inspected, err := wrong.Inspect(t.Context(), organization.ID); err != nil || inspected != first {
		t.Fatal("metadata unexpectedly needs decryption", err)
	}
	input.ExpectedRevision = 1
	same, err := apps.Configure(t.Context(), OperatorPrincipal(), organization.ID, input)
	if err != nil || same != first {
		t.Fatal("unchanged credentials changed identity", err)
	}
	for _, change := range []func(*DingTalkApplicationInput){func(v *DingTalkApplicationInput) { v.CorpID = "different-corp" }, func(v *DingTalkApplicationInput) { v.ClientID = "different-client" }, func(v *DingTalkApplicationInput) { v.ExpectedRevision = 0 }} {
		different := input
		change(&different)
		if _, err := apps.Configure(t.Context(), OperatorPrincipal(), organization.ID, different); !errors.Is(err, ErrConflict) {
			t.Fatal("binding or stale revision accepted", err)
		}
	}
	input.ClientSecret = rand.Text()
	second, err := apps.Configure(t.Context(), OperatorPrincipal(), organization.ID, input)
	if err != nil || second.Revision != 2 || second.Namespace != first.Namespace || second.CreatedAt != first.CreatedAt {
		t.Fatal("rotation changed identity", err)
	}
	restart, err := NewDingTalkApplications(store, key, apps.checker)
	if err != nil {
		t.Fatal(err)
	}
	loaded, err = restart.Load(t.Context(), organization.ID)
	if err != nil || loaded.Secret != input.ClientSecret {
		t.Fatal("rotated credential lost across restart", err)
	}
	// Old ciphertext cannot be substituted at a new configuration revision.
	if _, err := store.pool.Exec(t.Context(), "UPDATE dingtalk_applications SET secret_ciphertext=$2 WHERE organization_id=$1", organization.ID, encrypted); err != nil {
		t.Fatal(err)
	}
	if _, err := apps.Load(t.Context(), organization.ID); !errors.Is(err, ErrProviderConfiguration) {
		t.Fatal("old credential replay accepted", err)
	}
}

func TestDingTalkConfigurationRejectionPreservesStoredApplication(t *testing.T) {
	store, apps, organization, _ := applicationFixture(t)
	input := DingTalkApplicationInput{CorpID: "example-corp", ClientID: "example-client", ClientSecret: rand.Text()}
	apps.checker = checkDingTalkFunc(func(context.Context, string, string, string) error { return errors.New("private provider failure") })
	if _, err := apps.Configure(t.Context(), OperatorPrincipal(), organization.ID, input); err != ErrProviderUnavailable {
		t.Fatal("provider failure disclosed", err)
	}
	if _, err := apps.Inspect(t.Context(), organization.ID); !errors.Is(err, ErrNotFound) {
		t.Fatal("failed authorization stored configuration", err)
	}
	apps.checker = checkDingTalkFunc(func(context.Context, string, string, string) error { return nil })
	first, err := apps.Configure(t.Context(), OperatorPrincipal(), organization.ID, input)
	if err != nil {
		t.Fatal(err)
	}
	apps.checker = checkDingTalkFunc(func(context.Context, string, string, string) error { return errors.New("denied candidate credentials") })
	input.ExpectedRevision = 1
	input.ClientSecret = rand.Text()
	if _, err := apps.Configure(t.Context(), OperatorPrincipal(), organization.ID, input); err != ErrProviderUnavailable {
		t.Fatal(err)
	}
	retained, err := apps.Inspect(t.Context(), organization.ID)
	if err != nil || retained != first {
		t.Fatal("failed candidate changed current configuration", err)
	}
	disabled := "disabled"
	if _, err := store.UpdateOrganization(t.Context(), OperatorPrincipal(), organization.ID, OrganizationChange{Status: &disabled}); err != nil {
		t.Fatal(err)
	}
	if _, err := apps.Configure(t.Context(), OperatorPrincipal(), organization.ID, input); !errors.Is(err, ErrIneligible) {
		t.Fatal("disabled organization changed", err)
	}
	if _, err := apps.Configure(t.Context(), OperatorPrincipal(), "invalid", input); !errors.Is(err, ErrInvalid) {
		t.Fatal(err)
	}
	input.ExpectedRevision = -1
	if _, err := apps.Configure(t.Context(), OperatorPrincipal(), organization.ID, input); !errors.Is(err, ErrInvalid) {
		t.Fatal(err)
	}
}

func TestDingTalkCiphertextCannotCrossOrganizations(t *testing.T) {
	store, apps, firstOrganization, _ := applicationFixture(t)
	secondOrganization, _ := organizationAndMember(t, store)
	input := DingTalkApplicationInput{CorpID: "example-corp", ClientID: "first-client", ClientSecret: rand.Text()}
	first, err := apps.Configure(t.Context(), OperatorPrincipal(), firstOrganization.ID, input)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := apps.Configure(t.Context(), OperatorPrincipal(), secondOrganization.ID, input); !errors.Is(err, ErrConflict) {
		t.Fatal("application registration reused across organizations", err)
	}
	input.ClientID = "second-client"
	second, err := apps.Configure(t.Context(), OperatorPrincipal(), secondOrganization.ID, input)
	if err != nil || second.Namespace == first.Namespace {
		t.Fatal("organizations share a provider namespace", err)
	}
	if _, err := store.pool.Exec(t.Context(), "UPDATE dingtalk_applications SET secret_ciphertext=(SELECT secret_ciphertext FROM dingtalk_applications WHERE organization_id=$1) WHERE organization_id=$2", firstOrganization.ID, secondOrganization.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := apps.Load(t.Context(), secondOrganization.ID); !errors.Is(err, ErrProviderConfiguration) {
		t.Fatal("cross-organization ciphertext accepted", err)
	}
}

func TestDingTalkConcurrentConfigurationChecksRevisionAfterProviderIO(t *testing.T) {
	for _, initial := range []bool{true, false} {
		t.Run(map[bool]string{true: "initial", false: "rotation"}[initial], func(t *testing.T) {
			store, apps, organization, _ := applicationFixture(t)
			input := DingTalkApplicationInput{CorpID: "example-corp", ClientID: "example-client", ClientSecret: rand.Text()}
			if !initial {
				if _, err := apps.Configure(t.Context(), OperatorPrincipal(), organization.ID, input); err != nil {
					t.Fatal(err)
				}
				input.ExpectedRevision = 1
			}
			started := make(chan struct{}, 2)
			release := make(chan struct{})
			apps.checker = checkDingTalkFunc(func(context.Context, string, string, string) error { started <- struct{}{}; <-release; return nil })
			results := make(chan error, 2)
			for range 2 {
				candidate := input
				candidate.ClientSecret = rand.Text()
				go func() {
					_, err := apps.Configure(t.Context(), OperatorPrincipal(), organization.ID, candidate)
					results <- err
				}()
			}
			<-started
			<-started
			// A database operation can complete while both external checks wait.
			if _, err := store.Organization(t.Context(), organization.ID); err != nil {
				t.Fatal(err)
			}
			close(release)
			accepted, rejected := 0, 0
			for range 2 {
				err := <-results
				if err == nil {
					accepted++
				} else if errors.Is(err, ErrConflict) {
					rejected++
				} else {
					t.Fatal(err)
				}
			}
			if accepted != 1 || rejected != 1 {
				t.Fatal("concurrent configuration overwrote an accepted decision")
			}
		})
	}
}

func TestDingTalkConfigurationRechecksOrganizationAfterProviderIO(t *testing.T) {
	store, apps, organization, _ := applicationFixture(t)
	apps.checker = checkDingTalkFunc(func(ctx context.Context, _, _, _ string) error {
		disabled := "disabled"
		_, err := store.UpdateOrganization(ctx, OperatorPrincipal(), organization.ID, OrganizationChange{Status: &disabled})
		return err
	})
	if _, err := apps.Configure(t.Context(), OperatorPrincipal(), organization.ID, DingTalkApplicationInput{CorpID: "example-corp", ClientID: "example-client", ClientSecret: strings.Repeat("x", 32)}); !errors.Is(err, ErrIneligible) {
		t.Fatal("disabled organization accepted slow authorization", err)
	}
	if _, err := apps.Inspect(t.Context(), organization.ID); !errors.Is(err, ErrNotFound) {
		t.Fatal("rejected configuration left data", err)
	}
}
