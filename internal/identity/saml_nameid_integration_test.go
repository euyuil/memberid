//go:build integration

package identity

import (
	"errors"
	"fmt"
	"sync"
	"testing"

	"github.com/jackc/pgx/v5"
)

func nameIDProvider(t *testing.T, store *Store, organizationID, id, format string) SAMLServiceProvider {
	t.Helper()
	sp, err := store.PutSAMLServiceProvider(t.Context(), OperatorPrincipal(), SAMLServiceProvider{OrganizationID: organizationID, EntityID: "https://" + id + ".example.test", ACSURL: "https://sp.example.test/acs", NameIDFormat: format, AllowUnsignedRequests: true, Enabled: true}, false)
	if err != nil {
		t.Fatal(err)
	}
	return sp
}

func allocateNameID(t *testing.T, store *Store, sp SAMLServiceProvider, memberID string) (string, error) {
	t.Helper()
	var value string
	err := pgx.BeginFunc(t.Context(), store.pool, func(tx pgx.Tx) error {
		locked, err := LockSAMLServiceProvider(t.Context(), tx, sp.ID)
		if err != nil {
			return err
		}
		value, err = SAMLNameID(t.Context(), tx, locked, memberID, true)
		return err
	})
	return value, err
}

func TestSAMLNameIDLegacyAuthorityAndPermanentReservation(t *testing.T) {
	store := testStore(t)
	org, member := organizationAndMember(t, store)
	otherOrg, foreign := organizationAndMember(t, store)
	other, err := store.CreateMember(t.Context(), OperatorPrincipal(), org.ID, "", member.DisplayName)
	if err != nil {
		t.Fatal(err)
	}
	sp := nameIDProvider(t, store, org.ID, "legacy", "unspecified")
	provision := func(caller Principal, orgID, memberID, value string, revision int64) (SAMLNameIDMapping, error) {
		return store.ProvisionSAMLNameID(t.Context(), caller, orgID, sp.ID, memberID, value, revision)
	}
	for _, caller := range []Principal{{}, InstallationManagerPrincipal(), ManagementPrincipal(member.ID, "grant"), {kind: accountPrincipal}} {
		if _, err := provision(caller, org.ID, member.ID, "old-account-42", sp.Revision); !errors.Is(err, ErrForbidden) {
			t.Fatal("unauthorized provisioning", err)
		}
		if _, err := store.InspectSAMLNameID(t.Context(), caller, org.ID, sp.ID, member.ID); !errors.Is(err, ErrForbidden) {
			t.Fatal("unauthorized mapping read", err)
		}
	}
	if _, err := store.InspectSAMLNameID(t.Context(), OperatorPrincipal(), org.ID, sp.ID, member.ID); !errors.Is(err, ErrNotFound) {
		t.Fatal("inspect allocated a mapping", err)
	}
	if _, err := provision(OperatorPrincipal(), otherOrg.ID, foreign.ID, "old-account-42", sp.Revision); !errors.Is(err, ErrNotFound) {
		t.Fatal("foreign SP admitted", err)
	}
	if _, err := provision(OperatorPrincipal(), org.ID, foreign.ID, "old-account-42", sp.Revision); !errors.Is(err, ErrNotFound) {
		t.Fatal("foreign Member admitted", err)
	}
	if _, err := provision(OperatorPrincipal(), org.ID, member.ID, "old-account-42", sp.Revision+1); !errors.Is(err, ErrConflict) {
		t.Fatal("stale SP revision admitted", err)
	}
	mapping, err := provision(OperatorPrincipal(), org.ID, member.ID, "old-account-42", sp.Revision)
	if err != nil || mapping.Source != "legacy" || mapping.CreatedBy != "installation-operator" || mapping.NameIDFormat != "unspecified" || mapping.CreatedAt.IsZero() {
		t.Fatal("legacy provenance", mapping, err)
	}
	retry, err := provision(OperatorPrincipal(), org.ID, member.ID, mapping.Value, sp.Revision)
	if err != nil || retry != mapping {
		t.Fatal("exact retry changed immutable mapping", retry, err)
	}
	for _, target := range []struct{ member, value string }{{member.ID, "replacement"}, {other.ID, mapping.Value}} {
		if _, err := provision(OperatorPrincipal(), org.ID, target.member, target.value, sp.Revision); !errors.Is(err, ErrConflict) {
			t.Fatal("replacement or reassignment admitted", err)
		}
	}
	value, err := allocateNameID(t, store, sp, member.ID)
	if err != nil || value != mapping.Value {
		t.Fatal("issuance did not reuse legacy mapping", value, err)
	}
	value, err = allocateNameID(t, store, sp, other.ID)
	if err != nil || value == mapping.Value {
		t.Fatal("shared profile merged Members", value, err)
	}
	if _, err := provision(OperatorPrincipal(), org.ID, other.ID, value, sp.Revision); !errors.Is(err, ErrConflict) {
		t.Fatal("generated mapping was relabeled as legacy", err)
	}
	changed := sp
	changed.NameIDFormat = "persistent"
	if _, err := store.PutSAMLServiceProvider(t.Context(), OperatorPrincipal(), changed, false); !errors.Is(err, ErrConflict) {
		t.Fatal("allocated format changed", err)
	}
	foreignSP := nameIDProvider(t, store, otherOrg.ID, "foreign-legacy", "unspecified")
	if _, err := store.ProvisionSAMLNameID(t.Context(), OperatorPrincipal(), otherOrg.ID, foreignSP.ID, foreign.ID, mapping.Value, foreignSP.Revision); err != nil {
		t.Fatal("independent SP namespace conflated", err)
	}
	sp.Retired = true
	sp, err = store.PutSAMLServiceProvider(t.Context(), OperatorPrincipal(), sp, false)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := provision(OperatorPrincipal(), org.ID, other.ID, "retired-value", sp.Revision); !errors.Is(err, ErrConflict) {
		t.Fatal("retired SP provisioned", err)
	}
	retained, err := store.InspectSAMLNameID(t.Context(), OperatorPrincipal(), org.ID, sp.ID, member.ID)
	if err != nil || retained != mapping {
		t.Fatal("retirement released mapping", retained, err)
	}
	events, err := store.ManagementEvents(t.Context(), org.ID, member.ID, 0)
	if err != nil || len(events) != 1 || events[0].Action != "saml.nameId.provision" || events[0].Actor != "installation-operator" {
		t.Fatal("missing or duplicated audit", events, err)
	}
}

func TestSAMLNameIDFormatAndAuditRollback(t *testing.T) {
	store := testStore(t)
	org, member := organizationAndMember(t, store)
	sp := nameIDProvider(t, store, org.ID, "format", "")
	if sp.NameIDFormat != "persistent" {
		t.Fatal("incorrect default format")
	}
	if _, err := store.ProvisionSAMLNameID(t.Context(), OperatorPrincipal(), org.ID, sp.ID, member.ID, "old-name", sp.Revision); !errors.Is(err, ErrInvalid) {
		t.Fatal("legacy value asserted as persistent pseudonym", err)
	}
	sp.NameIDFormat = "unspecified"
	sp, err := store.PutSAMLServiceProvider(t.Context(), OperatorPrincipal(), sp, false)
	if err != nil {
		t.Fatal("unallocated format update", err)
	}
	if _, err := store.pool.Exec(t.Context(), "ALTER TABLE management_events ADD CONSTRAINT synthetic_nameid_audit_failure CHECK (action <> 'saml.nameId.provision') NOT VALID"); err != nil {
		t.Fatal(err)
	}
	if _, err := store.ProvisionSAMLNameID(t.Context(), OperatorPrincipal(), org.ID, sp.ID, member.ID, "old-name", sp.Revision); err == nil {
		t.Fatal("mapping committed without audit")
	}
	if _, err := store.InspectSAMLNameID(t.Context(), OperatorPrincipal(), org.ID, sp.ID, member.ID); !errors.Is(err, ErrNotFound) {
		t.Fatal("failed audit consumed mapping", err)
	}
}

func TestSAMLNameIDProvisionRacesAllocation(t *testing.T) {
	store := testStore(t)
	org, member := organizationAndMember(t, store)
	for iteration := range 6 {
		sp := nameIDProvider(t, store, org.ID, fmt.Sprintf("race-%d", iteration), "unspecified")
		var value string
		var allocationError, provisionError error
		var group sync.WaitGroup
		group.Go(func() { value, allocationError = allocateNameID(t, store, sp, member.ID) })
		group.Go(func() {
			_, provisionError = store.ProvisionSAMLNameID(t.Context(), OperatorPrincipal(), org.ID, sp.ID, member.ID, "old-name", sp.Revision)
		})
		group.Wait()
		if allocationError != nil || provisionError != nil && !errors.Is(provisionError, ErrConflict) {
			t.Fatal("allocation race", allocationError, provisionError)
		}
		stored, err := store.InspectSAMLNameID(t.Context(), OperatorPrincipal(), org.ID, sp.ID, member.ID)
		if err != nil || stored.Value != value || (provisionError == nil) != (stored.Source == "legacy") {
			t.Fatal("race replaced an allocated identifier", stored, value, err)
		}
	}
}

func TestSAMLNameIDFormatRacesFirstAllocation(t *testing.T) {
	store := testStore(t)
	org, member := organizationAndMember(t, store)
	for iteration := range 6 {
		sp := nameIDProvider(t, store, org.ID, fmt.Sprintf("format-race-%d", iteration), "persistent")
		changed := sp
		changed.NameIDFormat = "unspecified"
		var allocationError, updateError error
		var issuedFormat string
		var group sync.WaitGroup
		group.Go(func() {
			allocationError = pgx.BeginFunc(t.Context(), store.pool, func(tx pgx.Tx) error {
				locked, err := LockSAMLServiceProvider(t.Context(), tx, sp.ID)
				if err != nil {
					return err
				}
				issuedFormat = locked.NameIDFormat
				_, err = SAMLNameID(t.Context(), tx, locked, member.ID, true)
				return err
			})
		})
		group.Go(func() {
			_, updateError = store.PutSAMLServiceProvider(t.Context(), OperatorPrincipal(), changed, false)
		})
		group.Wait()
		if allocationError != nil || updateError != nil && !errors.Is(updateError, ErrConflict) {
			t.Fatal(allocationError, updateError)
		}
		stored, err := store.InspectSAMLNameID(t.Context(), OperatorPrincipal(), org.ID, sp.ID, member.ID)
		if err != nil || stored.NameIDFormat != issuedFormat {
			t.Fatal("format changed after initial allocation", issuedFormat, stored, err)
		}
	}
}
