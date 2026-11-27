//go:build integration

package identity

import (
	"encoding/json"
	"errors"
	"sync"
	"testing"
	"time"
)

func TestSAMLManagementScopeLifecycleAndAudit(t *testing.T) {
	store := testStore(t)
	org, ordinary := organizationAndMember(t, store)
	other, _ := organizationAndMember(t, store)
	admin, factor := administratorMember(t, store, org.ID, 91)
	platform, platformFactor := administratorMember(t, store, store.SystemOrganizationID(), 92)
	principal := administratorActor(t, store, admin, factor).Principal()
	platformPrincipal := administratorActor(t, store, platform, platformFactor).Principal()
	service := NewManagementService(store, nil, nil, time.Hour)
	sp := SAMLServiceProvider{DisplayName: "Example application", EntityID: "https://sp.example.test/metadata", OrganizationID: org.ID, ACSURL: "https://sp.example.test/acs", Enabled: true, AllowUnsignedRequests: true}
	for _, caller := range []Principal{{}, OperatorPrincipal(), InstallationManagerPrincipal(), ManagementPrincipal(ordinary.ID, "synthetic-grant")} {
		if _, err := service.PutSAMLServiceProvider(t.Context(), caller, sp); !errors.Is(err, ErrForbidden) {
			t.Fatal("unadmitted caller changed trust", err)
		}
	}
	var err error
	sp, err = service.PutSAMLServiceProvider(t.Context(), principal, sp)
	if err != nil || sp.Revision != 1 {
		t.Fatal(sp, err)
	}
	foreign := sp
	foreign.ID, foreign.EntityID, foreign.OrganizationID, foreign.Revision = "", "https://other.example.test/metadata", other.ID, 0
	if _, err := service.PutSAMLServiceProvider(t.Context(), principal, foreign); !errors.Is(err, ErrForbidden) {
		t.Fatal("cross-organization create", err)
	}
	foreign, err = service.PutSAMLServiceProvider(t.Context(), platformPrincipal, foreign)
	if err != nil {
		t.Fatal(err)
	}
	for _, operation := range []func() error{
		func() error {
			_, err := service.SAMLServiceProviders(t.Context(), principal, other.ID, "", 50)
			return err
		},
		func() error {
			_, err := service.SAMLServiceProvider(t.Context(), principal, other.ID, foreign.ID)
			return err
		},
		func() error { _, err := service.PutSAMLServiceProvider(t.Context(), principal, foreign); return err },
		func() error {
			_, err := service.RetireSAMLServiceProvider(t.Context(), principal, other.ID, foreign.ID, foreign.Revision)
			return err
		},
	} {
		if err := operation(); !errors.Is(err, ErrForbidden) {
			t.Fatal("foreign registration accessible", err)
		}
	}
	if _, err := service.SAMLServiceProvider(t.Context(), principal, org.ID, foreign.ID); !errors.Is(err, ErrNotFound) {
		t.Fatal("foreign identifier disclosed", err)
	}
	forged := foreign
	forged.OrganizationID = org.ID
	if _, err := service.PutSAMLServiceProvider(t.Context(), principal, forged); !errors.Is(err, ErrNotFound) {
		t.Fatal("registration moved between organizations", err)
	}
	if _, err := service.RetireSAMLServiceProvider(t.Context(), principal, org.ID, foreign.ID, foreign.Revision); !errors.Is(err, ErrNotFound) {
		t.Fatal("foreign registration retired", err)
	}
	page, err := service.SAMLServiceProviders(t.Context(), principal, org.ID, "", 1)
	if err != nil || len(page.Items) != 1 || page.Items[0].ID != sp.ID {
		t.Fatal(page, err)
	}
	duplicate := sp
	duplicate.ID, duplicate.Revision = "", 0
	if _, err := service.PutSAMLServiceProvider(t.Context(), principal, duplicate); !errors.Is(err, ErrConflict) {
		t.Fatal("duplicate entity ID accepted", err)
	}
	sp.Enabled = false
	sp.DisplayName = "Renamed application"
	sp, err = service.PutSAMLServiceProvider(t.Context(), platformPrincipal, sp)
	if err != nil || sp.Enabled {
		t.Fatal(sp, err)
	}
	sp, err = service.RetireSAMLServiceProvider(t.Context(), principal, org.ID, sp.ID, sp.Revision)
	if err != nil || !sp.Retired || sp.Enabled {
		t.Fatal(sp, err)
	}
	sp.Retired = false
	if _, err := service.PutSAMLServiceProvider(t.Context(), principal, sp); !errors.Is(err, ErrConflict) {
		t.Fatal("retired registration restored", err)
	}
	if _, err := service.PutSAMLServiceProvider(t.Context(), principal, duplicate); !errors.Is(err, ErrConflict) {
		t.Fatal("retired entity ID reassigned", err)
	}
	history, err := store.ManagementEvents(t.Context(), org.ID, "", 0)
	if err != nil {
		t.Fatal(err)
	}
	var writes []ManagementEvent
	for _, event := range history {
		if event.Action == "saml.serviceProvider.configure" {
			writes = append(writes, event)
		}
	}
	if len(writes) != 3 || writes[0].Actor != admin.ID || writes[1].Actor != platform.ID || writes[2].Actor != admin.ID {
		t.Fatal("audit actor or rejected-write boundary", writes)
	}
	var previous, changes SAMLServiceProvider
	if json.Unmarshal(writes[1].Previous, &previous) != nil || json.Unmarshal(writes[1].Changes, &changes) != nil || previous.DisplayName != "Example application" || changes.DisplayName != "Renamed application" || writes[1].Snapshot.TargetName != changes.DisplayName {
		t.Fatal("audit did not preserve before/after", writes[1])
	}
	// A formerly valid console principal loses authority on its next operation.
	if _, err := store.pool.Exec(t.Context(), "UPDATE oidc_grants SET revoked_at=clock_timestamp() WHERE id=$1", principal.grantID); err != nil {
		t.Fatal(err)
	}
	if _, err := service.SAMLServiceProviders(t.Context(), principal, org.ID, "", 50); !errors.Is(err, ErrManagementSession) {
		t.Fatal("revoked grant retained read access", err)
	}
	duplicate.EntityID = "https://new.example.test"
	if _, err := service.PutSAMLServiceProvider(t.Context(), principal, duplicate); !errors.Is(err, ErrManagementSession) {
		t.Fatal("revoked grant retained write access", err)
	}
}

func TestSAMLManagementConcurrencyPaginationAndAuditRollback(t *testing.T) {
	store := testStore(t)
	org, _ := organizationAndMember(t, store)
	admin, factor := administratorMember(t, store, org.ID, 93)
	principal := administratorActor(t, store, admin, factor).Principal()
	service := NewManagementService(store, nil, nil, time.Hour)
	sp, err := service.PutSAMLServiceProvider(t.Context(), principal, SAMLServiceProvider{EntityID: "https://a.example.test", OrganizationID: org.ID, ACSURL: "https://a.example.test/acs", Enabled: true, AllowUnsignedRequests: true})
	if err != nil {
		t.Fatal(err)
	}
	var group sync.WaitGroup
	outcomes := make(chan error, 2)
	for _, enabled := range []bool{true, false} {
		group.Go(func() {
			change := sp
			change.Enabled = enabled
			_, err := service.PutSAMLServiceProvider(t.Context(), principal, change)
			outcomes <- err
		})
	}
	group.Wait()
	close(outcomes)
	succeeded, conflicts := 0, 0
	for err := range outcomes {
		if err == nil {
			succeeded++
		} else if errors.Is(err, ErrConflict) {
			conflicts++
		} else {
			t.Fatal(err)
		}
	}
	if succeeded != 1 || conflicts != 1 {
		t.Fatal("lost update", succeeded, conflicts)
	}
	sp, err = service.SAMLServiceProvider(t.Context(), principal, org.ID, sp.ID)
	if err != nil || sp.Revision != 2 {
		t.Fatal(sp, err)
	}
	second := sp
	second.ID, second.EntityID, second.Revision = "", "https://b.example.test", 0
	second, err = service.PutSAMLServiceProvider(t.Context(), principal, second)
	if err != nil {
		t.Fatal(err)
	}
	page, err := service.SAMLServiceProviders(t.Context(), principal, org.ID, "", 1)
	if err != nil || len(page.Items) != 1 || page.NextAfter != min(sp.ID, second.ID) {
		t.Fatal(page, err)
	}
	page, err = service.SAMLServiceProviders(t.Context(), principal, org.ID, page.NextAfter, 1)
	if err != nil || len(page.Items) != 1 || page.Items[0].ID != max(sp.ID, second.ID) || page.NextAfter != "" {
		t.Fatal(page, err)
	}
	if _, err := store.pool.Exec(t.Context(), "ALTER TABLE management_events ADD CONSTRAINT fail_saml_audit CHECK(action<>'saml.serviceProvider.configure') NOT VALID"); err != nil {
		t.Fatal(err)
	}
	if _, err := service.RetireSAMLServiceProvider(t.Context(), principal, org.ID, sp.ID, sp.Revision); err == nil {
		t.Fatal("retirement committed without audit")
	}
	after, err := service.SAMLServiceProvider(t.Context(), principal, org.ID, sp.ID)
	if err != nil || after.Retired || after.Revision != sp.Revision {
		t.Fatal("audit failure changed registration", after, err)
	}
}
