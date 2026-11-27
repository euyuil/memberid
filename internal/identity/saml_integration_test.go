//go:build integration

package identity

import (
	"errors"
	"sync"
	"testing"

	"github.com/jackc/pgx/v5"
)

func TestSAMLRegistryAuthorityRevisionsAndPermanentSubjects(t *testing.T) {
	store := testStore(t)
	org, member := organizationAndMember(t, store)
	sp := SAMLServiceProvider{EntityID: "https://sp.example.test/metadata", OrganizationID: org.ID, ACSURL: "https://sp.example.test/acs", Enabled: true, AllowUnsignedRequests: true}
	for _, principal := range []Principal{{}, ManagementPrincipal(member.ID, "grant"), AccountPrincipal("session", member.ID, "factor", "binding")} {
		if _, err := store.PutSAMLServiceProvider(t.Context(), principal, sp, false); !errors.Is(err, ErrForbidden) {
			t.Fatal("non-installation caller modified registration", err)
		}
	}
	var err error
	sp, err = store.PutSAMLServiceProvider(t.Context(), OperatorPrincipal(), sp, false)
	if err != nil {
		t.Fatal(err)
	}
	stale := sp
	sp.Preauthorized = true
	sp, err = store.PutSAMLServiceProvider(t.Context(), OperatorPrincipal(), sp, false)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.PutSAMLServiceProvider(t.Context(), OperatorPrincipal(), stale, false); !errors.Is(err, ErrConflict) {
		t.Fatal("stale revision accepted", err)
	}
	changed := sp
	changed.EntityID = "https://different.example.test"
	if _, err := store.PutSAMLServiceProvider(t.Context(), OperatorPrincipal(), changed, false); !errors.Is(err, ErrConflict) {
		t.Fatal("identity scope changed", err)
	}
	var group sync.WaitGroup
	values := make(chan string, 4)
	failures := make(chan error, 4)
	for range 4 {
		group.Go(func() {
			err := pgx.BeginFunc(t.Context(), store.pool, func(tx pgx.Tx) error {
				if _, err := LockSAMLServiceProvider(t.Context(), tx, sp.ID); err != nil {
					return err
				}
				value, err := SAMLNameID(t.Context(), tx, sp, sp.OrganizationID, member.ID, true)
				if err == nil {
					values <- value
				}
				return err
			})
			if err != nil {
				failures <- err
			}
		})
	}
	group.Wait()
	close(values)
	close(failures)
	for err := range failures {
		t.Fatal(err)
	}
	name := ""
	for value := range values {
		if name != "" && name != value {
			t.Fatal("concurrent allocation changed identifier")
		}
		name = value
	}
	if name == "" || name == member.ID {
		t.Fatal("missing opaque subject")
	}
	sp.Retired = true
	sp, err = store.PutSAMLServiceProvider(t.Context(), OperatorPrincipal(), sp, false)
	if err != nil {
		t.Fatal(err)
	}
	sp.Retired = false
	sp.Enabled = true
	if _, err := store.PutSAMLServiceProvider(t.Context(), OperatorPrincipal(), sp, false); !errors.Is(err, ErrConflict) {
		t.Fatal("retired registration resurrected")
	}
	var retained string
	if err := store.pool.QueryRow(t.Context(), "SELECT value FROM saml_name_ids WHERE service_provider_id=$1 AND member_id=$2", sp.ID, member.ID).Scan(&retained); err != nil || retained != name {
		t.Fatal("retirement lost subject reservation", err)
	}
	events, err := store.ManagementEvents(t.Context(), org.ID, "", 0)
	if err != nil {
		t.Fatal(err)
	}
	count := 0
	for _, event := range events {
		if event.Action == "saml.serviceProvider.configure" {
			count++
		}
	}
	if count != 3 {
		t.Fatalf("expected 3 committed audited changes, got %d", count)
	}
}
