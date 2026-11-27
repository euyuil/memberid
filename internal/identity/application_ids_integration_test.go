//go:build integration

package identity

import (
	"context"
	"strings"
	"sync"
	"testing"

	"github.com/jackc/pgx/v5"
)

func TestConcurrentApplicationRegistrationIDs(t *testing.T) {
	store := testStore(t)
	ctx := t.Context()
	operator := OperatorPrincipal()
	const name = "Shared display name"
	var ids [4]string
	var group sync.WaitGroup
	for i := range ids {
		group.Go(func() {
			if i%2 == 0 {
				app, err := store.CreateOIDCClient(ctx, operator, OIDCClientRegistration{Client: OIDCClient{SubjectKind: "member", SecretSHA256: strings.Repeat("a", 64), RedirectURIs: []string{"https://example.test/callback"}}, DisplayName: name, OwnerOrganizationID: SystemOrganizationID}, false)
				if err != nil {
					t.Error(err)
					return
				}
				ids[i] = app.ClientID
			} else {
				entity := "https://a.example.test"
				if i == 3 {
					entity = "https://b.example.test"
				}
				sp, err := store.PutSAMLServiceProvider(ctx, operator, SAMLServiceProvider{DisplayName: name, EntityID: entity, OrganizationID: SystemOrganizationID, ACSURL: "https://example.test/acs", Enabled: true, AllowUnsignedRequests: true}, false)
				if err != nil {
					t.Error(err)
					return
				}
				ids[i] = sp.ID
			}
		})
	}
	group.Wait()
	seen := map[string]bool{}
	for _, id := range ids {
		if !ValidID(id, ApplicationKind) || seen[id] {
			t.Fatalf("invalid or repeated registration ID %q", id)
		}
		seen[id] = true
	}
}

func TestDatabaseUpgradeChecksApplicationInventoryBeforeCommit(t *testing.T) {
	dsn := baselineDatabase(t)
	ctx := t.Context()
	conn, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = conn.Exec(ctx, `INSERT INTO saml_service_providers(id,entity_id,organization_id,revision,data,retired_at)
	VALUES('same','urn:example:sp','org_system',1,'{"id":"same"}',now())`); err != nil {
		t.Fatal(err)
	}
	conn.Close(ctx)
	legacy := []OIDCClientRegistration{{Client: OIDCClient{ID: "same", SecretSHA256: strings.Repeat("a", 64)}, DisplayName: "Protected console", System: true}}
	plan, err := PlanApplicationIDs(ctx, dsn, func() ([]OIDCClientRegistration, error) { return legacy, nil }, nil)
	if err != nil {
		t.Fatal(err)
	}
	apply := func(rows []ApplicationIDAssignment) error {
		_, err := UpgradeDatabase(ctx, dsn, func(ctx context.Context, s string, version int) (UpgradePreparation, error) {
			prep, err := syntheticBackup(ctx, s, version)
			prep.ApplicationIDs, prep.OIDCClients = rows, legacy
			return prep, err
		})
		return err
	}
	if err := apply(plan[:1]); err == nil {
		t.Fatal("missing mapping committed")
	}
	assertBaseline(t, dsn)
	if err := apply(plan); err != nil {
		t.Fatal(err)
	}
	if err := apply(plan); err != nil {
		t.Fatal(err)
	}
	store, err := Open(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	client, err := store.OIDCClient(ctx, plan[0].NewID)
	if err != nil || !client.System || client.Client.ID != plan[0].NewID {
		t.Fatal("console registration lost", err)
	}
	sp, err := store.SAMLServiceProviderByEntityID(ctx, "urn:example:sp")
	if err != nil || !sp.Retired || sp.ID != plan[1].NewID {
		t.Fatal("retired SP reservation lost", err)
	}
}
