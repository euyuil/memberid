//go:build integration

package identity

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"
)

func TestInstallationReservations(t *testing.T) {
	ctx, op := t.Context(), OperatorPrincipal()
	first, second := testStore(t), testStore(t)
	if first.SystemOrganizationID() == second.SystemOrganizationID() || first.RootMemberID() == second.RootMemberID() {
		t.Fatal("independent installations reused identifiers")
	}
	for _, store := range []*Store{first, second} {
		org, err := store.LoginOrganizationIDBySlug(ctx, "system")
		if err != nil || org != store.SystemOrganizationID() || !ValidID(org, OrganizationKind) || !ValidID(store.RootMemberID(), MemberKind) {
			t.Fatal("invalid installation identities", err)
		}
		if _, err := store.Member(ctx, org, store.RootMemberID()); !errors.Is(err, ErrNotFound) {
			t.Fatal("schema-only initialization created a root Member", err)
		}
		member, err := store.CreateMember(ctx, op, org, "", "System fixture")
		if err != nil {
			t.Fatal(err)
		}
		if _, err := store.SetMemberPassword(ctx, op, org, member.ID, "root"); !errors.Is(err, ErrForbidden) {
			t.Fatal("another system Member could take root", err)
		}
		if _, err := store.ResetRootPassword(ctx, op); !errors.Is(err, ErrNotFound) {
			t.Fatal("recovery created an unprovisioned root", err)
		}
		other, ordinary := organizationAndMember(t, store)
		password, err := store.SetMemberPassword(ctx, op, other.ID, ordinary.ID, "root")
		if err != nil {
			t.Fatal(err)
		}
		if err := store.VerifyPasswordAndApply(ctx, other.ID, "root", password, func(_ pgx.Tx, admitted MemberAdmission) error {
			if admitted.MemberID != ordinary.ID {
				t.Fatal("ordinary root name resolved to another Member")
			}
			return nil
		}); err != nil {
			t.Fatal(err)
		}
		for _, q := range []string{"DELETE FROM organization_login_slugs WHERE slug='system'", "UPDATE organization_login_slugs SET slug='elsewhere' WHERE slug='system'", "UPDATE organization_login_slugs SET organization_id='" + other.ID + "' WHERE slug='system'", "DELETE FROM installation_identities"} {
			if _, err := store.pool.Exec(ctx, q); err == nil {
				t.Fatal("permanent reservation changed", q)
			}
		}
	}
}

func TestLegacyRootConflictAndProviderRekey(t *testing.T) {
	ctx := t.Context()
	dsn := baselineDatabase(t)
	exec := func(query string, args ...any) {
		t.Helper()
		conn, err := pgx.Connect(ctx, dsn)
		if err != nil {
			t.Fatal(err)
		}
		defer conn.Close(context.Background())
		if _, err := conn.Exec(ctx, query, args...); err != nil {
			t.Fatal(err)
		}
	}
	exec("INSERT INTO members(id,organization_id,display_name) VALUES('mbr_root','org_system','mbr_root')")
	other, _ := NewID(MemberKind)
	exec("INSERT INTO members(id,organization_id,display_name) VALUES($1,'org_system','Other')", other)
	for _, user := range []struct{ member, username string }{{"mbr_root", "renamed"}, {other, "root"}} {
		factor, _ := NewID(FactorKind)
		exec("INSERT INTO authentication_factors(id,type,namespace,subject) VALUES($1,'password','org_system',$2)", factor, user.username)
		exec("INSERT INTO member_auth_factor_bindings(member_id,organization_id,authentication_factor_id,factor_type) VALUES($1,'org_system',$2,'password')", user.member, factor)
	}
	if _, err := UpgradeDatabase(ctx, dsn, syntheticBackup); err == nil || !strings.Contains(err.Error(), "held by another identity") {
		t.Fatal("expected an ownership conflict", err)
	}
	assertBaseline(t, dsn)
	exec("UPDATE authentication_factors SET subject='ordinary' WHERE subject='root'")
	const updateID = "00000000-0000-4000-8000-000000000123"
	fingerprint := sha256.Sum256([]byte(`{"organizationId":"org_system","memberId":"mbr_root","change":{"displayName":"mbr_root","manualBlocked":null}}`))
	exec(`INSERT INTO member_updates(id,organization_id,member_id,request_hash,response,created_at)
		VALUES($1,'org_system','mbr_root',$2,'{"memberId":"mbr_root","organizationId":"org_system","member":{"id":"mbr_root","organizationId":"org_system","displayName":"mbr_root"}}',clock_timestamp())`, updateID, fingerprint[:])
	key := bytes.Repeat([]byte{17}, 32)
	app := DingTalkApplication{OrganizationID: "org_system", Namespace: "source", CorpID: "corp", ClientID: "client", Revision: 4}
	cipher, err := providerCipher(key)
	if err != nil {
		t.Fatal(err)
	}
	sealed := cipher.Seal(nil, nil, []byte("synthetic provider credential"), applicationAAD(app))
	exec("INSERT INTO dingtalk_applications(organization_id,namespace,corp_id,client_id,revision,secret_ciphertext) VALUES('org_system','source','corp','client',4,$1)", sealed)
	if _, err := UpgradeDatabase(ctx, dsn, syntheticBackup); !errors.Is(err, ErrProviderConfiguration) {
		t.Fatal("missing credential key did not fail closed", err)
	}
	assertBaseline(t, dsn)
	if _, err := UpgradeDatabase(ctx, dsn, func(ctx context.Context, s string, v int) (UpgradePreparation, error) {
		prep, err := syntheticBackup(ctx, s, v)
		prep.ProviderKey = key
		return prep, err
	}); err != nil {
		t.Fatal(err)
	}
	store, err := Open(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	loaded, err := (&DingTalkApplications{store: store, cipher: cipher}).Load(ctx, store.SystemOrganizationID())
	if err != nil || loaded.Secret != "synthetic provider credential" || loaded.Revision != 4 || loaded.Namespace != "source" {
		t.Fatal("upgraded credentials no longer decrypt under their owner", err)
	}
	name := "mbr_root"
	receipt, created, err := store.UpdateMemberOnce(ctx, OperatorPrincipal(), store.SystemOrganizationID(), store.RootMemberID(), updateID, MemberChange{DisplayName: &name})
	if err != nil || created || receipt.Member.ID != store.RootMemberID() || receipt.Member.DisplayName != name {
		t.Fatal("rekeyed receipt did not replay with its historical display name", err)
	}
	if _, _, err := store.UpdateMemberOnce(ctx, OperatorPrincipal(), store.SystemOrganizationID(), other, updateID, MemberChange{DisplayName: &name}); !errors.Is(err, ErrConflict) {
		t.Fatal("replayed receipt for another member", err)
	}
	var actual string
	if err := store.pool.QueryRow(ctx, "SELECT f.subject FROM member_auth_factor_bindings b JOIN authentication_factors f ON f.id=b.authentication_factor_id WHERE b.member_id=$1 AND f.namespace=$2", store.RootMemberID(), store.SystemOrganizationID()).Scan(&actual); err != nil || actual != "root" {
		t.Fatal("renamed root binding not recovered", err)
	}
	for _, q := range []string{"DELETE FROM member_auth_factor_bindings WHERE member_id=$1", "UPDATE member_auth_factor_bindings SET member_id=$2 WHERE member_id=$1", "UPDATE authentication_factors SET subject='elsewhere' WHERE id IN (SELECT authentication_factor_id FROM member_auth_factor_bindings WHERE member_id=$1)"} {
		args := []any{store.RootMemberID()}
		if strings.Contains(q, "$2") {
			args = append(args, other)
		}
		if _, err := store.pool.Exec(ctx, q, args...); err == nil {
			t.Fatal("permanent root binding changed", q)
		}
	}
}
