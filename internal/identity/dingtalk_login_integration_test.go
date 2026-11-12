//go:build integration

package identity

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/euyuil/memberid/internal/dingtalk"
	"github.com/jackc/pgx/v5"
)

type loginDingTalkFunc func(context.Context, string, string, string, string) (dingtalk.Member, error)

func (fn loginDingTalkFunc) Login(ctx context.Context, corp, client, secret, code string) (dingtalk.Member, error) {
	return fn(ctx, corp, client, secret, code)
}

func verifierFixture(t *testing.T) (*Store, *DingTalkApplications, *DingTalkVerifier, DingTalkApplication) {
	t.Helper()
	store, apps, organization, _ := applicationFixture(t)
	app, err := apps.Configure(t.Context(), organization.ID, DingTalkApplicationInput{CorpID: "example-corp", ClientID: "example-client", ClientSecret: rand.Text()})
	if err != nil {
		t.Fatal(err)
	}
	verifier, err := NewDingTalkVerifier(apps, loginDingTalkFunc(func(_ context.Context, corp, client, secret, code string) (dingtalk.Member, error) {
		if corp != "example-corp" || client != "example-client" || secret == "" || code != "synthetic-code" {
			return dingtalk.Member{}, errors.New("invalid fixture request")
		}
		return dingtalk.Member{UnionID: "example-union", UserID: "example-employee", DisplayName: "Example person", DepartmentIDs: []string{"17"}}, nil
	}))
	if err != nil {
		t.Fatal(err)
	}
	return store, apps, verifier, app
}

func verifiedLogin(t *testing.T, verifier *DingTalkVerifier, app DingTalkApplication) DingTalkLoginProof {
	t.Helper()
	proof, err := verifier.Verify(t.Context(), app.LoginContext(), "synthetic-code")
	if err != nil {
		t.Fatal(err)
	}
	return proof
}
func admitLogin(ctx context.Context, verifier *DingTalkVerifier, proof DingTalkLoginProof) (Verification, error) {
	var result Verification
	err := pgx.BeginFunc(ctx, verifier.applications.store.pool, func(tx pgx.Tx) error { var err error; result, err = verifier.Admit(ctx, tx, proof); return err })
	return result, err
}

func TestDingTalkAdmissionPreservesIdentityAndIndependentBlocks(t *testing.T) {
	store, _, verifier, app := verifierFixture(t)
	verified, err := admitLogin(t.Context(), verifier, verifiedLogin(t, verifier, app))
	if err != nil {
		t.Fatal(err)
	}
	members, err := store.EligibleMembers(t.Context(), verified.Factor.ID)
	if err != nil || len(members) != 1 || members[0].OrganizationID != app.OrganizationID || members[0].DisplayName != "Example person" || verified.Method != "dingtalk" {
		t.Fatal("invalid admission", err)
	}
	member := members[0]
	second, err := admitLogin(t.Context(), verifier, verifiedLogin(t, verifier, app))
	if err != nil || second.Factor.ID != verified.Factor.ID {
		t.Fatal("repeated login changed factor", err)
	}
	if _, err := store.SetManualBlock(t.Context(), app.OrganizationID, member.ID, true); err != nil {
		t.Fatal(err)
	}
	if _, err := admitLogin(t.Context(), verifier, verifiedLogin(t, verifier, app)); !errors.Is(err, ErrIneligible) {
		t.Fatal("login cleared manual block", err)
	}
	if _, err := store.SetExternalDeparture(t.Context(), app.OrganizationID, member.ID, true); err != nil {
		t.Fatal(err)
	}
	if _, err := store.SetManualBlock(t.Context(), app.OrganizationID, member.ID, false); err != nil {
		t.Fatal(err)
	}
	if _, err := admitLogin(t.Context(), verifier, verifiedLogin(t, verifier, app)); err != nil {
		t.Fatal("fresh verified return failed", err)
	}
	current, err := store.Member(t.Context(), app.OrganizationID, member.ID)
	if err != nil || current.Status != "active" {
		t.Fatal("verified return lost identity", err)
	}
	if err := store.RevokeBinding(t.Context(), app.OrganizationID, member.ID, verified.Factor.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := admitLogin(t.Context(), verifier, verifiedLogin(t, verifier, app)); !errors.Is(err, ErrConflict) {
		t.Fatal("login restored revoked binding", err)
	}
}

func TestDingTalkAdmissionCollisionAndAttributeEvidence(t *testing.T) {
	store, _, verifier, app := verifierFixture(t)
	first, err := admitLogin(t.Context(), verifier, verifiedLogin(t, verifier, app))
	if err != nil {
		t.Fatal(err)
	}
	proof := verifiedLogin(t, verifier, app)
	proof.member.UserID = "new-employee-id"
	proof.member.DisplayName = "Renamed external account"
	proof.member.DepartmentIDs = nil
	if _, err := admitLogin(t.Context(), verifier, proof); err != nil {
		t.Fatal("stable union identity lost after employee ID change", err)
	}
	var memberID, name, external string
	var departments []byte
	if err := store.pool.QueryRow(t.Context(), "SELECT m.id,m.display_name,i.external_member_id,i.department_ids FROM members m JOIN dingtalk_identities i ON i.member_id=m.id WHERE i.organization_id=$1 AND i.union_id=$2", app.OrganizationID, proof.member.UnionID).Scan(&memberID, &name, &external, &departments); err != nil {
		t.Fatal(err)
	}
	if external != "new-employee-id" || name != "Example person" || string(departments) != `["17"]` {
		t.Fatal("identity or optional evidence was overwritten")
	}
	proof.member.UnionID = "different-union"
	if _, err := admitLogin(t.Context(), verifier, proof); !errors.Is(err, ErrConflict) {
		t.Fatal("reused employee ID transferred identity", err)
	}
	proof.member.UserID = "second-employee"
	if _, err := admitLogin(t.Context(), verifier, proof); err != nil {
		t.Fatal(err)
	}
	proof.member.UnionID = "example-union"
	if _, err := admitLogin(t.Context(), verifier, proof); !errors.Is(err, ErrConflict) {
		t.Fatal("two existing identities merged", err)
	}
	members, err := store.EligibleMembers(t.Context(), first.Factor.ID)
	if err != nil || len(members) != 1 || members[0].ID != memberID {
		t.Fatal("collision reassigned original Member", err)
	}
	proof.member.UserID = "new-employee-id"
	proof.member.DepartmentIDs = []string{}
	if _, err := admitLogin(t.Context(), verifier, proof); err != nil {
		t.Fatal(err)
	}
	if err := store.pool.QueryRow(t.Context(), "SELECT department_ids FROM dingtalk_identities WHERE member_id=$1", memberID).Scan(&departments); err != nil || string(departments) != "[]" {
		t.Fatal("verified empty evidence was not retained", err)
	}
}

func TestDingTalkAdmissionOrganizationIsolationAndExplicitProvisioning(t *testing.T) {
	store, apps, verifier, firstApp := verifierFixture(t)
	first, err := admitLogin(t.Context(), verifier, verifiedLogin(t, verifier, firstApp))
	if err != nil {
		t.Fatal(err)
	}
	organization, member := organizationAndMember(t, store)
	secondApp, err := apps.Configure(t.Context(), organization.ID, DingTalkApplicationInput{CorpID: "example-corp", ClientID: "second-client", ClientSecret: rand.Text()})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.BindFactor(t.Context(), organization.ID, member.ID, first.Factor.ID); !errors.Is(err, ErrIneligible) {
		t.Fatal("foreign provider factor bound across organizations", err)
	}
	verifier.provider = loginDingTalkFunc(func(context.Context, string, string, string, string) (dingtalk.Member, error) {
		return dingtalk.Member{UnionID: "example-union", UserID: "example-employee", DisplayName: "Example person"}, nil
	})
	// An explicit operator binding can choose an existing local Member; contact matching cannot.
	factor, err := store.EnsureFactor(t.Context(), "dingtalk", secondApp.Namespace, "example-union")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.BindFactor(t.Context(), organization.ID, member.ID, factor.ID); err != nil {
		t.Fatal(err)
	}
	second, err := admitLogin(t.Context(), verifier, verifiedLogin(t, verifier, secondApp))
	if err != nil || second.Factor.ID == first.Factor.ID {
		t.Fatal("organizations shared factor identity", err)
	}
	members, err := store.EligibleMembers(t.Context(), second.Factor.ID)
	if err != nil || len(members) != 1 || members[0].ID != member.ID {
		t.Fatal("explicit Member binding was not preserved", err)
	}
	firstMembers, err := store.EligibleMembers(t.Context(), first.Factor.ID)
	if err != nil || len(firstMembers) != 1 || firstMembers[0].ID == member.ID {
		t.Fatal("organizations merged Members", err)
	}
}

func TestDingTalkAdmissionRollsBackWithAuthenticationTransaction(t *testing.T) {
	store, _, verifier, app := verifierFixture(t)
	proof := verifiedLogin(t, verifier, app)
	aborted := errors.New("synthetic session failure")
	err := pgx.BeginFunc(t.Context(), store.pool, func(tx pgx.Tx) error {
		if _, err := verifier.Admit(t.Context(), tx, proof); err != nil {
			return err
		}
		return aborted
	})
	if !errors.Is(err, aborted) {
		t.Fatal(err)
	}
	var count int
	if err := store.pool.QueryRow(t.Context(), "SELECT count(*) FROM dingtalk_identities WHERE organization_id=$1", app.OrganizationID).Scan(&count); err != nil || count != 0 {
		t.Fatal("aborted login retained external identity", err)
	}
	if err := store.pool.QueryRow(t.Context(), "SELECT count(*) FROM authentication_factors WHERE namespace=$1", app.Namespace).Scan(&count); err != nil || count != 0 {
		t.Fatal("aborted login retained factor", err)
	}
	if _, err := admitLogin(t.Context(), verifier, DingTalkLoginProof{}); !errors.Is(err, ErrIneligible) {
		t.Fatal("empty proof admitted", err)
	}
	encoded, err := json.Marshal(proof)
	if err != nil || string(encoded) != "{}" {
		t.Fatal("local proof became serializable credential", err)
	}
}

func TestDingTalkAdmissionRejectsStaleConfigurationAndExpiredProof(t *testing.T) {
	store, apps, verifier, app := verifierFixture(t)
	proof := verifiedLogin(t, verifier, app)
	_, err := apps.Configure(t.Context(), app.OrganizationID, DingTalkApplicationInput{CorpID: app.CorpID, ClientID: app.ClientID, ClientSecret: rand.Text(), ExpectedRevision: app.Revision})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := admitLogin(t.Context(), verifier, proof); !errors.Is(err, ErrConflict) {
		t.Fatal("stale application proof accepted", err)
	}
	if _, err := verifier.Verify(t.Context(), app.LoginContext(), "synthetic-code"); !errors.Is(err, ErrConflict) {
		t.Fatal("stale callback exchanged code", err)
	}
	current, err := apps.Inspect(t.Context(), app.OrganizationID)
	if err != nil {
		t.Fatal(err)
	}
	proof = verifiedLogin(t, verifier, current)
	verifier.now = func() time.Time { return proof.authenticatedAt.Add(5 * time.Minute) }
	if _, err := admitLogin(t.Context(), verifier, proof); !errors.Is(err, ErrIneligible) {
		t.Fatal("expired proof accepted", err)
	}
	verifier.now = time.Now
	disabled := "disabled"
	if _, err := store.UpdateOrganization(t.Context(), app.OrganizationID, OrganizationChange{Status: &disabled}); err != nil {
		t.Fatal(err)
	}
	if _, err := admitLogin(t.Context(), verifier, proof); !errors.Is(err, ErrIneligible) {
		t.Fatal("disabled organization admitted login", err)
	}
}

func TestConcurrentDingTalkAdmissionCreatesOneMember(t *testing.T) {
	store, _, verifier, app := verifierFixture(t)
	proof := verifiedLogin(t, verifier, app)
	var group sync.WaitGroup
	results := make(chan Verification, 8)
	failures := make(chan error, 8)
	for range 8 {
		group.Go(func() {
			verified, err := admitLogin(t.Context(), verifier, proof)
			results <- verified
			failures <- err
		})
	}
	group.Wait()
	close(results)
	close(failures)
	for err := range failures {
		if err != nil {
			t.Fatal(err)
		}
	}
	id := ""
	for result := range results {
		if id != "" && result.Factor.ID != id {
			t.Fatal("concurrent admission created multiple factors")
		}
		id = result.Factor.ID
	}
	members, err := store.EligibleMembers(t.Context(), id)
	if err != nil || len(members) != 1 {
		t.Fatal("concurrent admission created multiple Members", err)
	}
}
