//go:build integration

package oidcprovider

import (
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/euyuil/memberid/internal/identity"
)

func TestGrantInspectionAndTargetedRevocation(t *testing.T) {
	f := newConfiguredFixture(t, true)
	tokens := f.refreshTokens()
	page, verifier := f.loginPage("example-web", "openid profile phone offline_access")
	code := f.complete(page, f.member.ID)
	response := f.exchange("example-web", code, verifier)
	f.status(response, 200)
	second := jsonObject(t, response)
	list, err := ListGrants(t.Context(), f.store, GrantFilter{ClientID: "example-web", Subject: f.member.ID, Limit: 1})
	if err != nil || len(list.Items) != 1 || list.NextAfter == "" {
		t.Fatalf("first grant page: %+v %v", list, err)
	}
	last, err := ListGrants(t.Context(), f.store, GrantFilter{ClientID: "example-web", Subject: f.member.ID, After: list.NextAfter, Limit: 1})
	if err != nil || len(last.Items) != 1 || last.NextAfter != "" || last.Items[0].ID == list.Items[0].ID {
		t.Fatalf("last grant page: %+v %v", last, err)
	}
	empty, err := ListGrants(t.Context(), f.store, GrantFilter{ClientID: "second-web", Limit: 100})
	if err != nil || len(empty.Items) != 0 {
		t.Fatal("client filter leaked grants", err)
	}
	empty, err = ListGrants(t.Context(), f.store, GrantFilter{Subject: f.otherMember.ID, Limit: 100})
	if err != nil || len(empty.Items) != 0 {
		t.Fatal("subject filter leaked grants", err)
	}
	var id string
	if err := f.store.Database().QueryRow(t.Context(), "SELECT grant_id FROM oidc_access_tokens WHERE id=$1", f.signedClaims(tokens["access_token"].(string))["jti"]).Scan(&id); err != nil {
		t.Fatal(err)
	}
	before, err := InspectGrant(t.Context(), f.store, id)
	if err != nil || before.State != "active" || before.Subject != f.member.ID || before.OrganizationID != f.member.OrganizationID || !slices.Contains(before.OriginalScopes, "phone") {
		t.Fatalf("grant inspection: %+v %v", before, err)
	}
	encoded, err := json.Marshal(before)
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{tokens["access_token"].(string), tokens["refresh_token"].(string), "secret_hash", "secretHash"} {
		if strings.Contains(string(encoded), secret) {
			t.Fatal("grant metadata exposed a credential or verifier")
		}
	}
	if _, err := f.store.Database().Exec(t.Context(), "UPDATE oidc_sessions SET expires_at=clock_timestamp()-interval '1 second'"); err != nil {
		t.Fatal(err)
	}
	after, err := InspectGrant(t.Context(), f.store, id)
	if err != nil || after.State != "active" {
		t.Fatal("browser expiry incorrectly expired the grant", err)
	}
	revoked, err := RevokeGrant(t.Context(), f.store, id)
	if err != nil || revoked.State != "revoked" || revoked.RevokedAt == nil || !revoked.AuthenticatedAt.Equal(before.AuthenticatedAt) || !revoked.AbsoluteExpiresAt.Equal(before.AbsoluteExpiresAt) {
		t.Fatalf("revoke changed original metadata: %+v %v", revoked, err)
	}
	repeated, err := RevokeGrant(t.Context(), f.store, id)
	if err != nil || repeated.RevokedAt == nil || !repeated.RevokedAt.Equal(*revoked.RevokedAt) {
		t.Fatal("repeated revocation changed its first timestamp", err)
	}
	f.invalidRefresh("example-web", tokens["refresh_token"].(string))
	f.status(f.userinfo(tokens["access_token"].(string)), 401)
	f.status(f.userinfo(second["access_token"].(string)), 200)
	f.status(f.refresh("example-web", second["refresh_token"].(string), ""), 200)
	if _, err := InspectGrant(t.Context(), f.store, newID()); !errors.Is(err, identity.ErrNotFound) {
		t.Fatal("missing grant not reported", err)
	}
	if _, err := RevokeGrant(t.Context(), f.store, "invalid"); !errors.Is(err, identity.ErrInvalid) {
		t.Fatal("invalid grant ID accepted", err)
	}
}

func TestOperatorRevocationSerializesWithRefresh(t *testing.T) {
	f := newConfiguredFixture(t, true)
	tokens := f.refreshTokens()
	grants, err := ListGrants(t.Context(), f.store, GrantFilter{Limit: 50})
	if err != nil || len(grants.Items) != 1 {
		t.Fatal("missing grant", err)
	}
	start := make(chan struct{})
	rotated := make(chan reply, 1)
	revoked := make(chan error, 1)
	go func() { <-start; rotated <- f.refresh("example-web", tokens["refresh_token"].(string), "") }()
	go func() { <-start; _, err := RevokeGrant(t.Context(), f.store, grants.Items[0].ID); revoked <- err }()
	close(start)
	response := <-rotated
	if err := <-revoked; err != nil {
		t.Fatal(err)
	}
	if response.status == 200 {
		f.invalidRefresh("example-web", jsonObject(t, response)["refresh_token"].(string))
	} else {
		f.status(response, 400)
	}
	f.invalidRefresh("example-web", tokens["refresh_token"].(string))
	f.status(f.userinfo(tokens["access_token"].(string)), 401)
	info, err := InspectGrant(t.Context(), f.store, grants.Items[0].ID)
	if err != nil || info.State != "revoked" {
		t.Fatal("refresh resurrected the grant", err)
	}
}

func TestGrantLifecycleStatus(t *testing.T) {
	f := newConfiguredFixture(t, true)
	f.refreshTokens()
	grants, err := ListGrants(t.Context(), f.store, GrantFilter{Limit: 1})
	if err != nil || len(grants.Items) != 1 {
		t.Fatal("missing grant", err)
	}
	id := grants.Items[0].ID
	if _, err := f.store.Database().Exec(t.Context(), "UPDATE oidc_grants SET expires_at=$1 WHERE id=$2", time.Now().Add(-time.Second), id); err != nil {
		t.Fatal(err)
	}
	expired, err := InspectGrant(t.Context(), f.store, id)
	if err != nil || expired.State != "expired" {
		t.Fatal("expiry not reported", err)
	}
	if _, err := f.store.Database().Exec(t.Context(), "UPDATE oidc_sessions SET revoked_at=clock_timestamp()"); err != nil {
		t.Fatal(err)
	}
	revoked, err := InspectGrant(t.Context(), f.store, id)
	if err != nil || revoked.State != "revoked" || revoked.SessionRevokedAt == nil {
		t.Fatal("session revocation not reported", err)
	}
	if _, err := ListGrants(t.Context(), f.store, GrantFilter{Limit: 101}); !errors.Is(err, identity.ErrInvalid) {
		t.Fatal("unbounded query accepted", err)
	}
	if _, err := ListGrants(t.Context(), f.store, GrantFilter{Limit: 1, After: "bad"}); !errors.Is(err, identity.ErrInvalid) {
		t.Fatal("bad cursor accepted", err)
	}
	if _, err := ListGrants(t.Context(), f.store, GrantFilter{Limit: 1, Subject: "bad"}); !errors.Is(err, identity.ErrInvalid) {
		t.Fatal("bad subject accepted", err)
	}
}
