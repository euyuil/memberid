//go:build integration

package oidcprovider

import (
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/euyuil/memberid/internal/config"
	"github.com/euyuil/memberid/internal/dingtalk"
	"github.com/euyuil/memberid/internal/identity"
	"github.com/jackc/pgx/v5"
)

func directoryLogin(t *testing.T, f *fixture) (string, string, string) {
	t.Helper()
	_, verifier, callback := beginDingTalk(t, f, "example-web", "openid offline_access", f.member.OrganizationID)
	response := f.call(f.browser, "GET", callback, nil, nil)
	f.status(response, 303)
	page := f.call(f.browser, "GET", response.header.Get("Location"), nil, nil)
	f.status(page, 200)
	memberID := admittedMember(t, f, f.member.OrganizationID)
	return f.complete(page, memberID), verifier, memberID
}

func TestDirectoryOutageRetryAndReplayRevocation(t *testing.T) {
	for _, kind := range []string{"code", "refresh"} {
		t.Run(kind, func(t *testing.T) {
			f := newConfiguredFixture(t, true)
			provider, _ := enableDingTalk(t, f, false)
			code, verifier, _ := directoryLogin(t, f)
			request := func() reply { return f.exchange("example-web", code, verifier) }
			if kind == "refresh" {
				first := request()
				f.status(first, 200)
				secret := jsonObject(t, first)["refresh_token"].(string)
				request = func() reply { return f.refresh("example-web", secret, "") }
			}
			provider.directoryError = errors.New("private directory diagnostic")
			failed := request()
			f.status(failed, 500)
			if jsonObject(t, failed)["error"] != "server_error" || strings.Contains(failed.body, "private directory diagnostic") {
				t.Fatal("unavailable directory error disclosed diagnostics")
			}
			// The failed observation must not consume a first-use credential.
			provider.directoryError = nil
			recovered := request()
			f.status(recovered, 200)
			tokens := jsonObject(t, recovered)
			provider.directoryError = dingtalk.ErrUnavailable
			replayed := request()
			f.status(replayed, 400)
			if jsonObject(t, replayed)["error"] != "invalid_grant" {
				t.Fatal("provider failure masked replay")
			}
			provider.directoryError = nil
			f.invalidRefresh("example-web", tokens["refresh_token"].(string))
			f.status(f.userinfo(tokens["access_token"].(string)), 401)
			var revoked bool
			if err := f.store.Database().QueryRow(t.Context(), "SELECT revoked_at IS NOT NULL FROM oidc_grants").Scan(&revoked); err != nil || !revoked {
				t.Fatal("replay did not persist family revocation", err)
			}
		})
	}
}

func TestLinkedPhoneDirectoryFallbackAndDefinitiveDenial(t *testing.T) {
	f := newConfiguredFixture(t, true)
	provider, apps := enableDingTalk(t, f, true)
	app, err := apps.Inspect(t.Context(), f.member.OrganizationID)
	if err != nil {
		t.Fatal(err)
	}
	factor, err := f.store.EnsureFactor(t.Context(), "dingtalk", app.Namespace, "example-union")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.store.BindFactor(t.Context(), f.member.OrganizationID, f.member.ID, factor.ID); err != nil {
		t.Fatal(err)
	}
	proof, err := f.service.dingtalk.Verify(t.Context(), app.LoginContext(), "synthetic-code")
	if err != nil {
		t.Fatal(err)
	}
	if err := pgx.BeginFunc(t.Context(), f.store.Database(), func(tx pgx.Tx) error { _, err := f.service.dingtalk.Admit(t.Context(), tx, proof); return err }); err != nil {
		t.Fatal(err)
	}
	// Disabling the interactive adapter must not bypass checks for linked phone Members.
	f.service.dingtalk = nil
	provider.directoryError = dingtalk.ErrUnavailable
	tokens := f.refreshTokens()
	original := f.signedClaims(tokens["id_token"].(string))
	response := f.refresh("example-web", tokens["refresh_token"].(string), "")
	f.status(response, 200)
	tokens = jsonObject(t, response)
	if f.signedClaims(tokens["id_token"].(string))["auth_time"] != original["auth_time"] || provider.directoryCalls.Load() != 2 {
		t.Fatal("directory refresh reset authentication or skipped verification")
	}
	for _, denial := range []error{dingtalk.ErrNotMember, dingtalk.ErrIdentityConflict} {
		provider.directoryError = denial
		f.invalidRefresh("example-web", tokens["refresh_token"].(string))
	}
	provider.directoryError = dingtalk.ErrAuthorizationDenied
	response = f.refresh("example-web", tokens["refresh_token"].(string), "")
	f.status(response, 200)
	tokens = jsonObject(t, response)
	current, err := apps.Inspect(t.Context(), app.OrganizationID)
	if err != nil || current.AuthorizationStatus != "revoked" {
		t.Fatal("definitive current authorization denial was not retained", err)
	}
	// A stored application denial prevents further directory calls for the phone grant.
	calls := provider.directoryCalls.Load()
	provider.directoryError = nil
	response = f.refresh("example-web", tokens["refresh_token"].(string), "")
	f.status(response, 200)
	tokens = jsonObject(t, response)
	f.status(f.userinfo(tokens["access_token"].(string)), 200)
	if provider.directoryCalls.Load() != calls {
		t.Fatal("phone grant depended on the revoked application")
	}
}

func TestDirectoryObservationRejectsConcurrentInvalidation(t *testing.T) {
	for _, kind := range []string{"organization lifecycle", "manual block cycle", "external departure cycle", "credential rotation", "authorization observation", "binding revocation"} {
		t.Run(kind, func(t *testing.T) {
			f := newConfiguredFixture(t, true)
			provider, apps := enableDingTalk(t, f, false)
			code, verifier, memberID := directoryLogin(t, f)
			first := f.exchange("example-web", code, verifier)
			f.status(first, 200)
			secret := jsonObject(t, first)["refresh_token"].(string)
			started, release := make(chan struct{}), make(chan struct{})
			var once sync.Once
			defer once.Do(func() { close(release) })
			provider.directoryBefore = func() { close(started); <-release }
			result := make(chan reply, 1)
			go func() { result <- f.refresh("example-web", secret, "") }()
			select {
			case <-started:
			case <-time.After(10 * time.Second):
				t.Fatal("directory request did not start")
			}
			switch kind {
			case "organization lifecycle":
				for _, status := range []string{"disabled", "enabled"} {
					if _, err := f.store.UpdateOrganization(t.Context(), f.member.OrganizationID, identity.OrganizationChange{Status: &status}); err != nil {
						t.Fatal(err)
					}
				}
			case "manual block cycle":
				for _, blocked := range []bool{true, false} {
					if _, err := f.store.UpdateMember(t.Context(), f.member.OrganizationID, memberID, identity.MemberChange{ManualBlocked: &blocked}); err != nil {
						t.Fatal(err)
					}
				}
			case "external departure cycle":
				for _, departed := range []bool{true, false} {
					if _, err := f.store.SetExternalDeparture(t.Context(), f.member.OrganizationID, memberID, departed); err != nil {
						t.Fatal(err)
					}
				}
			case "credential rotation":
				if _, err := apps.Configure(t.Context(), f.member.OrganizationID, identity.DingTalkApplicationInput{CorpID: "example-corp", ClientID: "example-client", ClientSecret: config.RandomSecret(), ExpectedRevision: 1}); err != nil {
					t.Fatal(err)
				}
			case "authorization observation":
				if _, err := apps.SynchronizeAuthorization(t.Context(), f.member.OrganizationID); err != nil {
					t.Fatal(err)
				}
			case "binding revocation":
				bindings, err := f.store.Bindings(t.Context(), f.member.OrganizationID, memberID)
				if err != nil || len(bindings) != 1 {
					t.Fatal(err)
				}
				if err := f.store.RevokeBinding(t.Context(), f.member.OrganizationID, memberID, bindings[0].FactorID); err != nil {
					t.Fatal(err)
				}
			}
			once.Do(func() { close(release) })
			response := <-result
			f.status(response, 400)
			if jsonObject(t, response)["error"] != "invalid_grant" {
				t.Fatal("stale observation issued tokens")
			}
			var consumed bool
			if err := f.store.Database().QueryRow(t.Context(), "SELECT consumed_at IS NOT NULL FROM oidc_refresh_tokens WHERE secret_hash=$1", config.SecretHash(secret)).Scan(&consumed); err != nil || consumed {
				t.Fatal("rejected observation consumed refresh", err)
			}
		})
	}
}
