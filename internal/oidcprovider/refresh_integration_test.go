//go:build integration

package oidcprovider

import (
	"encoding/base64"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/euyuil/memberid/internal/config"
	"github.com/euyuil/memberid/internal/identity"
)

func (f *fixture) refreshTokens() map[string]any {
	f.t.Helper()
	page, verifier := f.loginPage("example-web", "openid profile phone offline_access")
	code := f.complete(f.verifyPhone(page), f.member.ID)
	response := f.exchange("example-web", code, verifier)
	f.status(response, 200)
	tokens := jsonObject(f.t, response)
	secret, ok := tokens["refresh_token"].(string)
	if !ok || len(secret) != 43 {
		f.t.Fatal("missing random refresh token")
	}
	return tokens
}
func (f *fixture) refresh(client, secret, scopes string) reply {
	f.t.Helper()
	body := url.Values{"grant_type": {"refresh_token"}, "refresh_token": {secret}}
	if scopes != "" {
		body.Set("scope", scopes)
	}
	return f.call(browserClient(), "POST", "/oauth/token", body, map[string]string{"Authorization": "Basic " + base64.StdEncoding.EncodeToString([]byte(client+":"+f.secret))})
}
func (f *fixture) invalidRefresh(client, secret string) {
	f.t.Helper()
	r := f.refresh(client, secret, "")
	f.status(r, 400)
	if jsonObject(f.t, r)["error"] != "invalid_grant" {
		f.t.Fatal("unexpected refresh error", r.body)
	}
}

func TestRefreshRotationAndScopeNarrowing(t *testing.T) {
	f := newConfiguredFixture(t, true)
	tokens := f.refreshTokens()
	originalSecret := tokens["refresh_token"].(string)
	originalClaims := f.signedClaims(tokens["id_token"].(string))
	response := f.refresh("second-web", originalSecret, "")
	f.status(response, 400)
	response = f.refresh("example-web", originalSecret, "openid unknown_scope")
	f.status(response, 400)
	if jsonObject(t, response)["error"] != "invalid_scope" {
		t.Fatal("scope escalation not rejected")
	}
	response = f.refresh("example-web", originalSecret, "openid")
	f.status(response, 200)
	next := jsonObject(t, response)
	nextSecret := next["refresh_token"].(string)
	if nextSecret == originalSecret || next["scope"] != "openid" {
		t.Fatal("refresh did not rotate and narrow scope")
	}
	nextClaims := f.signedClaims(next["id_token"].(string))
	if nextClaims["sub"] != originalClaims["sub"] || nextClaims["auth_time"] != originalClaims["auth_time"] || nextClaims["sid"] != originalClaims["sid"] {
		t.Fatal("rotation changed authenticated identity")
	}
	if _, present := nextClaims["nonce"]; present {
		t.Fatal("refresh reused the authorization nonce")
	}
	info := f.userinfo(next["access_token"].(string))
	f.status(info, 200)
	if jsonObject(t, info)["phone_number"] != nil || jsonObject(t, info)["name"] != nil {
		t.Fatal("narrowed scope disclosed profile claims")
	}
	response = f.refresh("example-web", nextSecret, "openid profile")
	f.status(response, 400)
	if jsonObject(t, response)["error"] != "invalid_scope" {
		t.Fatal("narrowed refresh regained removed scope")
	}
	var persistedHash, data string
	if err := f.store.Database().QueryRow(t.Context(), "SELECT secret_hash,data::text FROM oidc_refresh_tokens WHERE secret_hash=$1", config.SecretHash(nextSecret)).Scan(&persistedHash, &data); err != nil || persistedHash == nextSecret || strings.Contains(data, nextSecret) {
		t.Fatal("refresh credential persisted in plaintext", err)
	}
	response = f.refresh("example-web", nextSecret, "")
	f.status(response, 200)
	newest := jsonObject(t, response)
	f.invalidRefresh("example-web", originalSecret)
	f.invalidRefresh("example-web", newest["refresh_token"].(string))
	f.status(f.userinfo(newest["access_token"].(string)), 401)
}

func TestConcurrentRefreshRevokesFamily(t *testing.T) {
	f := newConfiguredFixture(t, true)
	tokens := f.refreshTokens()
	results := make(chan reply, 10)
	for range 10 {
		go func() { results <- f.refresh("example-web", tokens["refresh_token"].(string), "") }()
	}
	successes := 0
	var issued map[string]any
	for range 10 {
		response := <-results
		if response.status == 200 {
			successes++
			issued = jsonObject(t, response)
		} else {
			f.status(response, 400)
		}
	}
	if successes != 1 {
		t.Fatalf("successful concurrent refreshes: %d", successes)
	}
	f.invalidRefresh("example-web", issued["refresh_token"].(string))
	f.status(f.userinfo(issued["access_token"].(string)), 401)
}

func TestRefreshSurvivesBrowserExpiryAndPreservesDeadline(t *testing.T) {
	f := newConfiguredFixture(t, true)
	tokens := f.refreshTokens()
	var originalAuth, originalAbsolute, afterAuth, afterAbsolute, afterIdle time.Time
	if err := f.store.Database().QueryRow(t.Context(), "SELECT (data->>'authTime')::timestamptz,absolute_expires_at FROM oidc_grants").Scan(&originalAuth, &originalAbsolute); err != nil {
		t.Fatal(err)
	}
	if _, err := f.store.Database().Exec(t.Context(), "UPDATE oidc_sessions SET expires_at=clock_timestamp()-interval '1 hour'"); err != nil {
		t.Fatal(err)
	}
	if _, err := f.store.Database().Exec(t.Context(), "UPDATE oidc_grants SET expires_at=clock_timestamp()+interval '1 hour'"); err != nil {
		t.Fatal(err)
	}
	if err := f.service.Cleanup(t.Context()); err != nil {
		t.Fatal(err)
	}
	response := f.refresh("example-web", tokens["refresh_token"].(string), "")
	f.status(response, 200)
	if err := f.store.Database().QueryRow(t.Context(), "SELECT (data->>'authTime')::timestamptz,absolute_expires_at,expires_at FROM oidc_grants").Scan(&afterAuth, &afterAbsolute, &afterIdle); err != nil {
		t.Fatal(err)
	}
	if !afterAuth.Equal(originalAuth) || !afterAbsolute.Equal(originalAbsolute) || time.Until(afterIdle) < 7*24*time.Hour-time.Minute {
		t.Fatal("rotation reset original authentication or failed to renew inactivity deadline")
	}
	if err := f.service.Cleanup(t.Context()); err != nil {
		t.Fatal(err)
	}
	next := jsonObject(t, response)
	f.status(f.userinfo(next["access_token"].(string)), 200)
}

func TestRefreshExpiryEligibilityAndRevocation(t *testing.T) {
	for _, condition := range []string{"idle", "absolute", "blocked", "revoked", "logout"} {
		t.Run(condition, func(t *testing.T) {
			f := newConfiguredFixture(t, true)
			tokens := f.refreshTokens()
			secret := tokens["refresh_token"].(string)
			switch condition {
			case "idle":
				if _, err := f.store.Database().Exec(t.Context(), "UPDATE oidc_grants SET expires_at=clock_timestamp()-interval '1 second'"); err != nil {
					t.Fatal(err)
				}
			case "absolute":
				if _, err := f.store.Database().Exec(t.Context(), "UPDATE oidc_sessions SET absolute_expires_at=clock_timestamp()-interval '1 second'"); err != nil {
					t.Fatal(err)
				}
			case "blocked":
				if _, err := f.store.SetManualBlock(t.Context(), identity.OperatorPrincipal(), f.member.OrganizationID, f.member.ID, true); err != nil {
					t.Fatal(err)
				}
			case "revoked":
				basic := map[string]string{"Authorization": "Basic " + base64.StdEncoding.EncodeToString([]byte("second-web:"+f.secret))}
				f.status(f.call(browserClient(), "POST", "/oauth/revoke", url.Values{"token": {secret}, "token_type_hint": {"refresh_token"}}, basic), 200)
				response := f.refresh("example-web", secret, "")
				f.status(response, 200)
				secret = jsonObject(t, response)["refresh_token"].(string)
				basic["Authorization"] = "Basic " + base64.StdEncoding.EncodeToString([]byte("example-web:"+f.secret))
				f.status(f.call(browserClient(), "POST", "/oauth/revoke", url.Values{"token": {secret}, "token_type_hint": {"refresh_token"}}, basic), 200)
			case "logout":
				response := f.call(f.browser, "GET", "/oauth/logout?"+url.Values{"id_token_hint": {tokens["id_token"].(string)}}.Encode(), nil, nil)
				f.status(response, 302)
			}
			f.invalidRefresh("example-web", secret)
		})
	}
}

func TestRefreshDiscoveryAndClientPolicy(t *testing.T) {
	f := newConfiguredFixture(t, true)
	response := f.call(browserClient(), "GET", "/.well-known/openid-configuration", nil, nil)
	f.status(response, 200)
	metadata := jsonObject(t, response)
	grants, _ := metadata["grant_types_supported"].([]any)
	if len(grants) != 2 || grants[1] != "refresh_token" {
		t.Fatal("missing refresh discovery")
	}
	response, _ = f.authorization("registration", "openid registration_identity offline_access", nil)
	if strings.Contains(response.header.Get("Location"), "/login?") {
		t.Fatal("client without refresh permission received offline access")
	}
	response = f.refresh("registration", config.RandomSecret(), "")
	f.status(response, 400)
	if jsonObject(t, response)["error"] != "unauthorized_client" {
		t.Fatal("client refresh policy bypassed", response.body)
	}
}

func TestRefreshAbsoluteCapAndCoreClaimsAfterNarrowing(t *testing.T) {
	f := newConfiguredFixture(t, true)
	tokens := f.refreshTokens()
	deadline := time.Now().UTC().Add(7 * time.Minute)
	if _, err := f.store.Database().Exec(t.Context(), "UPDATE oidc_grants SET absolute_expires_at=$1,data=jsonb_set(data,'{absoluteExpiry}',to_jsonb($1::timestamptz))", deadline); err != nil {
		t.Fatal(err)
	}
	if _, err := f.store.Database().Exec(t.Context(), "UPDATE oidc_refresh_tokens SET data=jsonb_set(data,'{absoluteExpiry}',to_jsonb($1::timestamptz))", deadline); err != nil {
		t.Fatal(err)
	}
	if _, err := f.store.Database().Exec(t.Context(), "UPDATE oidc_sessions SET absolute_expires_at=$1", deadline); err != nil {
		t.Fatal(err)
	}
	response := f.refresh("example-web", tokens["refresh_token"].(string), "profile")
	f.status(response, 200)
	next := jsonObject(t, response)
	access := f.signedClaims(next["access_token"].(string))
	id := f.signedClaims(next["id_token"].(string))
	if int64(access["exp"].(float64)) != deadline.Unix() || id["sid"] == nil || id["auth_time"] == nil || access["scope"] != "profile" {
		t.Fatal("refresh changed deadline or lost core claims")
	}
	var expiry time.Time
	if err := f.store.Database().QueryRow(t.Context(), "SELECT expires_at FROM oidc_grants").Scan(&expiry); err != nil || expiry.Sub(deadline) > time.Millisecond {
		t.Fatal("grant inactivity exceeds absolute cap", err)
	}
}

func TestRefreshAcrossProviderInstances(t *testing.T) {
	f := newConfiguredFixture(t, true)
	tokens := f.refreshTokens()
	independentStore, err := identity.Open(t.Context(), f.store.Database().Config().ConnString())
	if err != nil {
		t.Fatal(err)
	}
	defer independentStore.Close()
	independent, err := New(f.service.configuration, independentStore, f.service.phone, nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	replica := httptest.NewServer(independent)
	defer replica.Close()
	originalServer := f.server
	f.server = replica
	response := f.refresh("example-web", tokens["refresh_token"].(string), "")
	f.status(response, 200)
	next := jsonObject(t, response)
	f.server = originalServer
	f.invalidRefresh("example-web", tokens["refresh_token"].(string))
	f.server = replica
	f.invalidRefresh("example-web", next["refresh_token"].(string))
}

func TestRefreshIssuanceFailureRollsBackConsumption(t *testing.T) {
	f := newConfiguredFixture(t, true)
	tokens := f.refreshTokens()
	if _, err := f.store.Database().Exec(t.Context(), "ALTER TABLE oidc_refresh_tokens ADD CONSTRAINT simulated_storage_failure CHECK (false) NOT VALID"); err != nil {
		t.Fatal(err)
	}
	response := f.refresh("example-web", tokens["refresh_token"].(string), "")
	f.status(response, 500)
	var consumed, accessCount, refreshCount int
	if err := f.store.Database().QueryRow(t.Context(), "SELECT (SELECT count(*) FROM oidc_refresh_tokens WHERE consumed_at IS NOT NULL),(SELECT count(*) FROM oidc_access_tokens),(SELECT count(*) FROM oidc_refresh_tokens)").Scan(&consumed, &accessCount, &refreshCount); err != nil {
		t.Fatal(err)
	}
	if consumed != 0 || accessCount != 1 || refreshCount != 1 {
		t.Fatal("failed issuance partially changed the family")
	}
	if _, err := f.store.Database().Exec(t.Context(), "ALTER TABLE oidc_refresh_tokens DROP CONSTRAINT simulated_storage_failure"); err != nil {
		t.Fatal(err)
	}
	f.status(f.refresh("example-web", tokens["refresh_token"].(string), ""), 200)
}
