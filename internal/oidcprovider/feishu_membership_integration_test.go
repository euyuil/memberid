//go:build integration

package oidcprovider

import (
	"context"
	"encoding/base64"
	"errors"
	"github.com/euyuil/memberid/internal/config"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/euyuil/memberid/internal/feishu"
	"github.com/euyuil/memberid/internal/identity"
	"github.com/jackc/pgx/v5"
)

func providerKey(t *testing.T, f *fixture) []byte {
	t.Helper()
	key, err := base64.StdEncoding.DecodeString(f.service.configuration.Secrets.ProviderKey)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

// These are real HTTP/database flows with synthetic Feishu directory responses.
func admittedFeishuFixture(t *testing.T) (*fixture, *testFeishu, string) {
	t.Helper()
	f, provider, id, page := feishuAccountFixture(t)
	result := f.call(f.browser, "GET", startFeishuAccount(f, page, id), nil, nil)
	f.status(result, 200)
	if !strings.Contains(result.body, "Feishu is linked") {
		t.Fatal("could not admit synthetic Feishu identity")
	}
	return f, provider, id
}

func feishuLoginCallback(t *testing.T, f *fixture, id string) (string, string) {
	t.Helper()
	f.browser = browserClient()
	page, verifier := f.loginPage("example-web", "openid offline_access")
	response := f.submit(page.body, "feishu", url.Values{"organization": {f.member.OrganizationID}, "provider": {id}})
	f.status(response, 303)
	location, err := url.Parse(response.header.Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	return feishuCallbackPath + "?" + url.Values{"state": {location.Query().Get("state")}, "code": {"synthetic-code"}}.Encode(), verifier
}

func assertFeishuDeparture(t *testing.T, f *fixture, want bool) {
	t.Helper()
	member, err := f.store.Member(t.Context(), f.member.OrganizationID, f.member.ID)
	if err != nil {
		t.Fatal(err)
	}
	departed := false
	for _, source := range member.BlockSources {
		departed = departed || source == "externalDeparture"
	}
	if departed != want {
		t.Fatal("incorrect stored departure", member)
	}
}

func TestFeishuDepartureBlocksSharedOIDCAndSAML(t *testing.T) {
	f, provider, _ := admittedFeishuFixture(t)
	sp := enableSAML(t, f)
	login, verifier := f.loginPage("example-web", "openid offline_access")
	response := f.exchange("example-web", f.complete(login, f.member.ID), verifier)
	f.status(response, 200)
	tokens := jsonObject(t, response)
	login, codeVerifier := f.loginPage("example-web", "openid offline_access")
	code := f.complete(login, f.member.ID)
	samlLogin := samlPage(t, f, sp)
	provider.membershipDeparted.Store(true)
	result, err := f.service.feishu.ReconcileMemberships(t.Context())
	if err != nil || result.Checked != 1 || result.Departed != 1 {
		t.Fatal(result, err)
	}
	assertFeishuDeparture(t, f, true)
	f.status(f.userinfo(tokens["access_token"].(string)), 401)
	f.invalidRefresh("example-web", tokens["refresh_token"].(string))
	basic := map[string]string{"Authorization": "Basic " + base64.StdEncoding.EncodeToString([]byte("example-web:"+f.secret))}
	f.status(f.call(browserClient(), "POST", "/oauth/revoke", url.Values{"token": {tokens["refresh_token"].(string)}}, basic), 200)
	f.status(f.exchange("example-web", code, codeVerifier), 400)
	assertion := f.submit(samlLogin.body, "continue", url.Values{"member": {f.member.ID}, "consent": {"yes"}})
	if strings.Contains(assertion.body, "SAMLResponse") {
		t.Fatal("departed Member received a SAML assertion")
	}
	reused, _ := f.loginPage("example-web", "openid")
	if strings.Contains(reused.body, `value="`+f.member.ID+`"`) {
		t.Fatal("SSO reused departed Member")
	}
	// A new process observes the same durable evidence; a provider outage cannot clear it.
	restarted, err := identity.NewFeishuApplications(f.store, providerKey(t, f), provider)
	if err != nil {
		t.Fatal(err)
	}
	provider.membershipError = feishu.ErrUnavailable
	if _, err := restarted.ReconcileMemberships(t.Context()); !errors.Is(err, identity.ErrFeishuReconciliationIncomplete) {
		t.Fatal(err)
	}
	assertFeishuDeparture(t, f, true)
	provider.membershipError = nil
	provider.membershipDeparted.Store(false)
	if result, err := restarted.ReconcileMemberships(t.Context()); err != nil || result.Present != 1 {
		t.Fatal(result, err)
	}
	assertFeishuDeparture(t, f, false)
	// Recovery does not revive a grant rejected/revoked while departed.
	f.invalidRefresh("example-web", tokens["refresh_token"].(string))
	var members int
	if err := f.store.Database().QueryRow(t.Context(), "SELECT count(*) FROM members WHERE organization_id=$1", f.member.OrganizationID).Scan(&members); err != nil || members != 1 {
		t.Fatal("reconciliation provisioned duplicate identities", members, err)
	}
}

func TestFeishuMembershipUnknownAndSourceFailuresAreDistinct(t *testing.T) {
	for _, kind := range []string{"unknown user", "permissions", "outage", "application revoked"} {
		t.Run(kind, func(t *testing.T) {
			f, provider, _ := admittedFeishuFixture(t)
			switch kind {
			case "unknown user":
				provider.membershipError = feishu.ErrMembershipUnknown
			case "permissions":
				provider.membershipError = feishu.ErrPermissionDenied
			case "outage":
				provider.membershipError = feishu.ErrUnavailable
			case "application revoked":
				provider.revoked.Store(true)
			}
			result, err := f.service.feishu.ReconcileMemberships(t.Context())
			if !errors.Is(err, identity.ErrFeishuReconciliationIncomplete) {
				t.Fatal(result, err)
			}
			if kind == "permissions" && result.PermissionDenied != 1 || kind == "unknown user" && result.Unknown != 1 {
				t.Fatal("unsafe operational classification", result)
			}
			assertFeishuDeparture(t, f, false)
			// Independent phone authentication retains its own eligibility.
			page, verifier := f.loginPage("example-web", "openid")
			f.status(f.exchange("example-web", f.complete(page, f.member.ID), verifier), 200)
			if kind == "application revoked" {
				providers, err := f.store.Providers(t.Context(), f.member.OrganizationID)
				if err != nil || providers[0].AuthorizationStatus != "revoked" {
					t.Fatal("application denial not recorded separately", err)
				}
			}
		})
	}
}

func TestFeishuMembershipStaleObservationsCannotOverridePolicy(t *testing.T) {
	for _, kind := range []string{"member", "organization", "provider", "authorization", "binding", "factor", "other observation"} {
		t.Run(kind, func(t *testing.T) {
			f, provider, id := admittedFeishuFixture(t)
			provider.membershipDeparted.Store(true)
			provider.membershipBefore = func() {
				query := ""
				args := []any{id}
				switch kind {
				case "member":
					query = "UPDATE members SET manual_block=true,eligibility_revision=eligibility_revision+1 WHERE organization_id=(SELECT organization_id FROM feishu_applications WHERE namespace=$1)"
				case "organization":
					query = "UPDATE organizations SET status='disabled',lifecycle_revision=lifecycle_revision+1 WHERE id=(SELECT organization_id FROM feishu_applications WHERE namespace=$1)"
				case "provider":
					query = "UPDATE feishu_applications SET revision=revision+1 WHERE namespace=$1"
				case "authorization":
					query = "UPDATE feishu_applications SET authorization_revision=authorization_revision+1 WHERE namespace=$1"
				case "binding":
					query = "UPDATE member_auth_factor_bindings SET status='revoked',revoked_at=clock_timestamp() WHERE provider_namespace=$1"
				case "factor":
					query = "UPDATE authentication_factors SET status='disabled' WHERE namespace=$1"
				case "other observation":
					provider.membershipBefore = nil
					provider.membershipDeparted.Store(false)
					if _, err := f.service.feishu.ReconcileMemberships(t.Context()); err != nil {
						t.Fatal(err)
					}
					provider.membershipDeparted.Store(true)
					return
				}
				if _, err := f.store.Database().Exec(t.Context(), query, args...); err != nil {
					t.Fatal(err)
				}
			}
			result, err := f.service.feishu.ReconcileMemberships(t.Context())
			if !errors.Is(err, identity.ErrFeishuReconciliationIncomplete) || result.Conflicts != 1 {
				t.Fatal("stale observation committed", result, err)
			}
			assertFeishuDeparture(t, f, false)
		})
	}
}

func TestFeishuReturningEmployeePreservesLocalRevocations(t *testing.T) {
	for _, kind := range []string{"manual block", "binding revoked", "DingTalk departure"} {
		t.Run(kind, func(t *testing.T) {
			f, provider, _ := admittedFeishuFixture(t)
			provider.membershipDeparted.Store(true)
			if _, err := f.service.feishu.ReconcileMemberships(t.Context()); err != nil {
				t.Fatal(err)
			}
			query := ""
			switch kind {
			case "manual block":
				query = "UPDATE members SET manual_block=true,eligibility_revision=eligibility_revision+1"
			case "binding revoked":
				query = "UPDATE member_auth_factor_bindings SET status='revoked',revoked_at=clock_timestamp() WHERE factor_type='feishu'"
			case "DingTalk departure":
				query = "UPDATE members SET external_departure=true,eligibility_revision=eligibility_revision+1"
			}
			if _, err := f.store.Database().Exec(t.Context(), query); err != nil {
				t.Fatal(err)
			}
			provider.membershipDeparted.Store(false)
			if _, err := f.service.feishu.ReconcileMemberships(t.Context()); err != nil {
				t.Fatal(err)
			}
			if kind == "binding revoked" {
				var status string
				if err := f.store.Database().QueryRow(t.Context(), "SELECT status FROM member_auth_factor_bindings WHERE factor_type='feishu'").Scan(&status); err != nil || status != "revoked" {
					t.Fatal("binding revived", err)
				}
			} else {
				member, err := f.store.Member(t.Context(), f.member.OrganizationID, f.member.ID)
				if err != nil || member.Status != "blocked" {
					t.Fatal("local block cleared", member, err)
				}
			}
		})
	}
}

func TestFeishuDepartureBeforeLoginAndFinalAdmission(t *testing.T) {
	for _, when := range []string{"before login", "during directory I/O", "before admission"} {
		t.Run(when, func(t *testing.T) {
			f, provider, id := admittedFeishuFixture(t)
			if when == "before admission" {
				_, login, err := f.service.feishu.LoginSource(t.Context(), f.member.OrganizationID, id)
				if err != nil {
					t.Fatal(err)
				}
				proof, err := f.service.feishu.Verify(t.Context(), login, f.server.URL+feishuCallbackPath, "synthetic-code", config.RandomSecret())
				if err != nil {
					t.Fatal(err)
				}
				provider.membershipDeparted.Store(true)
				if _, err := f.service.feishu.ReconcileMemberships(t.Context()); err != nil {
					t.Fatal(err)
				}
				err = pgx.BeginFunc(t.Context(), f.store.Database(), func(tx pgx.Tx) error { _, err := f.service.feishu.Admit(t.Context(), tx, proof); return err })
				if err == nil {
					t.Fatal("stale proof admitted departed identity")
				}
				return
			}
			callback, _ := feishuLoginCallback(t, f, id)
			if when == "before login" {
				provider.membershipDeparted.Store(true)
			} else {
				provider.membershipBefore = func() { provider.membershipDeparted.Store(true) }
			}
			response := f.call(f.browser, "GET", callback, nil, nil)
			if response.status == 303 || strings.Contains(response.body, "SAMLResponse") {
				t.Fatal("departed identity authenticated")
			}
			assertFeishuDeparture(t, f, true)
		})
	}
}

func TestFeishuMembershipWorkerRecoversOnRestart(t *testing.T) {
	f, provider, _ := admittedFeishuFixture(t)
	provider.membershipDeparted.Store(true)
	ctx, cancel := context.WithCancel(t.Context())
	f.service.feishu.RunSynchronization(ctx, func(result identity.FeishuReconciliation, err error) {
		if err != nil || result.Departed != 1 {
			t.Error(result, err)
		}
		cancel()
	})
	assertFeishuDeparture(t, f, true)
	restarted, err := identity.NewFeishuApplications(f.store, providerKey(t, f), provider)
	if err != nil {
		t.Fatal(err)
	}
	provider.membershipDeparted.Store(false)
	ctx, cancel = context.WithCancel(t.Context())
	restarted.RunSynchronization(ctx, func(result identity.FeishuReconciliation, err error) {
		if err != nil || result.Present != 1 {
			t.Error(result, err)
		}
		cancel()
	})
	assertFeishuDeparture(t, f, false)
}

func TestFeishuDepartureDuringFinalIssuance(t *testing.T) {
	for _, protocol := range []string{"code", "refresh", "saml"} {
		t.Run(protocol, func(t *testing.T) {
			f, provider, _ := admittedFeishuFixture(t)
			var issue func() reply
			if protocol == "saml" {
				sp := enableSAML(t, f)
				page := samlPage(t, f, sp)
				issue = func() reply {
					return f.submit(page.body, "continue", url.Values{"member": {f.member.ID}, "consent": {"yes"}})
				}
			} else {
				page, verifier := f.loginPage("example-web", "openid offline_access")
				code := f.complete(page, f.member.ID)
				if protocol == "code" {
					issue = func() reply { return f.exchange("example-web", code, verifier) }
				} else {
					response := f.exchange("example-web", code, verifier)
					f.status(response, 200)
					token := jsonObject(t, response)["refresh_token"].(string)
					issue = func() reply { return f.refresh("example-web", token, "") }
				}
			}
			tx, err := f.store.Database().Begin(t.Context())
			if err != nil {
				t.Fatal(err)
			}
			defer tx.Rollback(t.Context())
			// Hold the session row so issuance passes its initial reads and then
			// waits at the final transaction while reconciliation commits.
			if _, err := tx.Exec(t.Context(), "SELECT id FROM authentication_sessions FOR UPDATE"); err != nil {
				t.Fatal(err)
			}
			done := make(chan reply, 1)
			go func() { done <- issue() }()
			deadline := time.Now().Add(10 * time.Second)
			for {
				var waiting bool
				if err := f.store.Database().QueryRow(t.Context(), "SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE datname=current_database() AND wait_event_type='Lock')").Scan(&waiting); err != nil {
					t.Fatal(err)
				}
				if waiting {
					break
				}
				if time.Now().After(deadline) {
					t.Fatal("issuance did not reach the session transaction")
				}
				time.Sleep(10 * time.Millisecond)
			}
			provider.membershipDeparted.Store(true)
			if _, err := f.service.feishu.ReconcileMemberships(t.Context()); err != nil {
				t.Fatal(err)
			}
			if err := tx.Commit(t.Context()); err != nil {
				t.Fatal(err)
			}
			result := <-done
			if protocol == "saml" {
				if strings.Contains(result.body, "SAMLResponse") {
					t.Fatal("in-flight SAML issuance bypassed departure")
				}
			} else {
				f.status(result, 400)
			}
		})
	}
}

func TestFeishuMembershipBoundedRetriesVisitEveryAdmittedIdentity(t *testing.T) {
	f, provider, id := admittedFeishuFixture(t)
	for range identity.FeishuMembershipBatchSize + 1 {
		member, err := f.store.CreateMember(t.Context(), identity.OperatorPrincipal(), f.member.OrganizationID, "", "Synthetic admitted employee")
		if err != nil {
			t.Fatal(err)
		}
		factor, err := f.store.EnsureFactor(t.Context(), "feishu", id, "ou_"+member.ID)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := f.store.BindFactor(t.Context(), identity.OperatorPrincipal(), member.OrganizationID, member.ID, factor.ID); err != nil {
			t.Fatal(err)
		}
	}
	for range 2 {
		result, err := f.service.feishu.ReconcileMemberships(t.Context())
		if !errors.Is(err, identity.ErrFeishuReconciliationIncomplete) || result.Checked != identity.FeishuMembershipBatchSize {
			t.Fatal("unbounded or incorrectly classified batch", result, err)
		}
	}
	var attempts, departures int
	if err := f.store.Database().QueryRow(t.Context(), "SELECT count(*) FILTER (WHERE attempted_at>'-infinity'),count(*) FILTER (WHERE departed) FROM feishu_memberships").Scan(&attempts, &departures); err != nil || attempts != identity.FeishuMembershipBatchSize+2 || departures != 0 {
		t.Fatal("failed identities starved later work", attempts, departures, err)
	}
	if provider.membershipCalls.Load() != 2*identity.FeishuMembershipBatchSize {
		t.Fatal("unexpected directory discovery")
	}
}

func TestFeishuDepartureEvidenceRemainsIndependentAcrossApplications(t *testing.T) {
	f, provider, first := admittedFeishuFixture(t)
	var grantID string
	if err := f.store.Database().QueryRow(t.Context(), "SELECT id FROM oidc_grants WHERE data->>'memberId'=$1", f.member.ID).Scan(&grantID); err != nil {
		t.Fatal(err)
	}
	enabled := true
	second, err := identity.NewManagementService(f.store, nil, f.service.feishu, 0).ConfigureProvider(t.Context(), identity.ManagementPrincipal(f.member.ID, grantID), f.member.OrganizationID, "feishu", "", identity.ProviderInput{DisplayName: "Second synthetic Feishu", TenantID: "example-tenant", ClientID: "cli_second", ClientSecret: config.RandomSecret(), Enabled: &enabled})
	if err != nil {
		t.Fatal(err)
	}
	factor, err := f.store.EnsureFactor(t.Context(), "feishu", second.ID, "ou_example")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.store.BindFactor(t.Context(), identity.OperatorPrincipal(), f.member.OrganizationID, f.member.ID, factor.ID); err != nil {
		t.Fatal(err)
	}
	departed := map[string]bool{"cli_first": true, "cli_second": false}
	provider.membershipResult = func(clientID, openID string) (bool, error) {
		if openID != "ou_example" {
			t.Fatal("foreign subject")
		}
		return departed[clientID], nil
	}
	if _, err := f.service.feishu.ReconcileMemberships(t.Context()); err != nil {
		t.Fatal(err)
	}
	assertFeishuDeparture(t, f, true)
	if _, err := f.store.Database().Exec(t.Context(), "UPDATE feishu_applications SET enabled=false WHERE namespace=$1", first); err != nil {
		t.Fatal(err)
	}
	if _, err := f.service.feishu.ReconcileMemberships(t.Context()); err != nil {
		t.Fatal(err)
	}
	assertFeishuDeparture(t, f, true)
	if _, err := f.store.Database().Exec(t.Context(), "UPDATE feishu_applications SET enabled=true WHERE namespace=$1", first); err != nil {
		t.Fatal(err)
	}
	departed["cli_first"], departed["cli_second"] = false, true
	if _, err := f.service.feishu.ReconcileMemberships(t.Context()); err != nil {
		t.Fatal(err)
	}
	assertFeishuDeparture(t, f, true)
	departed["cli_second"] = false
	if _, err := f.service.feishu.ReconcileMemberships(t.Context()); err != nil {
		t.Fatal(err)
	}
	assertFeishuDeparture(t, f, false)
	unrelated, err := f.store.Member(t.Context(), f.otherMember.OrganizationID, f.otherMember.ID)
	if err != nil || unrelated.Status != "active" {
		t.Fatal("reconciliation affected another organization", err)
	}
}

func TestFeishuMembershipRollbackKeepsEligibilityAndEvidenceTogether(t *testing.T) {
	f, provider, _ := admittedFeishuFixture(t)
	if _, err := f.store.Database().Exec(t.Context(), "ALTER TABLE members ADD CONSTRAINT synthetic_membership_failure CHECK (eligibility_revision=0) NOT VALID"); err != nil {
		t.Fatal(err)
	}
	provider.membershipDeparted.Store(true)
	result, err := f.service.feishu.ReconcileMemberships(t.Context())
	if !errors.Is(err, identity.ErrFeishuReconciliationIncomplete) || result.Unavailable != 1 {
		t.Fatal(result, err)
	}
	assertFeishuDeparture(t, f, false)
	var checked bool
	if err := f.store.Database().QueryRow(t.Context(), "SELECT checked_at IS NOT NULL FROM feishu_memberships").Scan(&checked); err != nil || checked {
		t.Fatal("partial departure survived failed transaction", err)
	}
}

func TestFeishuDepartureWaitsForIssuanceCommit(t *testing.T) {
	f, provider, _ := admittedFeishuFixture(t)
	page, verifier := f.loginPage("example-web", "openid offline_access")
	code := f.complete(page, f.member.ID)
	gate, err := f.store.Database().Acquire(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer gate.Release()
	if _, err := gate.Exec(t.Context(), "SELECT pg_advisory_lock(139140)"); err != nil {
		t.Fatal(err)
	}
	defer gate.Exec(context.Background(), "SELECT pg_advisory_unlock(139140)")
	if _, err := f.store.Database().Exec(t.Context(), `CREATE FUNCTION pause_feishu_issue() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN PERFORM pg_advisory_xact_lock(139140); RETURN NEW; END $$;
 CREATE TRIGGER pause_feishu_issue BEFORE INSERT ON oidc_access_tokens FOR EACH ROW EXECUTE FUNCTION pause_feishu_issue()`); err != nil {
		t.Fatal(err)
	}
	issuance := make(chan reply, 1)
	go func() { issuance <- f.exchange("example-web", code, verifier) }()
	wait := func(query string) {
		t.Helper()
		deadline := time.Now().Add(10 * time.Second)
		for {
			var ready bool
			if err := f.store.Database().QueryRow(t.Context(), query).Scan(&ready); err != nil {
				t.Fatal(err)
			}
			if ready {
				return
			}
			if time.Now().After(deadline) {
				t.Fatal("operation did not reach commit boundary")
			}
			time.Sleep(10 * time.Millisecond)
		}
	}
	wait("SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE datname=current_database() AND wait_event='advisory')")
	provider.membershipDeparted.Store(true)
	reconciliation := make(chan error, 1)
	go func() { _, err := f.service.feishu.ReconcileMemberships(t.Context()); reconciliation <- err }()
	wait("SELECT count(*)>=2 FROM pg_stat_activity WHERE datname=current_database() AND wait_event_type='Lock'")
	select {
	case err := <-reconciliation:
		t.Fatal("departure committed past in-flight issuance lock", err)
	default:
	}
	if _, err := gate.Exec(t.Context(), "SELECT pg_advisory_unlock(139140)"); err != nil {
		t.Fatal(err)
	}
	result := <-issuance
	f.status(result, 200)
	if err := <-reconciliation; err != nil {
		t.Fatal(err)
	}
	assertFeishuDeparture(t, f, true)
	f.status(f.userinfo(jsonObject(t, result)["access_token"].(string)), 401)
}

func TestFeishuDepartureBeforeAuthorizationCodePersistence(t *testing.T) {
	f, provider, _ := admittedFeishuFixture(t)
	page, _ := f.loginPage("example-web", "openid offline_access")
	confirmed := f.submit(page.body, "continue", url.Values{"member": {f.member.ID}, "consent": {"yes"}})
	f.status(confirmed, 303)
	provider.membershipDeparted.Store(true)
	if _, err := f.service.feishu.ReconcileMemberships(t.Context()); err != nil {
		t.Fatal(err)
	}
	response := f.call(f.browser, "GET", confirmed.header.Get("Location"), nil, nil)
	location, err := url.Parse(response.header.Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	if location.Query().Get("code") != "" {
		t.Fatal("departed identity received an authorization code")
	}
	var issued bool
	confirmationURL, err := url.Parse(confirmed.header.Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	if err := f.store.Database().QueryRow(t.Context(), "SELECT code_hash IS NOT NULL FROM authentication_requests WHERE id=$1", confirmationURL.Query().Get("id")).Scan(&issued); err != nil || issued {
		t.Fatal("departure bypassed final code persistence check", err)
	}
}
