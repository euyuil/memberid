//go:build integration

package oidcprovider

import (
	"fmt"
	"os"
	"slices"
	"testing"
	"time"

	"github.com/euyuil/memberid/internal/identity"
)

// This opt-in profile uses an isolated database and stubbed providers. It reports
// SQL calls and HTTP latency, not production throughput or external-provider cost.
func TestConsoleQueryProfile(t *testing.T) {
	if os.Getenv("MEMBERID_TEST_QUERY_PROFILE") != "1" {
		t.Skip("set MEMBERID_TEST_QUERY_PROFILE=1 and preload pg_stat_statements")
	}
	f := newFixture(t)
	if _, err := f.store.Database().Exec(t.Context(), "CREATE EXTENSION pg_stat_statements"); err != nil {
		t.Fatal(err)
	}
	factor, err := f.store.PhoneFactor(t.Context(), "+8619900000001")
	if err != nil {
		t.Fatal(err)
	}
	platform, err := f.store.CreateMember(t.Context(), identity.OperatorPrincipal(), identity.SystemOrganizationID, "", "Profile administrator")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.store.BindFactor(t.Context(), identity.OperatorPrincipal(), platform.OrganizationID, platform.ID, factor.ID); err != nil {
		t.Fatal(err)
	}
	for _, member := range []identity.Member{platform, f.member} {
		if err := f.store.SetAdministrator(t.Context(), identity.OperatorPrincipal(), member.OrganizationID, member.ID, true); err != nil {
			t.Fatal(err)
		}
	}
	for i, member := range []identity.Member{f.member, f.otherMember} {
		backup, err := f.store.CreateMember(t.Context(), identity.OperatorPrincipal(), member.OrganizationID, "", "Profile backup")
		if err != nil {
			t.Fatal(err)
		}
		backupFactor, err := f.store.EnsureFactor(t.Context(), "phone", "phone:e164", fmt.Sprintf("+861990000%04d", i+31))
		if err != nil {
			t.Fatal(err)
		}
		if _, err := f.store.BindFactor(t.Context(), identity.OperatorPrincipal(), backup.OrganizationID, backup.ID, backupFactor.ID); err != nil {
			t.Fatal(err)
		}
		if err := f.store.SetAdministrator(t.Context(), identity.OperatorPrincipal(), backup.OrganizationID, backup.ID, true); err != nil {
			t.Fatal(err)
		}
	}
	server := consoleFixture(t, f)
	consoleLogin(t, f, server, platform.ID)
	csrf := consoleJSON(t, f, server, "GET", "/api/session", "", "", 200)["csrf"].(string)
	base := "/api/organizations/" + f.member.OrganizationID
	type operation struct {
		name, method, path, body string
		maxQueries               int64
	}
	operations := []operation{
		{"session", "GET", "/api/session", "", 2},
		{"organizations", "GET", "/api/organizations", "", 3},
		{"organization", "GET", base, "", 3},
		{"global members", "GET", "/api/members", "", 3},
		{"organization members", "GET", base + "/members", "", 5},
		{"member detail", "GET", base + "/members/" + f.member.ID, "", 5},
		{"providers", "GET", base + "/providers", "", 4},
		{"events", "GET", "/api/events", "", 3},
		{"create organization", "POST", "/api/organizations", `{"name":"Profile organization"}`, 6},
		{"create member", "POST", base + "/members", `{"displayName":"Profile member"}`, 6},
		{"update organization", "PATCH", base, `{"name":"Profile organization"}`, 8},
		{"update member", "PATCH", base + "/members/" + f.member.ID, `{"displayName":"Profile member"}`, 11},
	}
	count := func() int64 {
		t.Helper()
		var calls int64
		err := f.store.Database().QueryRow(t.Context(), `SELECT COALESCE(sum(calls),0)::bigint FROM pg_stat_statements
 WHERE dbid=(SELECT oid FROM pg_database WHERE datname=current_database())
 AND query NOT ILIKE '%pg_stat_statements%' AND lower(query) NOT IN ('begin','commit','rollback')`).Scan(&calls)
		if err != nil {
			t.Fatal(err)
		}
		return calls
	}
	for _, op := range operations {
		t.Run(op.name, func(t *testing.T) {
			for range 5 {
				consoleJSON(t, f, server, op.method, op.path, csrf, op.body, 200)
			}
			before := count()
			durations := make([]time.Duration, 100)
			for i := range durations {
				start := time.Now()
				consoleJSON(t, f, server, op.method, op.path, csrf, op.body, 200)
				durations[i] = time.Since(start)
			}
			after := count()
			if after-before > op.maxQueries*int64(len(durations)) {
				t.Errorf("%s exceeded the SQL budget: %d calls for %d requests (max %d/request)", op.name, after-before, len(durations), op.maxQueries)
			}
			slices.Sort(durations)
			t.Logf("%s: %.2f SQL/request, p50=%s, p95=%s", op.name, float64(after-before)/float64(len(durations)), durations[49], durations[94])
		})
	}
	// These mutations are measured once to preserve their meaningful state changes.
	for _, op := range []operation{
		{"grant administrator", "PUT", "/api/organizations/" + f.otherMember.OrganizationID + "/members/" + f.otherMember.ID + "/administrator", `{"enabled":true}`, 11},
		{"revoke administrator", "PUT", base + "/members/" + f.member.ID + "/administrator", `{"enabled":false}`, 10},
		{"create feishu", "POST", base + "/providers/feishu", `{"displayName":"Profile provider","tenantId":"example-tenant","clientId":"cli_profile","clientSecret":"synthetic-provider-secret","enabled":true}`, 9},
	} {
		before := count()
		consoleJSON(t, f, server, op.method, op.path, csrf, op.body, 200)
		calls := count() - before
		if calls > op.maxQueries {
			t.Errorf("%s exceeded the SQL budget: %d calls (max %d)", op.name, calls, op.maxQueries)
		}
		t.Logf("%s: %d SQL/request (single mutation)", op.name, calls)
	}
}
