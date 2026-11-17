//go:build integration

package identity

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"
)

func TestManagementBindingDetailsStayScoped(t *testing.T) {
	s, dingTalk, org, key := applicationFixture(t)
	local, phone := administratorMember(t, s, org.ID, 91)
	principal := administratorActor(t, s, local, phone).Principal()
	feishuApps, err := NewFeishuApplications(s, key, checkFeishuFunc(func(_ context.Context, _, _ string) error { return nil }))
	if err != nil {
		t.Fatal(err)
	}
	service := NewManagementService(s, dingTalk, feishuApps, time.Hour)
	enabled := true
	for _, kind := range []string{"feishu", "dingtalk"} {
		app, err := service.ConfigureProvider(t.Context(), principal, org.ID, kind, "", ProviderInput{DisplayName: "Example " + kind, TenantID: "example-tenant", ClientID: "cli_example", ClientSecret: "synthetic-provider-secret", Enabled: &enabled})
		if err != nil {
			t.Fatal(err)
		}
		factor, err := s.EnsureFactor(t.Context(), kind, app.ID, "example-external-subject")
		if err != nil {
			t.Fatal(err)
		}
		if _, err = s.BindFactor(t.Context(), OperatorPrincipal(), org.ID, local.ID, factor.ID); err != nil {
			t.Fatal(err)
		}
		if kind == "dingtalk" {
			if _, err = s.pool.Exec(t.Context(), `INSERT INTO dingtalk_identities(member_id,organization_id,namespace,union_id,external_member_id,verified_at) VALUES($1,$2,$3,$4,'example-employee',clock_timestamp())`, local.ID, org.ID, app.ID, factor.Subject); err != nil {
				t.Fatal(err)
			}
		}
	}
	detail, err := service.Member(t.Context(), principal, org.ID, local.ID)
	if err != nil || len(detail.Bindings) != 3 {
		t.Fatal(detail, err)
	}
	for _, binding := range detail.Bindings {
		if binding.FactorType == "phone" {
			if binding.ExternalSubject != "" || binding.ProviderID != "" {
				t.Fatal("phone identity exposed", binding)
			}
			continue
		}
		if binding.ProviderName != "Example "+binding.FactorType || binding.ClientID != "cli_example" || binding.TenantID != "example-tenant" || binding.ExternalSubject != "example-external-subject" || binding.CreatedAt.IsZero() {
			t.Fatal(binding)
		}
		if binding.FactorType == "dingtalk" && binding.ExternalMemberID != "example-employee" {
			t.Fatal(binding)
		}
	}
	encoded, _ := json.Marshal(detail)
	if strings.Contains(string(encoded), "synthetic-provider-secret") || strings.Contains(string(encoded), phone.Subject) {
		t.Fatal("credential or phone leaked")
	}
	otherOrg, other := organizationAndMember(t, s)
	if _, err := service.Member(t.Context(), principal, otherOrg.ID, other.ID); !errors.Is(err, ErrForbidden) {
		t.Fatal(err)
	}
	if _, err := service.Member(t.Context(), principal, org.ID, other.ID); !errors.Is(err, ErrNotFound) {
		t.Fatal(err)
	}
}
