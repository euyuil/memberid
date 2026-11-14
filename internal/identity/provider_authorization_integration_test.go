//go:build integration

package identity

import (
	"context"
	"errors"
	"testing"

	"github.com/euyuil/memberid/internal/feishu"
)

type checkFeishuFunc func(context.Context, string, string) error

func (fn checkFeishuFunc) CheckAuthorization(ctx context.Context, client, secret string) error {
	return fn(ctx, client, secret)
}
func (fn checkFeishuFunc) Login(context.Context, string, string, string, string, string) (feishu.Profile, error) {
	return feishu.Profile{}, feishu.ErrUnavailable
}

func TestProviderSaveAuthorizationAfterVerification(t *testing.T) {
	for _, kind := range []string{"dingtalk", "feishu"} {
		t.Run(kind, func(t *testing.T) {
			s, dingTalk, org, key := applicationFixture(t)
			otherOrg, _ := organizationAndMember(t, s)
			local, factor := administratorMember(t, s, org.ID, 91)
			administratorMember(t, s, org.ID, 92)
			principal := administratorActor(t, s, local, factor).Principal()
			calls := 0
			onCheck := func() error { calls++; return nil }
			dingTalk.checker = checkDingTalkFunc(func(context.Context, string, string, string) error { return onCheck() })
			feishuApps, err := NewFeishuApplications(s, key, checkFeishuFunc(func(context.Context, string, string) error { return onCheck() }))
			if err != nil {
				t.Fatal(err)
			}
			enabled := true
			input := ProviderInput{DisplayName: "Example provider", TenantID: "example-tenant", ClientID: "cli_example", ClientSecret: "synthetic-provider-secret", Enabled: &enabled}
			if _, err := ConfigureProvider(t.Context(), principal, otherOrg.ID, kind, "", input, dingTalk, feishuApps); !errors.Is(err, ErrForbidden) || calls != 0 {
				t.Fatal("cross-organization provider call", calls, err)
			}
			if _, err := s.ManagementProviders(t.Context(), principal, otherOrg.ID); !errors.Is(err, ErrForbidden) {
				t.Fatal(err)
			}
			created, err := ConfigureProvider(t.Context(), principal, org.ID, kind, "", input, dingTalk, feishuApps)
			if err != nil || calls != 1 {
				t.Fatal(created, calls, err)
			}
			enabled = false
			input.DisplayName, input.ClientSecret, input.ExpectedRevision = "Disabled provider", "", created.Revision
			updated, err := ConfigureProvider(t.Context(), principal, org.ID, kind, created.ID, input, dingTalk, feishuApps)
			if err != nil || updated.Enabled || updated.DisplayName != input.DisplayName {
				t.Fatal(updated, err)
			}
			providers, err := s.ManagementProviders(t.Context(), principal, org.ID)
			if err != nil || len(providers) != 1 || providers[0].ID != created.ID {
				t.Fatal(providers, err)
			}
			enabled = true
			input.DisplayName, input.ClientSecret, input.ExpectedRevision = "Must not be saved", "synthetic-new-provider-secret", updated.Revision
			onCheck = func() error {
				calls++
				return s.SetAdministrator(t.Context(), OperatorPrincipal(), org.ID, local.ID, false)
			}
			if _, err := ConfigureProvider(t.Context(), principal, org.ID, kind, created.ID, input, dingTalk, feishuApps); !errors.Is(err, ErrForbidden) {
				t.Fatal("revoked during verification but saved", err)
			}
			providers, err = s.Providers(t.Context(), org.ID)
			if err != nil || len(providers) != 1 || providers[0].ID != updated.ID || providers[0].DisplayName != updated.DisplayName || providers[0].Enabled || providers[0].Revision != updated.Revision || calls != 2 {
				t.Fatal("denied configuration changed stored provider", providers, calls, err)
			}
			events, err := s.ManagementEvents(t.Context(), org.ID, "", 0)
			if err != nil {
				t.Fatal(err)
			}
			configurations := 0
			for _, event := range events {
				if event.Action == "provider.configure" {
					configurations++
				}
			}
			if configurations != 2 {
				t.Fatal("denied save created success audit", configurations)
			}
		})
	}
}

func TestProviderStatusPreservesLastAdministrator(t *testing.T) {
	s, apps, org, _ := applicationFixture(t)
	app, err := apps.Configure(t.Context(), OperatorPrincipal(), org.ID, DingTalkApplicationInput{CorpID: "example-corp", ClientID: "example-client", ClientSecret: "synthetic-provider-secret"})
	if err != nil {
		t.Fatal(err)
	}
	member, err := s.CreateMember(t.Context(), OperatorPrincipal(), org.ID, "", "Provider administrator")
	if err != nil {
		t.Fatal(err)
	}
	factor, err := s.EnsureFactor(t.Context(), "dingtalk", app.Namespace, "example-union")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.BindFactor(t.Context(), OperatorPrincipal(), org.ID, member.ID, factor.ID); err != nil {
		t.Fatal(err)
	}
	if err := s.SetAdministrator(t.Context(), OperatorPrincipal(), org.ID, member.ID, true); err != nil {
		t.Fatal(err)
	}
	principal := administratorActor(t, s, member, factor).Principal()
	enabled := false
	input := ProviderInput{DisplayName: "Must remain enabled", TenantID: app.CorpID, ClientID: app.ClientID, Enabled: &enabled, ExpectedRevision: app.Revision}
	if _, err := ConfigureProvider(t.Context(), principal, org.ID, "dingtalk", app.Namespace, input, apps, nil); !errors.Is(err, ErrLastAdministrator) {
		t.Fatal(err)
	}
	current, err := apps.Inspect(t.Context(), org.ID)
	if err != nil || !current.Enabled || current.Revision != app.Revision || current.DisplayName != app.DisplayName {
		t.Fatal("denied status update was not atomic", current, err)
	}
}
