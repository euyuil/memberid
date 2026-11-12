//go:build integration

package identity

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/euyuil/memberid/internal/dingtalk"
	"github.com/jackc/pgx/v5"
)

type directoryDingTalkFunc func(context.Context, string, string, string, string) (dingtalk.Member, error)

func (fn directoryDingTalkFunc) VerifyMember(ctx context.Context, corp, client, secret, union string) (dingtalk.Member, error) {
	return fn(ctx, corp, client, secret, union)
}

func TestDirectoryDistinguishesOutageFromContradiction(t *testing.T) {
	store, apps, verifier, app := verifierFixture(t)
	verified, err := admitLogin(t.Context(), verifier, verifiedLogin(t, verifier, app))
	if err != nil {
		t.Fatal(err)
	}
	members, err := store.EligibleMembers(t.Context(), verified.Factor.ID)
	if err != nil || len(members) != 1 {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name, factor      string
		providerErr, want error
		employee          string
	}{
		{name: "verified DingTalk", factor: "dingtalk"},
		{name: "verified phone", factor: "phone"},
		{name: "phone outage", factor: "phone", providerErr: dingtalk.ErrUnavailable},
		{name: "DingTalk outage", factor: "dingtalk", providerErr: dingtalk.ErrUnavailable, want: ErrProviderUnavailable},
		{name: "external contact phone", factor: "phone", providerErr: dingtalk.ErrNotMember, want: ErrIneligible},
		{name: "external contact DingTalk", factor: "dingtalk", providerErr: dingtalk.ErrNotMember, want: ErrIneligible},
		{name: "conflicting identity", factor: "phone", providerErr: dingtalk.ErrIdentityConflict, want: ErrIneligible},
		{name: "changed employee", factor: "phone", employee: "different-employee", want: ErrConflict},
	} {
		t.Run(test.name, func(t *testing.T) {
			calls := 0
			directory, err := NewDingTalkDirectory(apps, directoryDingTalkFunc(func(ctx context.Context, corp, client, secret, union string) (dingtalk.Member, error) {
				calls++
				if corp != app.CorpID || client != app.ClientID || secret == "" || union != "example-union" {
					t.Fatal("wrong directory context")
				}
				deadline, ok := ctx.Deadline()
				if !ok || time.Until(deadline) > 15*time.Second {
					t.Fatal("unbounded directory lookup")
				}
				employee := "example-employee"
				if test.employee != "" {
					employee = test.employee
				}
				return dingtalk.Member{UnionID: union, UserID: employee}, test.providerErr
			}))
			if err != nil {
				t.Fatal(err)
			}
			observation, err := directory.Observe(t.Context(), app.OrganizationID, members[0].ID, test.factor)
			if !errors.Is(err, test.want) || calls != 1 {
				t.Fatal("incorrect provider failure policy", err)
			}
			if err == nil {
				err = pgx.BeginFunc(t.Context(), store.pool, func(tx pgx.Tx) error { return observation.Validate(t.Context(), tx) })
				if err != nil {
					t.Fatal("current directory observation rejected", err)
				}
			}
		})
	}
}

func TestDirectoryPhoneWithoutVerifiedExternalIdentity(t *testing.T) {
	store, apps, organization, _ := applicationFixture(t)
	member, err := store.CreateMember(t.Context(), organization.ID, "", "Example Member")
	if err != nil {
		t.Fatal(err)
	}
	directory, err := NewDingTalkDirectory(apps, directoryDingTalkFunc(func(context.Context, string, string, string, string) (dingtalk.Member, error) {
		t.Fatal("unlinked phone Member contacted DingTalk")
		return dingtalk.Member{}, nil
	}))
	if err != nil {
		t.Fatal(err)
	}
	for _, state := range []string{"unconfigured", "explicit prebinding", "revoked prebinding"} {
		t.Run(state, func(t *testing.T) {
			if state == "explicit prebinding" {
				app, err := apps.Configure(t.Context(), organization.ID, DingTalkApplicationInput{CorpID: "example-corp", ClientID: "example-client", ClientSecret: "synthetic-secret"})
				if err != nil {
					t.Fatal(err)
				}
				factor, err := store.EnsureFactor(t.Context(), "dingtalk", app.Namespace, "example-union")
				if err != nil {
					t.Fatal(err)
				}
				if _, err := store.BindFactor(t.Context(), organization.ID, member.ID, factor.ID); err != nil {
					t.Fatal(err)
				}
			}
			if state == "revoked prebinding" {
				bindings, err := store.Bindings(t.Context(), organization.ID, member.ID)
				if err != nil || len(bindings) != 1 {
					t.Fatal(err)
				}
				if err := store.RevokeBinding(t.Context(), organization.ID, member.ID, bindings[0].FactorID); err != nil {
					t.Fatal(err)
				}
			}
			observation, err := directory.Observe(t.Context(), organization.ID, member.ID, "phone")
			if err != nil {
				t.Fatal(err)
			}
			if err := observation.Validate(t.Context(), store.pool); err != nil {
				t.Fatal(err)
			}
			if _, err := directory.Observe(t.Context(), organization.ID, member.ID, "dingtalk"); !errors.Is(err, ErrIneligible) {
				t.Fatal("unverified directory identity admitted", err)
			}
		})
	}
}

func TestDirectoryObservationExpiryAndLocalCredentialFailure(t *testing.T) {
	store, apps, verifier, app := verifierFixture(t)
	verified, err := admitLogin(t.Context(), verifier, verifiedLogin(t, verifier, app))
	if err != nil {
		t.Fatal(err)
	}
	members, err := store.EligibleMembers(t.Context(), verified.Factor.ID)
	if err != nil || len(members) != 1 {
		t.Fatal(err)
	}
	directory, err := NewDingTalkDirectory(apps, directoryDingTalkFunc(func(context.Context, string, string, string, string) (dingtalk.Member, error) {
		return dingtalk.Member{UnionID: "example-union", UserID: "example-employee"}, nil
	}))
	if err != nil {
		t.Fatal(err)
	}
	observation, err := directory.Observe(t.Context(), app.OrganizationID, members[0].ID, "dingtalk")
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := json.Marshal(observation)
	if err != nil || string(encoded) != "{}" {
		t.Fatal("directory evidence became a serialized credential", err)
	}
	directory.now = func() time.Time { return observation.observedAt.Add(time.Minute) }
	if err := observation.Validate(t.Context(), store.pool); !errors.Is(err, ErrIneligible) {
		t.Fatal("expired observation accepted", err)
	}
	directory.now = func() time.Time { return observation.observedAt.Add(-time.Second) }
	if err := observation.Validate(t.Context(), store.pool); !errors.Is(err, ErrIneligible) {
		t.Fatal("future observation accepted", err)
	}
	directory.now = time.Now
	if _, err := store.pool.Exec(t.Context(), "UPDATE dingtalk_applications SET secret_ciphertext=$2 WHERE organization_id=$1", app.OrganizationID, []byte("synthetic-invalid-ciphertext")); err != nil {
		t.Fatal(err)
	}
	if _, err := directory.Observe(t.Context(), app.OrganizationID, members[0].ID, "phone"); err != nil {
		t.Fatal("local credential outage disabled phone fallback", err)
	}
	if _, err := directory.Observe(t.Context(), app.OrganizationID, members[0].ID, "dingtalk"); !errors.Is(err, ErrProviderConfiguration) {
		t.Fatal("unreadable credentials admitted DingTalk", err)
	}
}
