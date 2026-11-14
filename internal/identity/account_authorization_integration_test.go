//go:build integration

package identity

import (
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/euyuil/memberid/internal/authorization"
)

func TestAccountAuthorityResolvesSessionAndSelectedBinding(t *testing.T) {
	s := testStore(t)
	org, member := organizationAndMember(t, s)
	otherOrg, other := organizationAndMember(t, s)
	systemMember, err := s.CreateMember(t.Context(), OperatorPrincipal(), SystemOrganizationID, "", "System account Member")
	if err != nil {
		t.Fatal(err)
	}
	factor, err := s.EnsureFactor(t.Context(), "phone", "phone:e164", "+8619900010101")
	if err != nil {
		t.Fatal(err)
	}
	bindings := map[string]Binding{}
	for _, selected := range []Member{member, other, systemMember} {
		binding, err := s.BindFactor(t.Context(), OperatorPrincipal(), selected.OrganizationID, selected.ID, factor.ID)
		if err != nil {
			t.Fatal(err)
		}
		bindings[selected.ID] = binding
	}
	verification, err := json.Marshal(Verification{Factor: factor, AuthenticatedAt: time.Now(), Method: "sms"})
	if err != nil {
		t.Fatal(err)
	}
	const sessionID = "synthetic-account-session"
	if _, err := s.pool.Exec(t.Context(), "INSERT INTO oidc_sessions(id,secret_hash,verification,expires_at,absolute_expires_at) VALUES($1,$1,$2,clock_timestamp()+interval '1 hour',clock_timestamp()+interval '2 hours')", sessionID, verification); err != nil {
		t.Fatal(err)
	}
	principal := AccountPrincipal(sessionID, member.ID, factor.ID, bindings[member.ID].ID)
	own := "organizations/" + org.ID + "/members/" + member.ID
	if err := s.AuthorizeAccountView(t.Context(), principal, org.ID); err != nil {
		t.Fatal("ordinary Member account view", err)
	}
	if err := authorizeAll(t.Context(), s.pool, principal, authorization.Requirement{Target: own + "/bindings", Action: "create"}); err != nil {
		t.Fatal(err)
	}
	if err := authorizeAll(t.Context(), s.pool, principal, authorization.Requirement{Target: "organizations/" + otherOrg.ID + "/members/" + other.ID, Action: "get"}); !errors.Is(err, ErrForbidden) {
		t.Fatal("shared factor expanded selected identity", err)
	}
	if _, err := s.ManagementMember(t.Context(), principal, org.ID, member.ID); !errors.Is(err, ErrForbidden) {
		t.Fatal("account context acquired console detail", err)
	}
	wrong := AccountPrincipal(sessionID, member.ID, factor.ID, bindings[other.ID].ID)
	if err := s.AuthorizeAccountView(t.Context(), wrong, org.ID); !errors.Is(err, ErrForbidden) {
		t.Fatal("substituted source binding", err)
	}
	systemPrincipal := AccountPrincipal(sessionID, systemMember.ID, factor.ID, bindings[systemMember.ID].ID)
	if err := s.AuthorizeAccountView(t.Context(), systemPrincipal, SystemOrganizationID); err != nil {
		t.Fatal("ordinary system Member self access", err)
	}
	if err := s.SetAdministrator(t.Context(), OperatorPrincipal(), SystemOrganizationID, systemMember.ID, true); err != nil {
		t.Fatal(err)
	}
	if err := authorizeAll(t.Context(), s.pool, systemPrincipal, authorization.Requirement{Target: "organizations", Action: "create"}); !errors.Is(err, ErrForbidden) {
		t.Fatal("account context inherited platform role", err)
	}
	tx, err := s.pool.Begin(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(t.Context())
	if err := LinkPhone(t.Context(), tx, principal, Verification{Factor: factor, Method: "sms"}, PhoneLinkTarget{OrganizationID: otherOrg.ID, MemberID: other.ID, SourceFactorID: factor.ID, SourceBindingID: bindings[member.ID].ID}); !errors.Is(err, ErrForbidden) {
		t.Fatal("self binding targeted another Member", err)
	}
	if err := tx.Rollback(t.Context()); err != nil {
		t.Fatal(err)
	}
	for name, mutation := range map[string]string{
		"revoked":         "revoked_at=clock_timestamp()",
		"idle expiry":     "expires_at=clock_timestamp()-interval '1 second'",
		"absolute expiry": "absolute_expires_at=clock_timestamp()-interval '1 second'",
		"source mismatch": "verification='{}'::jsonb",
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := s.pool.Exec(t.Context(), "UPDATE oidc_sessions SET "+mutation+" WHERE id=$1", sessionID); err != nil {
				t.Fatal(err)
			}
			if err := s.AuthorizeAccountView(t.Context(), principal, org.ID); !errors.Is(err, ErrForbidden) {
				t.Fatal("invalid source session retained authority", err)
			}
			if _, err := s.pool.Exec(t.Context(), "UPDATE oidc_sessions SET revoked_at=NULL,expires_at=clock_timestamp()+interval '1 hour',absolute_expires_at=clock_timestamp()+interval '2 hours',verification=$2 WHERE id=$1", sessionID, verification); err != nil {
				t.Fatal(err)
			}
		})
	}
	if err := s.RevokeBinding(t.Context(), OperatorPrincipal(), org.ID, member.ID, factor.ID); err != nil {
		t.Fatal(err)
	}
	if err := s.AuthorizeAccountView(t.Context(), principal, org.ID); !errors.Is(err, ErrForbidden) {
		t.Fatal("revoked binding retained self access", err)
	}
	selectedOther := AccountPrincipal(sessionID, other.ID, factor.ID, bindings[other.ID].ID)
	if err := s.AuthorizeAccountView(t.Context(), selectedOther, otherOrg.ID); err != nil {
		t.Fatal("independent Member binding was revoked", err)
	}
}
