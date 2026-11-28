//go:build integration

package oidcprovider

import (
	"net/url"
	"slices"
	"strings"
	"testing"

	"github.com/zhizhun-tech/memberid/internal/config"
	"github.com/zhizhun-tech/memberid/internal/identity"
)

func TestMemberTokenOrganization(t *testing.T) {
	f := newFixture(t)
	ctx, op := t.Context(), identity.OperatorPrincipal()
	owner, err := f.store.CreateOrganization(ctx, op, "", "Application owner")
	if err != nil {
		t.Fatal(err)
	}
	b, c := f.member, f.otherMember // Two Members of the same person, bound to the same phone.
	another, err := f.store.CreateMember(ctx, op, b.OrganizationID, "", "Second employee")
	if err != nil {
		t.Fatal(err)
	}
	password, err := f.store.SetMemberPassword(ctx, op, b.OrganizationID, another.ID, "second")
	if err != nil {
		t.Fatal(err)
	}
	management := identity.NewManagementService(f.store, nil, nil, 0)
	app, err := management.CreateOIDCApplication(ctx, op, owner.ID, identity.OIDCApplication{
		DisplayName: "Workspace", RedirectURIs: []string{callback}, Refresh: true,
	}, config.SecretHash(f.secret), true)
	if err != nil {
		t.Fatal(err)
	}
	id := app.ClientID
	if err := management.SetOIDCPublication(ctx, op, owner.ID, id, true); err != nil {
		t.Fatal(err)
	}
	for _, m := range []identity.Member{b, c} {
		if err := management.SetOIDCEnablement(ctx, op, m.OrganizationID, id, true); err != nil {
			t.Fatal(err)
		}
	}

	const retired = "memberid.organization"
	token := func(m identity.Member, scope string) map[string]any {
		t.Helper()
		r, verifier := f.authorization(id, scope, nil)
		f.status(r, 302)
		r = f.call(f.browser, "GET", r.header.Get("Location"), nil, nil)
		r = f.selectOrganization(r, m.OrganizationID)
		if m.ID == another.ID {
			r = f.submit(r.body, "password", url.Values{"username": {"second"}, "password": {password}})
			f.status(r, 200)
		} else if strings.Contains(r.body, `id="phone"`) {
			r = f.verifyPhone(r)
		}
		if !strings.Contains(r.body, "Requested identity information: openid") || strings.Contains(r.body, retired) {
			t.Fatal("unexpected consent scope list")
		}
		result := f.exchange(id, f.complete(r, m.ID), verifier)
		f.status(result, 200)
		return jsonObject(t, result)
	}
	check := func(tokens map[string]any, m identity.Member, wantScope string) {
		t.Helper()
		for token, audience := range map[string]string{"id_token": id, "access_token": f.server.URL + "/oauth/userinfo"} {
			claims := f.signedClaims(tokens[token].(string))
			aud, _ := claims["aud"].([]any)
			if !slices.Contains(aud, any(audience)) || claims["iss"] != f.server.URL || claims["sub"] != m.ID || claims["org_id"] != m.OrganizationID {
				t.Fatalf("incorrect audience, issuer, subject or organization in %s", token)
			}
			if token == "access_token" && (len(aud) != 1 || claims["scope"] != wantScope || claims["tokenUse"] != "access") {
				t.Fatal("unexpected access token audience, scope or use")
			}
			for _, key := range []string{"organizationId", "authentication", "memberId", "factorId", "bindingId", "memberships", "roles"} {
				if _, ok := claims[key]; ok {
					t.Fatalf("unexpected %s in %s", key, token)
				}
			}
		}
		info := f.userinfo(tokens["access_token"].(string))
		f.status(info, 200)
		user := jsonObject(t, info)
		if user["org_id"] != nil || user["organizationId"] != nil {
			t.Fatal("organization claim appeared in UserInfo")
		}
	}
	check(token(b, "openid"), b, "openid")
	// A registration saved by the previous release can still contain its opt-in.
	if _, err := f.store.Database().Exec(ctx, `UPDATE oidc_clients SET registration = registration || '{"allowOrganizationScope":true}' WHERE client_id=$1`, id); err != nil {
		t.Fatal(err)
	}
	discovery := jsonObject(t, f.call(f.browser, "GET", "/.well-known/openid-configuration", nil, nil))
	scopes := discovery["scopes_supported"].([]any)
	claims := discovery["claims_supported"].([]any)
	if slices.Contains(scopes, any(retired)) || slices.Contains(claims, any("organizationId")) || !slices.Contains(claims, any("org_id")) {
		t.Fatal("unexpected organization discovery metadata")
	}

	check(token(c, "openid "+retired), c, "openid")
	phoneBrowser := f.browser
	f.browser = browserClient()
	check(token(another, "openid"), another, "openid")
	f.browser = phoneBrowser

	const optional = "openid profile offline_access"
	original := token(c, optional)
	check(original, c, optional)
	name := "Renamed consumer"
	if _, err = f.store.UpdateOrganization(ctx, op, c.OrganizationID, identity.OrganizationChange{Name: &name}); err != nil {
		t.Fatal(err)
	}
	// Model a refresh token issued before the scope was retired.
	secret := original["refresh_token"].(string)
	updated, err := f.store.Database().Exec(ctx, `UPDATE oidc_refresh_tokens SET data=jsonb_set(data,'{scopes}',(data->'scopes') || to_jsonb($1::text)) WHERE secret_hash=$2`, retired, config.SecretHash(secret))
	if err != nil || updated.RowsAffected() != 1 {
		t.Fatal("could not seed the legacy refresh scope", err)
	}
	response := f.refresh(id, secret, "")
	f.status(response, 200)
	renewed := jsonObject(t, response)
	check(renewed, c, optional)
	response = f.refresh(id, renewed["refresh_token"].(string), "openid")
	f.status(response, 200)
	check(jsonObject(t, response), c, "openid")
}
