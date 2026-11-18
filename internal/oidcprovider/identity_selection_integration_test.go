//go:build integration

package oidcprovider

import (
	"net/url"
	"strings"
	"testing"
)

func TestOIDCIdentityPreselectionKeepsConsentExplicit(t *testing.T) {
	t.Run("sole eligible Member", func(t *testing.T) {
		f := newFixture(t)
		page, verifier := f.loginPage("example-web", "openid profile")
		selected := `<option value="` + f.member.ID + `" selected>`
		if strings.Contains(page.body, selected) {
			t.Fatal("identity selected before verification")
		}

		page = f.verifyPhone(page)
		if !strings.Contains(page.body, selected) {
			t.Fatal("sole eligible identity is not selected after verification")
		}
		if !strings.Contains(page.body, `name="consent" type="checkbox" value="yes" required`) {
			t.Fatal("consent control must require explicit confirmation")
		}
		refused := f.submit(page.body, "continue", url.Values{"member": {f.member.ID}})
		f.status(refused, 200)
		if !strings.Contains(refused.body, "Approve the requested identity information before continuing.") {
			t.Fatal("preselected Member proceeded without consent")
		}

		code := f.complete(refused, f.member.ID)
		f.status(f.exchange("example-web", code, verifier), 200)
	})

}
