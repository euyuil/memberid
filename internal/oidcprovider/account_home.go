package oidcprovider

import (
	_ "embed"
	"html/template"
	"net/http"
	"net/url"

	"github.com/zhizhun-tech/memberid/internal/config"
	"github.com/zhizhun-tech/memberid/internal/identity"
)

//go:embed account_home.html
var accountHomeHTML string
var accountHomePage = template.Must(template.New("account-home").Parse(accountHomeHTML))

func (service *Service) accountHome(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", "GET")
		http.Error(w, "Method not allowed", 405)
		return
	}
	if !accountFields(r, "memberId") || len(r.Form["memberId"]) != 1 || !identity.ValidID(r.Form.Get("memberId"), identity.MemberKind) {
		http.Error(w, "Invalid account request", 400)
		return
	}
	session, err := service.accountSession(r, service.store.Database(), false)
	if err != nil {
		http.Error(w, "Sign in through a registered application, then reopen this account page.", 401)
		return
	}
	member, _, err := service.accountMember(r, session, r.Form.Get("memberId"))
	if err != nil {
		http.Error(w, "This Member identity is not available to the current session.", 403)
		return
	}
	if !service.freshAccountSession(session) {
		http.Error(w, "Fresh authentication is required. Reopen this page from the management console after signing in again.", 401)
		return
	}
	providers, err := service.store.Providers(r.Context(), member.OrganizationID)
	if err != nil {
		http.Error(w, "Account management temporarily unavailable", 503)
		return
	}
	bindings, err := service.store.Bindings(r.Context(), member.OrganizationID, member.ID)
	if err != nil {
		http.Error(w, "Account management temporarily unavailable", 503)
		return
	}
	occupiedKinds, occupiedProviders := map[string]bool{}, map[string]bool{}
	for _, binding := range bindings {
		if binding.FactorType != "feishu" {
			occupiedKinds[binding.FactorType] = true
			continue
		}
		factor, err := service.store.Factor(r.Context(), binding.FactorID)
		if err != nil {
			http.Error(w, "Account management temporarily unavailable", 503)
			return
		}
		occupiedProviders[factor.Namespace] = true
	}
	type link struct{ Label, URL string }
	links := []link{}
	query := url.Values{"memberId": {member.ID}}.Encode()
	if service.phone != nil && !occupiedKinds["phone"] {
		links = append(links, link{"Link phone", "/account/link/phone?" + query})
	}
	for _, kind := range []string{"dingtalk", "feishu"} {
		if !service.accountProviderEnabled(kind) || occupiedKinds[kind] || kind == "feishu" && member.OrganizationID == service.store.SystemOrganizationID() {
			continue
		}
		for _, provider := range providers {
			if provider.Type == kind && provider.Enabled && provider.AuthorizationStatus == "active" && !occupiedProviders[provider.ID] {
				label := "Link DingTalk"
				if kind == "feishu" {
					label = "Link Feishu"
				}
				links = append(links, link{label, "/account/link/" + kind + "?" + query})
				break
			}
		}
	}
	nonce := config.RandomSecret()
	w.Header().Set("Content-Security-Policy", "default-src 'none'; style-src 'nonce-"+nonce+"'; base-uri 'none'; frame-ancestors 'none'")
	writeHTMLPage(w, accountHomePage, struct {
		Member identity.Member
		Links  []link
		Nonce  string
	}{member, links, nonce})
}
