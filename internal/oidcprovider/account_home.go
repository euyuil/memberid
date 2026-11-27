package oidcprovider

import (
	"crypto/hmac"
	"crypto/sha256"
	_ "embed"
	"encoding/base64"
	"errors"
	"fmt"
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
	fields := []string{"memberId"}
	switch r.Method {
	case http.MethodGet:
	case http.MethodPost:
		fields = append(fields, "csrf", "username")
		if r.URL.RawQuery != "" {
			http.Error(w, "Invalid account request", 400)
			return
		}
	default:
		w.Header().Set("Allow", "GET, POST")
		http.Error(w, "Method not allowed", 405)
		return
	}
	if !accountFields(r, fields...) || !identity.ValidID(r.Form.Get("memberId"), identity.MemberKind) {
		http.Error(w, "Invalid account request", 400)
		return
	}
	session, err := service.accountSession(r, service.store.Database(), false)
	if err != nil {
		http.Error(w, "Sign in through a registered application, then reopen this account page.", 401)
		return
	}
	member, binding, err := service.accountMember(r, session, r.Form.Get("memberId"))
	if err != nil {
		http.Error(w, "This Member identity is not available to the current session.", 403)
		return
	}
	if !service.freshAccountSession(session) {
		http.Error(w, "Fresh authentication is required. Reopen this page from the management console after signing in again.", 401)
		return
	}
	principal := identity.AccountPrincipal(session.id, member.ID, session.verified.Factor.ID, binding)
	// Bind the form to this browser, source session and selected organization identity.
	mac := hmac.New(sha256.New, []byte(service.configuration.Secrets.ProtocolKey))
	fmt.Fprintf(mac, "memberid/account-login-name\x00%s\x00%s\x00%s\x00%s\x00%s", service.configuration.Issuer, accountBrowser(r), session.id, member.ID, binding)
	csrf := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	status, message := http.StatusOK, ""
	if r.Method == http.MethodPost {
		if !validLoginSubmission(r, service.configuration.Issuer, csrf) {
			http.Error(w, "Invalid account submission", 403)
			return
		}
		err := service.store.SetFirstAccountLoginName(r.Context(), principal, member.OrganizationID, r.PostForm.Get("username"))
		switch {
		case err == nil:
			http.Redirect(w, r, "/account?"+url.Values{"memberId": {member.ID}}.Encode(), http.StatusSeeOther)
			return
		case errors.Is(err, identity.ErrPasswordUsernameTaken):
			status, message = 409, "This username is already in use in your organization. Choose another."
		case errors.Is(err, identity.ErrConflict):
			status, message = 409, "Your login username is already set. Contact your organization administrator to change it."
		case errors.Is(err, identity.ErrInvalid):
			status, message = 400, "Use 1–64 letters, digits, dots, underscores or hyphens, starting with a letter or digit."
		case errors.Is(err, identity.ErrForbidden), errors.Is(err, identity.ErrIneligible):
			http.Error(w, "This account change is unavailable. Sign in again or contact your administrator.", 403)
			return
		default:
			http.Error(w, "Account management temporarily unavailable", 503)
			return
		}
	}
	username, err := service.store.AccountLoginName(r.Context(), principal, member.OrganizationID)
	if err != nil {
		http.Error(w, "Account management temporarily unavailable", 503)
		return
	}
	service.renderAccountHome(w, r, member, username, csrf, message, status)
}

func (service *Service) renderAccountHome(w http.ResponseWriter, r *http.Request, member identity.Member, username, csrf, message string, status int) {
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
	w.Header().Set("Content-Security-Policy", "default-src 'none'; style-src 'nonce-"+nonce+"'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'")
	writeHTMLPageStatus(w, accountHomePage, struct {
		Member                         identity.Member
		Links                          []link
		Nonce, Username, CSRF, Message string
	}{member, links, nonce, username, csrf, message}, status)
}
