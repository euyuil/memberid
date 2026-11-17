package oidcprovider

import (
	"embed"
	"html/template"
	"net/http"
	"net/url"
	"slices"
	"strings"

	"github.com/euyuil/memberid/internal/config"
	"github.com/euyuil/memberid/internal/identity"
)

//go:embed login.html
var pageFiles embed.FS
var loginPage = template.Must(template.ParseFS(pageFiles, "login.html"))

type memberChoice struct{ ID, Label string }
type pageData struct {
	Request                                                        *authorizationRequest
	ApplicationName, Scopes, Message, Nonce                        string
	SelectedMemberID                                               string
	Members                                                        []memberChoice
	Verified, Pending, PhonePending, FactorClient, ConsentRequired bool
	PhoneEnabled, ProviderEnabled, OrganizationRestricted          bool
	PasswordEnabled                                                bool
	PasswordOrganization, PasswordUsername                         string
	ProviderOrganizationID, ProviderOrganizationName               string
	Providers                                                      []identity.Provider
}

func (service *Service) renderLogin(w http.ResponseWriter, r *http.Request, request *authorizationRequest, client loginPolicy, message string) {
	members, err := service.members(r, request, client)
	if err != nil {
		http.Error(w, "Login temporarily unavailable", http.StatusServiceUnavailable)
		return
	}
	choices := []memberChoice{}
	for _, member := range members {
		organization, err := service.store.Organization(r.Context(), member.OrganizationID)
		if err != nil {
			http.Error(w, "Login temporarily unavailable", http.StatusServiceUnavailable)
			return
		}
		choices = append(choices, memberChoice{member.ID, organization.Name + " — " + member.DisplayName})
	}
	verified := request.Verification != nil
	if verified && message == "" {
		switch request.Method {
		case "dingtalk":
			message = "DingTalk verified."
		case "feishu":
			message = "Feishu verified."
		}
	}
	if verified && client.registration.SubjectKind == "member" && len(choices) == 0 {
		message = "No eligible Member identity is available. Contact your organization administrator."
	}
	if !verified && request.phonePending() && request.ChallengeID == "" && message == "" {
		message = "Phone verification is pending. Cancel verification to start again."
	}
	applicationName := client.displayName
	if applicationName == "" {
		applicationName = client.registration.ID
	}
	data := pageData{
		Request: request, ApplicationName: applicationName, Scopes: client.registration.IdentityInformation, Message: message,
		Nonce: config.RandomSecret(), Members: choices, Verified: verified,
		Pending: request.phonePending() || request.externalPending(), PhonePending: request.ChallengeID != "",
		PhoneEnabled: service.phone != nil, ProviderEnabled: client.registration.SubjectKind == "member" && (service.dingtalk != nil || service.feishu != nil),
		OrganizationRestricted: client.registration.OrganizationID != "", ProviderOrganizationID: client.registration.OrganizationID,
		FactorClient: client.registration.SubjectKind == "factor", ConsentRequired: !client.registration.Preauthorized || slices.Contains(request.prompts(), "consent"),
	}
	if request.SAML == nil && len(choices) == 1 {
		data.SelectedMemberID = choices[0].ID
	}
	if !data.OrganizationRestricted {
		data.ProviderOrganizationID = request.ProviderOrganizationID
	}
	if client.registration.SubjectKind == "member" {
		data.PasswordEnabled, err = service.store.HasPasswordCredentials(r.Context(), client.registration.OrganizationID)
		if err != nil {
			http.Error(w, "Login temporarily unavailable", http.StatusServiceUnavailable)
			return
		}
		if r.PostForm.Get("action") == "password" {
			data.PasswordOrganization, data.PasswordUsername = r.PostForm.Get("password_organization"), r.PostForm.Get("username")
		}
	}
	if !verified && !data.PhoneEnabled && !data.ProviderEnabled && !data.PasswordEnabled && data.Message == "" {
		data.Message = "No sign-in methods have been configured."
	}
	if data.ProviderEnabled && data.ProviderOrganizationID != "" {
		ctx := r.Context()
		organization, err := service.store.Organization(ctx, data.ProviderOrganizationID)
		if err != nil {
			http.Error(w, "Login temporarily unavailable", http.StatusServiceUnavailable)
			return
		}
		data.ProviderOrganizationName = organization.Name
		if organization.Status == "enabled" {
			providers, err := service.store.Providers(ctx, organization.ID)
			if err != nil {
				http.Error(w, "Login temporarily unavailable", http.StatusServiceUnavailable)
				return
			}
			for _, provider := range providers {
				if provider.Enabled && provider.AuthorizationStatus == "active" &&
					(provider.Type == "feishu" && service.feishu != nil || provider.Type == "dingtalk" && service.dingtalk != nil) {
					data.Providers = append(data.Providers, provider)
				}
			}
		}
	}
	formTargets := []string{"'self'"}
	if client.registration.ReturnURI != "" {
		target, err := url.Parse(client.registration.ReturnURI)
		if err == nil {
			formTargets = append(formTargets, target.Scheme+"://"+target.Host)
		}
	}
	if data.ProviderEnabled && service.dingtalk != nil {
		formTargets = append(formTargets, "https://login.dingtalk.com")
	}
	if data.ProviderEnabled && service.feishu != nil {
		formTargets = append(formTargets, "https://accounts.feishu.cn")
	}
	w.Header().Set("Content-Security-Policy", "default-src 'none'; style-src 'nonce-"+data.Nonce+"'; form-action "+strings.Join(formTargets, " ")+"; base-uri 'none'; frame-ancestors 'none'")
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_ = loginPage.Execute(w, data)
}
