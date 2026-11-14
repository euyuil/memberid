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
	ClientID, Scopes, Message, Nonce                               string
	Members                                                        []memberChoice
	Verified, Pending, PhonePending, FactorClient, ConsentRequired bool
	PhoneEnabled, ProviderEnabled, OrganizationRestricted          bool
	ProviderOrganizationID, ProviderOrganizationName               string
	Providers                                                      []identity.Provider
}

func (service *Service) renderLogin(w http.ResponseWriter, r *http.Request, request *authorizationRequest, client client, message string) {
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
			message = "DingTalk verified. Select your identity and continue."
		case "feishu":
			message = "Feishu verified. Select your identity and continue."
		}
	}
	if verified && client.registration.SubjectKind == "member" && len(choices) == 0 {
		message = "No eligible Member identity is available. Contact your organization administrator."
	}
	data := pageData{
		Request: request, ClientID: client.registration.ID, Scopes: strings.Join(request.Scopes, ", "), Message: message,
		Nonce: config.RandomSecret(), Members: choices, Verified: verified,
		Pending: request.ChallengeID != "" || request.externalPending(), PhonePending: request.ChallengeID != "",
		PhoneEnabled: service.phone != nil, ProviderEnabled: client.registration.SubjectKind == "member" && (service.dingtalk != nil || service.feishu != nil),
		OrganizationRestricted: client.registration.OrganizationID != "", ProviderOrganizationID: client.registration.OrganizationID,
		FactorClient: client.registration.SubjectKind == "factor", ConsentRequired: !client.registration.Preauthorized || slices.Contains(request.Input.Prompt, "consent"),
	}
	if !data.OrganizationRestricted {
		data.ProviderOrganizationID = request.ProviderOrganizationID
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
	if slices.Contains(client.registration.RedirectURIs, request.Input.RedirectURI) {
		target, err := url.Parse(request.Input.RedirectURI)
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
