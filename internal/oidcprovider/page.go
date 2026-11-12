package oidcprovider

import (
	"embed"
	"html/template"
	"net/http"
	"net/url"
	"slices"
	"strings"

	"github.com/euyuil/memberid/internal/config"
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
	PhoneEnabled, DingTalkEnabled, OrganizationRestricted          bool
	DingTalkOrganizationID                                         string
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
	if verified && request.Method == "dingtalk" && message == "" {
		message = "DingTalk verified. Select your identity and continue."
	}
	if verified && client.registration.SubjectKind == "member" && len(choices) == 0 {
		message = "No eligible Member identity is available. Contact your organization administrator."
	}
	data := pageData{Request: request, ClientID: client.registration.ID, Scopes: strings.Join(request.Scopes, ", "), Message: message, Nonce: config.RandomSecret(), Members: choices, Verified: verified, Pending: request.ChallengeID != "" || request.DingTalk != nil, PhonePending: request.ChallengeID != "", PhoneEnabled: service.phone != nil, DingTalkEnabled: service.dingtalk != nil && client.registration.SubjectKind == "member", OrganizationRestricted: client.registration.OrganizationID != "", DingTalkOrganizationID: client.registration.OrganizationID, FactorClient: client.registration.SubjectKind == "factor", ConsentRequired: !client.registration.Preauthorized || slices.Contains(request.Input.Prompt, "consent")}
	if request.DingTalk != nil {
		data.DingTalkOrganizationID = request.DingTalk.OrganizationID
	}
	formTargets := []string{"'self'"}
	if slices.Contains(client.registration.RedirectURIs, request.Input.RedirectURI) {
		target, err := url.Parse(request.Input.RedirectURI)
		if err == nil {
			formTargets = append(formTargets, target.Scheme+"://"+target.Host)
		}
	}
	if data.DingTalkEnabled {
		formTargets = append(formTargets, "https://login.dingtalk.com")
	}
	w.Header().Set("Content-Security-Policy", "default-src 'none'; style-src 'nonce-"+data.Nonce+"'; form-action "+strings.Join(formTargets, " ")+"; base-uri 'none'; frame-ancestors 'none'")
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_ = loginPage.Execute(w, data)
}
