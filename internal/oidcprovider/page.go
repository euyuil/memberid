package oidcprovider

import (
	"embed"
	"html/template"
	"net/http"
	"slices"
	"strings"

	"github.com/euyuil/memberid/internal/config"
)

//go:embed login.html
var pageFiles embed.FS
var loginPage = template.Must(template.ParseFS(pageFiles, "login.html"))

type memberChoice struct{ ID, Label string }
type pageData struct {
	Request                                          *authorizationRequest
	ClientID, Scopes, Message, Nonce                 string
	Members                                          []memberChoice
	Verified, Pending, FactorClient, ConsentRequired bool
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
	if verified && client.registration.SubjectKind == "member" && len(choices) == 0 {
		message = "No eligible Member identity is available. Contact your organization administrator."
	}
	data := pageData{Request: request, ClientID: client.registration.ID, Scopes: strings.Join(request.Scopes, ", "), Message: message, Nonce: config.RandomSecret(), Members: choices, Verified: verified, Pending: request.ChallengeID != "", FactorClient: client.registration.SubjectKind == "factor", ConsentRequired: !client.registration.Preauthorized || slices.Contains(request.Input.Prompt, "consent")}
	w.Header().Set("Content-Security-Policy", "default-src 'none'; style-src 'nonce-"+data.Nonce+"'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'")
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_ = loginPage.Execute(w, data)
}
