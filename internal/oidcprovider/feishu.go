package oidcprovider

import (
	"context"
	"net/http"
	"time"

	"github.com/euyuil/memberid/internal/config"
	"github.com/euyuil/memberid/internal/feishu"
	"github.com/euyuil/memberid/internal/identity"
	"github.com/jackc/pgx/v5"
	"golang.org/x/oauth2"
)

const feishuCallbackPath = "/login/feishu/callback"

type feishuAttempt struct {
	identity.FeishuLoginContext
	StateHash string    `json:"stateHash"`
	Verifier  string    `json:"verifier,omitempty"`
	ExpiresAt time.Time `json:"expiresAt"`
}

func (service *Service) startFeishu(w http.ResponseWriter, r *http.Request, request *authorizationRequest, registered client) {
	if service.feishu == nil || registered.registration.SubjectKind != "member" || request.Verification != nil || request.ChallengeID != "" || request.externalPending() {
		http.Error(w, "Feishu login is unavailable for this transaction.", http.StatusBadRequest)
		return
	}
	organizationID, providerID := r.PostForm.Get("organization"), r.PostForm.Get("provider")
	if providerID == "" || registered.registration.OrganizationID != "" && registered.registration.OrganizationID != organizationID {
		http.Error(w, "Invalid Feishu provider selection", http.StatusBadRequest)
		return
	}
	app, login, err := service.feishu.LoginSource(r.Context(), organizationID, providerID)
	if err != nil {
		service.renderLogin(w, r, request, registered, "Feishu is not available for that organization.")
		return
	}
	state, verifier := config.RandomSecret(), oauth2.GenerateVerifier()
	request.Feishu = &feishuAttempt{login, config.SecretHash(state), verifier, service.now().Add(5 * time.Minute)}
	request.Fresh = true
	request.ProviderOrganizationID = organizationID
	if err := service.storage.saveRequest(r.Context(), request); err != nil {
		http.Error(w, "Login transaction expired", http.StatusBadRequest)
		return
	}
	http.Redirect(w, r, feishu.AuthorizationURL(app.ClientID, service.configuration.Issuer+feishuCallbackPath, state, verifier), http.StatusSeeOther)
}

func (service *Service) feishuCallback(w http.ResponseWriter, r *http.Request) {
	if service.feishu == nil {
		http.NotFound(w, r)
		return
	}
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", "GET")
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	for name := range r.Form {
		if name != "state" && name != "code" && name != "error" && name != "error_description" {
			http.Error(w, "Invalid Feishu callback", http.StatusBadRequest)
			return
		}
	}
	state := r.Form.Get("state")
	if len(state) != 43 {
		http.Error(w, "Invalid Feishu callback", http.StatusBadRequest)
		return
	}
	hash := config.SecretHash(state)
	request, err := service.storage.loadRequest(r.Context(), "data->'feishu'->>'stateHash'", hash)
	if err != nil || !sameSecret(request.BrowserHash, config.SecretHash(accountBrowser(r))) {
		http.Error(w, "Invalid or expired Feishu login", http.StatusBadRequest)
		return
	}
	attempt := request.Feishu
	registered, err := service.storage.client(request.ClientID)
	if err != nil || request.Complete || request.Verification != nil || attempt == nil || attempt.Verifier == "" ||
		!attempt.ExpiresAt.After(service.now()) || !sameSecret(attempt.StateHash, hash) || registered.registration.SubjectKind != "member" ||
		registered.registration.OrganizationID != "" && registered.registration.OrganizationID != attempt.OrganizationID {
		http.Error(w, "Invalid or expired Feishu login", http.StatusBadRequest)
		return
	}
	// Clearing the verifier and advancing the request revision consumes this callback.
	verifier := attempt.Verifier
	attempt.Verifier = ""
	if err := service.storage.saveRequest(r.Context(), request); err != nil {
		http.Error(w, "Invalid or expired Feishu login", http.StatusBadRequest)
		return
	}
	if r.Form.Get("error") != "" || r.Form.Get("code") == "" {
		service.renderLogin(w, r, request, registered, "Feishu login did not complete. Cancel verification to try again.")
		return
	}
	proof, err := service.feishu.Verify(r.Context(), attempt.FeishuLoginContext, service.configuration.Issuer+feishuCallbackPath, r.Form.Get("code"), verifier)
	if err != nil {
		service.renderLogin(w, r, request, registered, "Unable to verify the Feishu identity. Cancel verification to try again.")
		return
	}
	service.completeExternalLogin(w, r, request, attempt.ExpiresAt, "Feishu", func(ctx context.Context, tx pgx.Tx) (identity.Verification, error) {
		return service.feishu.Admit(ctx, tx, proof)
	})
}
