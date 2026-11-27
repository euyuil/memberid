package oidcprovider

import (
	"context"
	"errors"
	"html/template"
	"net/http"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/zhizhun-tech/memberid/internal/authevent"
	"github.com/zhizhun-tech/memberid/internal/browserauth"
	"github.com/zhizhun-tech/memberid/internal/config"
	"github.com/zhizhun-tech/memberid/internal/feishu"
	"github.com/zhizhun-tech/memberid/internal/identity"
	"golang.org/x/oauth2"
)

const feishuCallbackPath = "/auth/feishu/callback"

type feishuAttempt = browserauth.FeishuAttempt

func (service *Service) startFeishu(w http.ResponseWriter, r *http.Request, request *authorizationRequest, registered loginPolicy) {
	if service.feishu == nil || registered.registration.SubjectKind != "member" || request.Verification != nil || request.phonePending() || request.externalPending() {
		http.Error(w, "Feishu login is unavailable for this transaction.", http.StatusBadRequest)
		return
	}
	organizationID, providerID := loginOrganizationID(request, registered), r.PostForm.Get("provider")
	if providerID == "" || organizationID == "" || r.PostForm.Get("organization") != organizationID {
		http.Error(w, "Invalid Feishu provider selection", http.StatusBadRequest)
		return
	}
	app, login, err := service.feishu.LoginSource(r.Context(), organizationID, providerID)
	if err != nil {
		service.renderLogin(w, r, request, registered, "Feishu is not available for that organization.")
		return
	}
	state, verifier := config.RandomSecret(), oauth2.GenerateVerifier()
	request.Feishu = &feishuAttempt{FeishuLoginContext: login, StateHash: config.SecretHash(state), Verifier: verifier, ExpiresAt: service.now().Add(5 * time.Minute)}
	request.Fresh = true
	request.ProviderOrganizationID = organizationID
	if err := service.saveExternalLogin(w, r, request, state); err != nil {
		http.Error(w, "Login transaction expired", http.StatusBadRequest)
		return
	}
	writeFeishuNavigation(w, feishu.AuthorizationURL(app.ClientID, service.configuration.Issuer+feishuCallbackPath, state, verifier), requestLoginURL(request))
}

var feishuNavigation = template.Must(template.New("feishu-navigation").Parse(`<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Continue to Feishu</title></head><body><main>
<p><a id="provider" href="{{.Destination}}">Continue to Feishu</a></p>
<p><a id="resume" href="{{.Resume}}">Return to MemberID</a></p></main>
<script nonce="{{.Nonce}}">
// Back and reload must reopen the pending interaction with GET.
history.replaceState(null, "", document.getElementById("resume").href);
history.pushState(null, "", location.href);
location.replace(document.getElementById("provider").href);
</script></body></html>`))

func writeFeishuNavigation(w http.ResponseWriter, destination, resume string) {
	nonce := config.RandomSecret()
	w.Header().Set("Content-Security-Policy", "default-src 'none'; script-src 'nonce-"+nonce+"'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("Cache-Control", "no-store")
	writeHTMLPage(w, feishuNavigation, struct{ Destination, Resume, Nonce string }{destination, resume, nonce})
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
	event := authevent.Event{Purpose: "login"}
	failure := errCallbackRejected
	completed := false
	defer func() {
		if !completed {
			service.recordVerification(r, event, "feishu", failure)
		}
	}()
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
	request, err := service.externalLoginRequest(r, state, "data->'feishu'->>'stateHash'")
	if err != nil {
		if !errors.Is(err, identity.ErrIneligible) {
			failure = err
		}
		http.Error(w, "Invalid or expired Feishu login", http.StatusBadRequest)
		return
	}
	attempt := request.Feishu
	event = service.loginEvent(r.Context(), request)
	if attempt != nil {
		event.OrganizationID = attempt.OrganizationID
		event.ProviderID = attempt.ProviderID
	}
	registered, err := service.loginPolicy(r.Context(), request)
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
		failure = err
		http.Error(w, "Invalid or expired Feishu login", http.StatusBadRequest)
		return
	}
	if r.Form.Get("error") != "" || r.Form.Get("code") == "" {
		if r.Form.Get("error") != "" {
			failure = callbackFailure(r.Form.Get("error"))
		}
		service.renderLogin(w, r, request, registered, "Feishu login did not complete. Cancel verification to try again.")
		return
	}
	proof, err := service.feishu.Verify(r.Context(), attempt.FeishuLoginContext, service.configuration.Issuer+feishuCallbackPath, r.Form.Get("code"), verifier)
	if err != nil {
		failure = err
		service.renderLogin(w, r, request, registered, "Unable to verify the Feishu identity. Cancel verification to try again.")
		return
	}
	completed = true
	service.completeExternalLogin(w, r, request, attempt.ExpiresAt, "Feishu", event, func(ctx context.Context, tx pgx.Tx) (identity.MemberAdmission, error) {
		return service.feishu.Admit(ctx, tx, proof)
	})
}
