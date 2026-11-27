package oidcprovider

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/zhizhun-tech/memberid/internal/browserauth"
	"github.com/zhizhun-tech/memberid/internal/config"
	"github.com/zhizhun-tech/memberid/internal/identity"
	"github.com/zhizhun-tech/memberid/internal/samlprovider"
)

const samlLoginPrefix = "saml."

type samlLoginState struct {
	ID            string                   `json:"id"`
	EnablementID  string                   `json:"enablementId,omitempty"`
	InteractionID string                   `json:"interactionId"`
	SessionID     string                   `json:"sessionId,omitempty"`
	Revision      int64                    `json:"revision"`
	Transaction   samlprovider.Transaction `json:"saml"`
	Interaction   browserauth.Interaction  `json:"login"`
}

func (request *authorizationRequest) browserHeldSAML() bool {
	return request.SAML != nil && request.entryToken != ""
}

// Scope the authenticated ciphertext to this protocol and issuer. The marker
// supplies the authoritative expiry and revision throughout the interaction.
func (service *Service) sealSAMLLogin(request *authorizationRequest, revision int64) (string, error) {
	state := samlLoginState{
		ID: request.ID, EnablementID: request.EnablementID, InteractionID: request.InteractionID, SessionID: request.SessionID,
		Revision: revision, Transaction: *request.SAML, Interaction: request.Interaction,
	}
	// The reservation already holds the SP's request ID.
	state.Transaction.RequestID = ""
	data, err := json.Marshal(state)
	if err != nil {
		return "", err
	}
	token, err := service.protocol.Crypto().Encrypt("saml-login:" + config.SecretHash(service.configuration.Issuer) + ":" + string(data))
	if err != nil {
		return "", err
	}
	return samlLoginPrefix + token, nil
}

func (service *Service) readSAMLLogin(ctx context.Context, token string) (*authorizationRequest, error) {
	ciphertext, ok := strings.CutPrefix(token, samlLoginPrefix)
	if !ok {
		return nil, identity.ErrIneligible
	}
	plaintext, err := service.protocol.Crypto().Decrypt(ciphertext)
	payload, ok := strings.CutPrefix(plaintext, "saml-login:"+config.SecretHash(service.configuration.Issuer)+":")
	var state samlLoginState
	browser, _ := ctx.Value(browserKey{}).(string)
	if err != nil || !ok || json.Unmarshal([]byte(payload), &state) != nil || browser == "" ||
		!sameSecret(state.Interaction.BrowserHash, config.SecretHash(browser)) {
		return nil, identity.ErrIneligible
	}
	err = service.store.Database().QueryRow(ctx, `SELECT saml_request_id FROM authentication_requests
		WHERE id=$1 AND saml_service_provider_id=$2 AND revision=$3 AND consumed_at IS NULL AND expires_at>$4`,
		state.ID, state.Transaction.ServiceProviderID, state.Revision, service.now()).Scan(&state.Transaction.RequestID)
	if err != nil {
		return nil, err
	}
	request := &authorizationRequest{
		grant:       grant{ID: state.ID, EnablementID: state.EnablementID, InteractionID: state.InteractionID, SessionID: state.SessionID, ClientID: state.Transaction.ServiceProviderID},
		Interaction: state.Interaction, SAML: &state.Transaction, entryToken: token,
	}
	request.Revision = state.Revision
	if request.Verification != nil {
		setVerification(request, *request.Verification)
	}
	return request, nil
}

// The provider echoes its usual short random state. Keep the matching sealed
// continuation in the initiating browser while it is visiting the provider.
func (service *Service) saveExternalLogin(w http.ResponseWriter, r *http.Request, request *authorizationRequest, state string) error {
	if err := service.storage.saveRequest(r.Context(), request); err != nil {
		return err
	}
	if request.browserHeldSAML() {
		service.cookie(w, "saml_"+state, request.entryToken, 5*time.Minute)
	}
	return nil
}

func (service *Service) externalLoginRequest(r *http.Request, state, stateColumn string) (*authorizationRequest, error) {
	if token := service.cookieValue(r, "saml_"+state); token != "" {
		return service.readSAMLLogin(r.Context(), token)
	}
	request, err := service.storage.loadRequest(r.Context(), stateColumn, config.SecretHash(state))
	if err != nil {
		return nil, err
	}
	if !sameSecret(request.BrowserHash, config.SecretHash(accountBrowser(r))) {
		return nil, identity.ErrIneligible
	}
	return request, nil
}
