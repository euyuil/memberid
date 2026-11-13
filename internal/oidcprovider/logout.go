package oidcprovider

import (
	_ "embed"
	"encoding/json"
	"errors"
	"html/template"
	"mime"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/euyuil/memberid/internal/config"
	"github.com/jackc/pgx/v5"
	"github.com/zitadel/oidc/v3/pkg/oidc"
	"github.com/zitadel/oidc/v3/pkg/op"
)

//go:embed logout.html
var logoutHTML string
var logoutPage = template.Must(template.New("logout").Parse(logoutHTML))

type logoutConfirmation struct {
	SessionID   string    `json:"sessionId"`
	SessionHash string    `json:"sessionHash"`
	BrowserHash string    `json:"browserHash"`
	RedirectURI string    `json:"redirectUri"`
	ExpiresAt   time.Time `json:"expiresAt"`
}

func (service *Service) logout(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodPost {
		w.Header().Set("Allow", "GET, POST")
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	r = r.WithContext(op.ContextWithIssuer(r.Context(), service.configuration.Issuer))
	request, err := op.ParseEndSessionRequest(r, service.protocol.Decoder())
	if err != nil {
		op.RequestError(w, r, err, nil)
		return
	}
	validated, err := op.ValidateEndSessionRequest(r.Context(), request, service.protocol)
	if err == nil && request.PostLogoutRedirectURI != "" && validated.ClientID == "" {
		err = oidc.ErrInvalidRequest().WithDescription("A registered client is required for post-logout redirection")
	}
	if err != nil {
		op.RequestError(w, r, err, nil)
		return
	}
	if r.Method == http.MethodPost {
		// A top-level GET lets SameSite=Lax cookies identify the current browser
		// session after a cross-site RP form POST.
		http.Redirect(w, r, "/oauth/logout?"+r.Form.Encode(), http.StatusSeeOther)
		return
	}
	secret := service.cookieValue(r, "session")
	var sessionID string
	err = service.store.Database().QueryRow(r.Context(), "SELECT id FROM oidc_sessions WHERE secret_hash=$1 AND revoked_at IS NULL AND expires_at>$2 AND absolute_expires_at>$2", config.SecretHash(secret), service.now()).Scan(&sessionID)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		op.RequestError(w, r, oidc.ErrServerError(), nil)
		return
	}
	if sessionID != "" && validated.IDTokenHintClaims != nil && validated.IDTokenHintClaims.SessionID == sessionID {
		service.completeLogout(w, r, sessionID, secret, validated.RedirectURI)
		return
	}
	confirmation := logoutConfirmation{SessionID: sessionID, SessionHash: config.SecretHash(secret), BrowserHash: config.SecretHash(accountBrowser(r)), RedirectURI: validated.RedirectURI, ExpiresAt: service.now().Add(10 * time.Minute)}
	data, err := json.Marshal(confirmation)
	if err != nil {
		op.RequestError(w, r, oidc.ErrServerError(), nil)
		return
	}
	sealed, err := service.protocol.Crypto().Encrypt("logout:" + string(data))
	if err != nil {
		op.RequestError(w, r, oidc.ErrServerError(), nil)
		return
	}
	nonce := config.RandomSecret()
	target, _ := url.Parse(validated.RedirectURI)
	w.Header().Set("Content-Security-Policy", "default-src 'none'; style-src 'nonce-"+nonce+"'; form-action 'self' "+target.Scheme+"://"+target.Host+"; base-uri 'none'; frame-ancestors 'none'")
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_ = logoutPage.Execute(w, struct{ Request, Nonce string }{sealed, nonce})
}

func (service *Service) confirmLogout(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	mediaType, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || mediaType != "application/x-www-form-urlencoded" || r.Header.Get("Origin") != service.configuration.Issuer {
		http.Error(w, "Invalid logout confirmation", http.StatusForbidden)
		return
	}
	data, err := service.protocol.Crypto().Decrypt(r.PostForm.Get("request"))
	var confirmation logoutConfirmation
	secret := service.cookieValue(r, "session")
	if err != nil || !strings.HasPrefix(data, "logout:") || json.Unmarshal([]byte(strings.TrimPrefix(data, "logout:")), &confirmation) != nil || !confirmation.ExpiresAt.After(service.now()) || !sameSecret(confirmation.BrowserHash, config.SecretHash(accountBrowser(r))) || !sameSecret(confirmation.SessionHash, config.SecretHash(secret)) {
		http.Error(w, "Invalid or expired logout confirmation. Start a new logout request.", http.StatusForbidden)
		return
	}
	switch r.PostForm.Get("action") {
	case "confirm":
		service.completeLogout(w, r, confirmation.SessionID, secret, confirmation.RedirectURI)
	case "cancel":
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		_, _ = w.Write([]byte("Sign-out cancelled. You may close this page.\n"))
	default:
		http.Error(w, "Invalid logout action", http.StatusBadRequest)
	}
}

func (service *Service) completeLogout(w http.ResponseWriter, r *http.Request, sessionID, secret, redirectURI string) {
	if sessionID != "" {
		if err := service.storage.endSession(r.Context(), sessionID, secret); err != nil {
			op.RequestError(w, r, err, nil)
			return
		}
	}
	service.cookie(w, "session", "", -time.Second)
	http.Redirect(w, r, redirectURI, http.StatusFound)
}
