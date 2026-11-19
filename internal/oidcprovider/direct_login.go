package oidcprovider

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/euyuil/memberid/internal/browserauth"
	"github.com/euyuil/memberid/internal/config"
	"github.com/euyuil/memberid/internal/identity"
)

const (
	directStartsPerMinute  = 600
	browserStartsPerMinute = 12
)

// The process-wide cap also bounds the number of browser keys held in memory.
type directLoginQuota struct {
	mu       sync.Mutex
	resetsAt time.Time
	total    int
	browsers map[string]int
}

func (quota *directLoginQuota) allow(browser string, now time.Time) bool {
	quota.mu.Lock()
	defer quota.mu.Unlock()
	if !now.Before(quota.resetsAt) {
		quota.resetsAt = now.Add(time.Minute)
		quota.total = 0
		quota.browsers = make(map[string]int)
	}
	if quota.total >= directStartsPerMinute || quota.browsers[browser] >= browserStartsPerMinute {
		return false
	}
	quota.total++
	quota.browsers[browser]++
	return true
}

func (service *Service) directLogin(w http.ResponseWriter, r *http.Request, organizationID string) {
	browser := accountBrowser(r)
	id := r.PostForm.Get("request")
	if r.Method == http.MethodGet {
		id = fmt.Sprintf("direct.%d.%s", service.now().Add(10*time.Minute).Unix(), newID())
	}
	// Bind the unpersisted form to its browser, organization page and deadline.
	mac := hmac.New(sha256.New, []byte(service.configuration.Secrets.ProtocolKey))
	fmt.Fprintf(mac, "memberid/direct-login\x00%s\x00%s\x00%s\x00%s", service.configuration.Issuer, browser, organizationID, id)
	request := &authorizationRequest{
		grant:       grant{ID: id},
		Interaction: browserauth.Interaction{BrowserHash: config.SecretHash(browser), CSRF: base64.RawURLEncoding.EncodeToString(mac.Sum(nil)), ProviderOrganizationID: organizationID},
	}
	if r.Method == http.MethodPost && !validLoginSubmission(r, service.configuration.Issuer, request.CSRF) {
		http.Error(w, "Invalid login submission", http.StatusForbidden)
		return
	}
	if organizationID != "" {
		if err := service.requireLoginOrganization(r.Context(), organizationID); err != nil {
			writeLoginOrganizationError(w, err)
			return
		}
	}
	policy := directLoginPolicy(organizationID)
	if r.Method == http.MethodGet {
		if organizationID != "" {
			service.loadSession(r, request)
		}
		service.renderLogin(w, r, request, policy, "")
		return
	}
	deadline, transactionID, ok := strings.Cut(strings.TrimPrefix(id, "direct."), ".")
	expires, err := strconv.ParseInt(deadline, 10, 64)
	if !ok || err != nil || !service.now().Before(time.Unix(expires, 0)) {
		http.Error(w, "Login form expired. Reload the page to continue.", http.StatusBadRequest)
		return
	}
	action := r.PostForm.Get("action")
	if organizationID == "" {
		if action != "choose-organization" {
			http.Error(w, "Select an organization before continuing", http.StatusBadRequest)
			return
		}
		selected := service.selectedLoginOrganization(w, r, request, policy)
		if selected == "" {
			return
		}
		http.Redirect(w, r, "/login/"+selected, http.StatusSeeOther)
		return
	}
	switch action {
	case "continue":
		if !service.loadSession(r, request) {
			service.renderLogin(w, r, request, policy, "Sign in again to continue.")
			return
		}
		session := accountSession{id: request.SessionID, verified: *request.Verification}
		member, _, err := service.accountMember(r, session, r.PostForm.Get("member"))
		if err != nil || member.OrganizationID != organizationID {
			http.Error(w, "Member identity is unavailable", http.StatusForbidden)
			return
		}
		http.Redirect(w, r, "/account?memberId="+url.QueryEscape(member.ID), http.StatusSeeOther)
	case "cancel":
		service.renderLogin(w, r, request, policy, "")
	case "password", "send", "dingtalk", "feishu":
		service.startDirectAuthentication(w, r, request, transactionID)
	default:
		http.Error(w, "Invalid login action", http.StatusBadRequest)
	}
}

func (service *Service) startDirectAuthentication(w http.ResponseWriter, r *http.Request, request *authorizationRequest, transactionID string) {
	if !service.directStarts.allow(accountBrowser(r), service.now()) {
		w.Header().Set("Retry-After", "60")
		http.Error(w, "Too many new login attempts. Try again later.", http.StatusTooManyRequests)
		return
	}
	request.ID, request.InteractionID, request.Revision = transactionID, newID(), 1
	data, err := json.Marshal(request)
	if err != nil {
		http.Error(w, "Login temporarily unavailable", http.StatusServiceUnavailable)
		return
	}
	// One form can start only one authentication, including across replicas.
	result, err := service.store.Database().Exec(r.Context(), "INSERT INTO authentication_requests(id,client_id,data,expires_at) VALUES($1,'',$2,$3) ON CONFLICT (id) DO NOTHING", request.ID, data, service.now().Add(10*time.Minute))
	if err != nil {
		http.Error(w, "Login temporarily unavailable", http.StatusServiceUnavailable)
		return
	}
	if result.RowsAffected() == 0 {
		http.Redirect(w, r, requestLoginURL(request), http.StatusSeeOther)
		return
	}
	service.loginTransaction(w, r, request, request.ProviderOrganizationID)
}

func (service *Service) finishDirectLogin(w http.ResponseWriter, r *http.Request, request *authorizationRequest) error {
	if request.MemberID == "" {
		return identity.ErrIneligible
	}
	request.Complete = true
	if err := service.storage.saveRequest(r.Context(), request); err != nil {
		return err
	}
	http.Redirect(w, r, "/account?memberId="+url.QueryEscape(request.MemberID), http.StatusSeeOther)
	return nil
}
