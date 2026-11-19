package oidcprovider

import (
	"encoding/json"
	"net/http"
	"net/url"
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

func (service *Service) createDirectLogin(r *http.Request, organizationID string) (*authorizationRequest, error) {
	if organizationID != "" {
		if err := service.requireLoginOrganization(r.Context(), organizationID); err != nil {
			return nil, err
		}
	}
	browser, _ := r.Context().Value(browserKey{}).(string)
	request := &authorizationRequest{
		grant: grant{ID: newID(), InteractionID: newID()},
		Interaction: browserauth.Interaction{
			Revision: 1, BrowserHash: config.SecretHash(browser), CSRF: config.RandomSecret(), ProviderOrganizationID: organizationID,
		},
	}
	data, err := json.Marshal(request)
	if err != nil {
		return nil, err
	}
	_, err = service.store.Database().Exec(r.Context(), "INSERT INTO authentication_requests(id,client_id,data,expires_at) VALUES($1,$2,$3,$4)", request.ID, request.ClientID, data, service.now().Add(10*time.Minute))
	return request, err
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
