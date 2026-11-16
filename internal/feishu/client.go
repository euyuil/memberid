// Package feishu implements OAuth login for Feishu enterprise self-built apps.
package feishu

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"golang.org/x/oauth2"
)

const (
	AuthURL             = "https://accounts.feishu.cn/open-apis/authen/v1/authorize"
	loginTokenURL       = "https://open.feishu.cn/open-apis/authen/v2/oauth/token"
	applicationTokenURL = "https://accounts.feishu.cn/oauth/v3/token"
	userInfoURL         = "https://open.feishu.cn/open-apis/authen/v1/user_info"
)

var ErrUnavailable = errors.New("Feishu provider unavailable")
var ErrAuthorizationDenied = errors.New("Feishu application authorization denied")
var ErrPermissionDenied = errors.New("Feishu membership permission denied")
var ErrMembershipUnknown = errors.New("Feishu membership state unknown")

var identifier = regexp.MustCompile(`^[A-Za-z0-9_-]{1,256}$`)
var appSecret = regexp.MustCompile(`^[\x21-\x7e]+$`)
var bearerToken = regexp.MustCompile(`^[A-Za-z0-9._~+/=-]+$`)

func ValidApplication(tenantKey, clientID string) bool {
	return identifier.MatchString(tenantKey) && strings.HasPrefix(clientID, "cli_") && len(clientID) > 4 && identifier.MatchString(clientID)
}

func ValidSecret(secret string) bool { return len(secret) <= 4096 && appSecret.MatchString(secret) }

type Client struct{ http *http.Client }

func New() *Client {
	return &Client{http: &http.Client{Timeout: 10 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}}
}

func AuthorizationURL(clientID, callback, state, verifier string) string {
	client := oauth2.Config{ClientID: clientID, RedirectURL: callback, Endpoint: oauth2.Endpoint{AuthURL: AuthURL}}
	return client.AuthCodeURL(state, oauth2.S256ChallengeOption(verifier))
}

type Profile struct {
	TenantKey string `json:"tenant_key"`
	OpenID    string `json:"open_id"`
	Name      string `json:"name"`
}

type tokenResponse struct {
	Code        *int   `json:"code"`
	Error       string `json:"error"`
	AccessToken string `json:"access_token"`
	ExpiresIn   int64  `json:"expires_in"`
	TokenType   string `json:"token_type"`
}

func (t tokenResponse) valid() bool {
	return t.Code != nil && *t.Code == 0 && t.Error == "" && strings.EqualFold(t.TokenType, "Bearer") &&
		t.ExpiresIn > 0 && len(t.AccessToken) <= 16384 && bearerToken.MatchString(t.AccessToken)
}

func denied(status int, code *int) bool {
	return status == http.StatusBadRequest && code != nil && (*code == 20009 || *code == 20048 || *code == 20069)
}

// CheckAuthorization validates stored or candidate credentials against the
// self-built application endpoint. The token is immediately discarded.
func (client *Client) CheckAuthorization(ctx context.Context, clientID, secret string) error {
	_, err := client.applicationToken(ctx, clientID, secret)
	return err
}

func (client *Client) applicationToken(ctx context.Context, clientID, secret string) (string, error) {
	payload := url.Values{"grant_type": {"client_credentials"}, "client_id": {clientID}, "client_secret": {secret}}
	var result tokenResponse
	status := client.request(ctx, http.MethodPost, applicationTokenURL, "application/x-www-form-urlencoded", []byte(payload.Encode()), "", &result)
	if denied(status, result.Code) {
		return "", ErrAuthorizationDenied
	}
	if status != http.StatusOK || !result.valid() {
		return "", ErrUnavailable
	}
	return result.AccessToken, nil
}

func (client *Client) Login(ctx context.Context, clientID, secret, callback, code, verifier string) (Profile, error) {
	payload, _ := json.Marshal(map[string]string{
		"grant_type": "authorization_code", "client_id": clientID, "client_secret": secret,
		"redirect_uri": callback, "code": code, "code_verifier": verifier,
	})
	var token tokenResponse
	status := client.request(ctx, http.MethodPost, loginTokenURL, "application/json; charset=utf-8", payload, "", &token)
	if denied(status, token.Code) {
		return Profile{}, ErrAuthorizationDenied
	}
	if status != http.StatusOK || !token.valid() {
		return Profile{}, ErrUnavailable
	}
	var result struct {
		Code *int    `json:"code"`
		Data Profile `json:"data"`
	}
	status = client.request(ctx, http.MethodGet, userInfoURL, "", nil, token.AccessToken, &result)
	if status != http.StatusOK || result.Code == nil || *result.Code != 0 ||
		!identifier.MatchString(result.Data.TenantKey) || !identifier.MatchString(result.Data.OpenID) {
		return Profile{}, ErrUnavailable
	}
	return result.Data, nil
}

// Membership returns only explicit employee status for an application-scoped
// open ID. A self-built application's credential is restricted to its own tenant.
// Missing users, visibility errors and incomplete status are never departure proof.
func (client *Client) Membership(ctx context.Context, clientID, secret, openID string) (bool, error) {
	if !identifier.MatchString(openID) {
		return false, ErrMembershipUnknown
	}
	token, err := client.applicationToken(ctx, clientID, secret)
	if err != nil {
		return false, err
	}
	var result struct {
		Code *int `json:"code"`
		Data struct {
			User struct {
				OpenID string `json:"open_id"`
				Status struct {
					Resigned  *bool `json:"is_resigned"`
					Activated *bool `json:"is_activated"`
					Frozen    *bool `json:"is_frozen"`
					Exited    *bool `json:"is_exited"`
					Unjoined  *bool `json:"is_unjoin"`
				} `json:"status"`
			} `json:"user"`
		} `json:"data"`
	}
	endpoint := "https://open.feishu.cn/open-apis/contact/v3/users/" + url.PathEscape(openID) + "?user_id_type=open_id"
	status := client.request(ctx, http.MethodGet, endpoint, "application/json; charset=utf-8", nil, token, &result)
	if result.Code != nil && (*result.Code == 41050 || *result.Code == 99991672) {
		return false, ErrPermissionDenied
	}
	if status != http.StatusOK || result.Code == nil {
		return false, ErrUnavailable
	}
	if *result.Code != 0 || result.Data.User.OpenID != openID || result.Data.User.Status.Resigned == nil {
		return false, ErrMembershipUnknown
	}
	state := result.Data.User.Status
	if *state.Resigned {
		return true, nil
	}
	if state.Activated == nil || state.Frozen == nil || state.Exited == nil || state.Unjoined == nil ||
		!*state.Activated || *state.Frozen || *state.Exited || *state.Unjoined {
		return false, ErrMembershipUnknown
	}
	return false, nil
}

// Requests use fixed HTTPS origins and bounded responses. Errors never return
// provider messages, upstream codes, or credential-bearing transport details.
func (client *Client) request(ctx context.Context, method, endpoint, contentType string, payload []byte, token string, result any) int {
	req, err := http.NewRequestWithContext(ctx, method, endpoint, bytes.NewReader(payload))
	if err != nil {
		return 0
	}
	req.Header.Set("Accept", "application/json")
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	res, err := client.http.Do(req)
	if err != nil {
		return 0
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK && res.StatusCode != http.StatusBadRequest && res.StatusCode != http.StatusForbidden && res.StatusCode != http.StatusNotFound {
		return 0
	}
	const limit = 64 << 10
	data, err := io.ReadAll(io.LimitReader(res.Body, limit+1))
	if err != nil || len(data) > limit || json.Unmarshal(data, result) != nil {
		return 0
	}
	return res.StatusCode
}
