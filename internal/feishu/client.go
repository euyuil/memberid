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
	payload := url.Values{"grant_type": {"client_credentials"}, "client_id": {clientID}, "client_secret": {secret}}
	var result tokenResponse
	status := client.request(ctx, http.MethodPost, applicationTokenURL, "application/x-www-form-urlencoded", []byte(payload.Encode()), "", &result)
	if denied(status, result.Code) {
		return ErrAuthorizationDenied
	}
	if status != http.StatusOK || !result.valid() {
		return ErrUnavailable
	}
	return nil
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
	if res.StatusCode != http.StatusOK && res.StatusCode != http.StatusBadRequest {
		return 0
	}
	const limit = 64 << 10
	data, err := io.ReadAll(io.LimitReader(res.Body, limit+1))
	if err != nil || len(data) > limit || json.Unmarshal(data, result) != nil {
		return 0
	}
	return res.StatusCode
}
