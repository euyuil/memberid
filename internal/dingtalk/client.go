// Package dingtalk contains the optional DingTalk provider transport.
package dingtalk

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"regexp"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

var ErrUnavailable = errors.New("DingTalk provider unavailable")
var ErrAuthorizationDenied = errors.New("DingTalk application authorization denied")

var identifier = regexp.MustCompile(`^[A-Za-z0-9_-]{1,256}$`)

func ValidCredentials(corpID, clientID, secret string) bool {
	return identifier.MatchString(corpID) && identifier.MatchString(clientID) && utf8.ValidString(secret) && len(secret) > 0 && len(secret) <= 4096 && strings.TrimSpace(secret) == secret && strings.IndexFunc(secret, unicode.IsControl) == -1
}

type Client struct{ http *http.Client }

func New() *Client {
	return &Client{http: &http.Client{Timeout: 10 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}}
}

// CheckAuthorization obtains a fresh application token without retaining or exposing it.
// Unknown failures do not establish that an existing application's authorization was revoked.
func (client *Client) CheckAuthorization(ctx context.Context, corpID, clientID, secret string) error {
	if !ValidCredentials(corpID, clientID, secret) {
		return ErrUnavailable
	}
	body, err := json.Marshal(map[string]string{"client_id": clientID, "client_secret": secret, "grant_type": "client_credentials"})
	if err != nil {
		return ErrUnavailable
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, "https://api.dingtalk.com/v1.0/oauth2/"+corpID+"/token", bytes.NewReader(body))
	if err != nil {
		return ErrUnavailable
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Accept", "application/json")
	response, err := client.http.Do(request)
	if err != nil {
		return ErrUnavailable
	}
	defer response.Body.Close()
	data, err := io.ReadAll(io.LimitReader(response.Body, (64<<10)+1))
	if err != nil || len(data) > 64<<10 {
		return ErrUnavailable
	}
	var result struct {
		AccessToken string          `json:"access_token"`
		ExpiresIn   int64           `json:"expires_in"`
		Code        json.RawMessage `json:"code"`
	}
	if json.Unmarshal(data, &result) != nil {
		return ErrUnavailable
	}
	if response.StatusCode == http.StatusBadRequest && string(result.Code) == `"unauthorized.client"` {
		return ErrAuthorizationDenied
	}
	if response.StatusCode != http.StatusOK || len(result.Code) != 0 && string(result.Code) != "null" || result.AccessToken == "" || len(result.AccessToken) > 16384 || strings.IndexFunc(result.AccessToken, unicode.IsSpace) != -1 || strings.IndexFunc(result.AccessToken, unicode.IsControl) != -1 || result.ExpiresIn <= 0 || result.ExpiresIn > 86400 {
		return ErrUnavailable
	}
	return nil
}
