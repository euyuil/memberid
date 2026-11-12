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
	return identifier.MatchString(corpID) && identifier.MatchString(clientID) && validValue(secret, 4096)
}

func validValue(value string, maximum int) bool {
	return utf8.ValidString(value) && len(value) > 0 && len(value) <= maximum && strings.TrimSpace(value) == value && strings.IndexFunc(value, unicode.IsControl) == -1
}

type Client struct{ http *http.Client }

func New() *Client {
	return &Client{http: &http.Client{Timeout: 10 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}}
}

func zero(code json.RawMessage) bool { return string(code) == "0" || string(code) == `"0"` }

// All callers construct fixed provider URLs. Transport failures and provider descriptions stay private.
func (client *Client) request(ctx context.Context, method, address string, body any, token string, applicationToken bool, target any) error {
	var data []byte
	var err error
	if body != nil {
		data, err = json.Marshal(body)
		if err != nil {
			return ErrUnavailable
		}
	}
	request, err := http.NewRequestWithContext(ctx, method, address, bytes.NewReader(data))
	if err != nil {
		return ErrUnavailable
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Accept", "application/json")
	if token != "" {
		request.Header.Set("x-acs-dingtalk-access-token", token)
	}
	response, err := client.http.Do(request)
	if err != nil {
		return ErrUnavailable
	}
	defer response.Body.Close()
	data, err = io.ReadAll(io.LimitReader(response.Body, (64<<10)+1))
	if err != nil || len(data) > 64<<10 {
		return ErrUnavailable
	}
	var envelope struct {
		Code    json.RawMessage `json:"code"`
		ErrCode json.RawMessage `json:"errcode"`
	}
	if json.Unmarshal(data, &envelope) != nil {
		return ErrUnavailable
	}
	if applicationToken && response.StatusCode == http.StatusBadRequest && string(envelope.Code) == `"unauthorized.client"` {
		return ErrAuthorizationDenied
	}
	if response.StatusCode != http.StatusOK {
		return ErrUnavailable
	}
	for _, code := range []json.RawMessage{envelope.Code, envelope.ErrCode} {
		if len(code) != 0 && string(code) != "null" && !zero(code) {
			return ErrUnavailable
		}
	}
	if strings.HasPrefix(address, "https://oapi.dingtalk.com/") && !zero(envelope.ErrCode) {
		return ErrUnavailable
	}
	if json.Unmarshal(data, target) != nil {
		return ErrUnavailable
	}
	return nil
}

func (client *Client) applicationToken(ctx context.Context, corpID, clientID, secret string) (string, error) {
	if !ValidCredentials(corpID, clientID, secret) {
		return "", ErrUnavailable
	}
	var result struct {
		AccessToken string `json:"access_token"`
		ExpiresIn   int64  `json:"expires_in"`
	}
	err := client.request(ctx, http.MethodPost, "https://api.dingtalk.com/v1.0/oauth2/"+corpID+"/token", map[string]string{"client_id": clientID, "client_secret": secret, "grant_type": "client_credentials"}, "", true, &result)
	if err != nil {
		return "", err
	}
	if !validValue(result.AccessToken, 16384) || strings.IndexFunc(result.AccessToken, unicode.IsSpace) != -1 || result.ExpiresIn <= 0 || result.ExpiresIn > 86400 {
		return "", ErrUnavailable
	}
	return result.AccessToken, nil
}

// CheckAuthorization obtains a fresh application token without retaining or exposing it.
// Unknown failures do not establish that an existing application's authorization was revoked.
func (client *Client) CheckAuthorization(ctx context.Context, corpID, clientID, secret string) error {
	_, err := client.applicationToken(ctx, corpID, clientID, secret)
	return err
}
