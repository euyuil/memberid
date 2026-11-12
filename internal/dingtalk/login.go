package dingtalk

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"strconv"
)

// Member is evidence from an exact corporation/application, never a cross-organization account.
type Member struct {
	UnionID       string
	UserID        string
	DisplayName   string
	DepartmentIDs []string
}

// Login exchanges a browser authorization code and independently verifies corporation membership.
// Upstream access and refresh credentials never leave this transport.
func (client *Client) Login(ctx context.Context, corpID, clientID, secret, code string) (Member, error) {
	if !ValidCredentials(corpID, clientID, secret) || !validValue(code, 4096) {
		return Member{}, ErrUnavailable
	}
	var token struct {
		AccessToken string `json:"accessToken"`
		CorpID      string `json:"corpId"`
	}
	err := client.request(ctx, http.MethodPost, "https://api.dingtalk.com/v1.0/oauth2/userAccessToken", map[string]string{"clientId": clientID, "clientSecret": secret, "code": code, "grantType": "authorization_code"}, "", false, &token)
	if err != nil || !validValue(token.AccessToken, 16384) || token.CorpID != corpID {
		return Member{}, ErrUnavailable
	}
	var user struct {
		UnionID string `json:"unionId"`
	}
	if err := client.request(ctx, http.MethodGet, "https://api.dingtalk.com/v1.0/contact/users/me", nil, token.AccessToken, false, &user); err != nil || !validValue(user.UnionID, 512) {
		return Member{}, ErrUnavailable
	}
	return client.VerifyMember(ctx, corpID, clientID, secret, user.UnionID)
}

// VerifyMember obtains current directory evidence for an already known provider subject.
// An unavailable lookup does not establish that the person left the organization.
func (client *Client) VerifyMember(ctx context.Context, corpID, clientID, secret, unionID string) (Member, error) {
	if !ValidCredentials(corpID, clientID, secret) || !validValue(unionID, 512) {
		return Member{}, ErrUnavailable
	}
	applicationToken, err := client.applicationToken(ctx, corpID, clientID, secret)
	if err != nil {
		return Member{}, err
	}
	var mapping struct {
		Result struct {
			UserID      string          `json:"userid"`
			ContactType json.RawMessage `json:"contact_type"`
		} `json:"result"`
	}
	if err := client.request(ctx, http.MethodPost, "https://oapi.dingtalk.com/topapi/user/getbyunionid?access_token="+url.QueryEscape(applicationToken), map[string]string{"unionid": unionID}, "", false, &mapping); err != nil || !validValue(mapping.Result.UserID, 512) {
		return Member{}, ErrUnavailable
	}
	if string(mapping.Result.ContactType) == "1" || string(mapping.Result.ContactType) == `"1"` {
		return Member{}, ErrNotMember
	}
	if !zero(mapping.Result.ContactType) {
		return Member{}, ErrUnavailable
	}
	var detail struct {
		Result struct {
			UserID      string          `json:"userid"`
			UnionID     string          `json:"unionid"`
			Name        string          `json:"name"`
			Departments json.RawMessage `json:"dept_id_list"`
		} `json:"result"`
	}
	if err := client.request(ctx, http.MethodPost, "https://oapi.dingtalk.com/topapi/v2/user/get?access_token="+url.QueryEscape(applicationToken), map[string]string{"userid": mapping.Result.UserID}, "", false, &detail); err != nil || !validValue(detail.Result.UserID, 512) || !validValue(detail.Result.UnionID, 512) {
		return Member{}, ErrUnavailable
	}
	if detail.Result.UserID != mapping.Result.UserID || detail.Result.UnionID != unionID {
		return Member{}, ErrIdentityConflict
	}
	return Member{UnionID: unionID, UserID: detail.Result.UserID, DisplayName: detail.Result.Name, DepartmentIDs: departments(detail.Result.Departments)}, nil
}

// Missing or malformed optional attributes do not invalidate otherwise verified membership.
// Nil remains distinct from a verified empty department list.
func departments(raw json.RawMessage) []string {
	var ids []int64
	if json.Unmarshal(raw, &ids) != nil || ids == nil {
		return nil
	}
	result := make([]string, 0, len(ids))
	seen := map[int64]bool{}
	for _, id := range ids {
		if id <= 0 || seen[id] {
			return nil
		}
		seen[id] = true
		result = append(result, strconv.FormatInt(id, 10))
	}
	return result
}
