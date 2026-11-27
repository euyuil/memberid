// Package browserauth contains the browser authentication state shared by the
// OIDC and SAML protocol continuations. It issues no portable credentials.
package browserauth

import (
	"time"

	"github.com/zhizhun-tech/memberid/internal/identity"
)

type Policy struct {
	ID                  string
	OrganizationID      string
	SubjectKind         string
	Preauthorized       bool
	ReturnURI           string
	IdentityInformation string
}

type DingTalkAttempt struct {
	StateHash string `json:"stateHash"`
	identity.DingTalkLoginContext
	ExpiresAt time.Time `json:"expiresAt"`
	Consumed  bool      `json:"consumed"`
}

type FeishuAttempt struct {
	identity.FeishuLoginContext
	StateHash string    `json:"stateHash"`
	Verifier  string    `json:"verifier,omitempty"`
	ExpiresAt time.Time `json:"expiresAt"`
}

type Interaction struct {
	Revision               int64                  `json:"-"`
	BrowserHash            string                 `json:"browserHash"`
	CSRF                   string                 `json:"csrf"`
	PhoneNumber            string                 `json:"phoneNumber,omitempty"`
	ChallengeID            string                 `json:"challengeId,omitempty"`
	Verification           *identity.Verification `json:"verification,omitempty"`
	DingTalk               *DingTalkAttempt       `json:"dingtalk,omitempty"`
	Feishu                 *FeishuAttempt         `json:"feishu,omitempty"`
	ProviderOrganizationID string                 `json:"providerOrganizationId,omitempty"`
	Fresh                  bool                   `json:"fresh"`
	Complete               bool                   `json:"complete"`
}
