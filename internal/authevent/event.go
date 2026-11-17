// Package authevent records bounded, best-effort authentication evidence.
// Events are never used to make authentication or authorization decisions.
package authevent

import (
	"context"
	"crypto/rand"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

type Actor struct {
	Kind string `json:"kind,omitempty"`
	ID   string `json:"id,omitempty"`
}

// Event has no arbitrary attributes or credential-bearing payloads. Producers
// capture established references at the operation boundary, never during delivery.
type Event struct {
	EventID        string    `json:"eventId"`
	Type           string    `json:"type"`
	Outcome        string    `json:"outcome"`
	ReasonCode     string    `json:"reasonCode,omitempty"`
	OccurredAt     time.Time `json:"occurredAt"`
	RecordedAt     time.Time `json:"recordedAt,omitzero"`
	InteractionID  string    `json:"interactionId,omitempty"`
	RequestID      string    `json:"requestId,omitempty"`
	Actor          Actor     `json:"actor,omitzero"`
	OrganizationID string    `json:"organizationId,omitempty"`
	MemberID       string    `json:"memberId,omitempty"`
	ClientID       string    `json:"clientId,omitempty"`
	ClientName     string    `json:"clientName,omitempty"`
	FactorID       string    `json:"factorId,omitempty"`
	BindingID      string    `json:"bindingId,omitempty"`
	SessionID      string    `json:"sessionId,omitempty"`
	GrantID        string    `json:"grantId,omitempty"`
	ProviderID     string    `json:"providerId,omitempty"`
	Method         string    `json:"method,omitempty"`
	Purpose        string    `json:"purpose,omitempty"`
	Trigger        string    `json:"trigger,omitempty"`
	CausationID    string    `json:"causationId,omitempty"`
}

func NewID() string { return rand.Text() }

func (event Event) valid() bool {
	switch event.Type {
	case "sms.send", "authentication.verify", "oidc.grant.issue", "saml.request", "saml.assertion.issue", "session.revoke", "grant.revoke":
		if !oneOf(event.Outcome, "succeeded", "rejected", "failed") {
			return false
		}
	case "oidc.authorizationCode.reuse", "oidc.refreshToken.reuse", "saml.request.reuse":
		if event.Outcome != "detected" {
			return false
		}
	default:
		return false
	}
	if !oneOf(event.ReasonCode, "", "invalidCredential", "expiredCredential", "invalidRequest", "sendRateLimited", "rateLimited", "providerUnavailable", "backendUnavailable", "commitUnconfirmed", "ineligible", "canceled") ||
		!oneOf(event.Method, "", "sms", "dingtalk", "feishu", "pwd") ||
		!oneOf(event.Purpose, "", "login", "accountLinking") ||
		!oneOf(event.Trigger, "", "browserLogout", "clientRevocation", "operatorRequest", "replayDetection") ||
		!oneOf(event.Actor.Kind, "", "factor", "member", "client", "operator", "manager", "system") {
		return false
	}
	if (event.Actor.Kind == "") != (event.Actor.ID == "") || event.OccurredAt.IsZero() || event.EventID == "" {
		return false
	}
	if event.ClientName != "" && (event.ClientID == "" || !utf8.ValidString(event.ClientName) ||
		strings.TrimSpace(event.ClientName) == "" || utf8.RuneCountInString(event.ClientName) > 128 ||
		strings.IndexFunc(event.ClientName, unicode.IsControl) != -1) {
		return false
	}
	for _, value := range []string{event.EventID, event.InteractionID, event.RequestID, event.Actor.ID, event.OrganizationID, event.MemberID, event.ClientID, event.FactorID, event.BindingID, event.SessionID, event.GrantID, event.CausationID, event.ProviderID} {
		if len(value) > 128 {
			return false
		}
		for _, c := range value {
			if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || strings.ContainsRune("_.-:", c)) {
				return false
			}
		}
	}
	return true
}
func oneOf(value string, choices ...string) bool {
	for _, choice := range choices {
		if value == choice {
			return true
		}
	}
	return false
}

type requestKey struct{}
type eventKey struct{}

func RequestContext(ctx context.Context) context.Context {
	return context.WithValue(ctx, requestKey{}, NewID())
}
func WithContext(ctx context.Context, event Event) context.Context {
	return context.WithValue(ctx, eventKey{}, event)
}
func FromContext(ctx context.Context) Event {
	event, _ := ctx.Value(eventKey{}).(Event)
	event.RequestID, _ = ctx.Value(requestKey{}).(string)
	return event
}
