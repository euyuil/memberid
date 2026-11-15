package identity

import (
	"errors"
	"testing"
	"time"
)

func TestAuthenticationEventFilterValidation(t *testing.T) {
	for _, f := range []AuthenticationEventFilter{
		{}, {Limit: 101}, {Limit: -1}, {Limit: 1, Type: "unknown"}, {Limit: 1, Outcome: "ok"}, {Limit: 1, Method: "password"},
		{Limit: 1, MemberID: "not-member"}, {Limit: 1, RequestID: "raw/token"}, {Limit: 1, From: "today"}, {Limit: 1, To: "yesterday"},
		{Limit: 1, From: "2026-01-01T00:00:00Z", To: "2025-01-01T00:00:00Z"}, {Limit: 1, After: "invalid"},
	} {
		if _, _, _, err := f.validate(); !errors.Is(err, ErrInvalid) {
			t.Fatal(f, err)
		}
	}
	service := NewManagementService(&Store{}, nil, nil, 24*time.Hour)
	for _, p := range []Principal{{}, OperatorPrincipal(), InstallationManagerPrincipal(), AccountPrincipal("session", "member", "factor", "binding")} {
		if _, err := service.AuthenticationEvents(t.Context(), p, "", AuthenticationEventFilter{}); !errors.Is(err, ErrForbidden) {
			t.Fatal("authorization must precede filters", err)
		}
		if _, err := service.AuthenticationEvent(t.Context(), p, "", "event"); !errors.Is(err, ErrForbidden) {
			t.Fatal("wrong entry context", err)
		}
	}
}
