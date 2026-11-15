package oidcprovider

import (
	"io"
	"testing"

	"github.com/euyuil/memberid/internal/authevent"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/zitadel/oidc/v3/pkg/oidc"
)

func TestGrantOperationUncertainty(t *testing.T) {
	for _, test := range []struct {
		name, outcome, reason string
		err                   error
		commitReady           bool
	}{
		{"committed", "succeeded", "", nil, true},
		{"denied", "rejected", "invalidCredential", oidc.ErrInvalidGrant(), false},
		{"statement failed", "failed", "backendUnavailable", io.EOF, false},
		{"commit acknowledgement lost", "failed", "commitUnconfirmed", io.EOF, true},
		{"commit constraint failed", "failed", "backendUnavailable", &pgconn.PgError{Code: "23514"}, true},
		{"commit rolled back", "failed", "backendUnavailable", pgx.ErrTxCommitRollback, true},
	} {
		t.Run(test.name, func(t *testing.T) {
			event := operationResult(authevent.Event{}, test.err, test.commitReady)
			if event.Outcome != test.outcome || event.ReasonCode != test.reason {
				t.Fatal(event)
			}
		})
	}
}
