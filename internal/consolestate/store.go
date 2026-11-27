// Package consolestate persists console login transactions and opaque sessions.
// It exposes no general identity queries or management operations.
package consolestate

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/zhizhun-tech/memberid/internal/config"
)

type Store struct {
	pool *pgxpool.Pool
}

func New(pool *pgxpool.Pool) *Store { return &Store{pool: pool} }

type Login struct {
	Verifier, Nonce, ReturnTo         string
	SwitchMemberID, SourceSessionHash string
}

type Session struct {
	MemberID, GrantID, CSRF string
}

func (store *Store) BeginLogin(ctx context.Context, state, browser string, login Login) error {
	_, err := store.pool.Exec(ctx, "DELETE FROM console_logins WHERE expires_at<clock_timestamp()")
	if err == nil {
		_, err = store.pool.Exec(ctx, "DELETE FROM console_sessions WHERE expires_at<clock_timestamp() OR absolute_expires_at<clock_timestamp()")
	}
	if err == nil {
		_, err = store.pool.Exec(ctx, "INSERT INTO console_logins(state_hash,browser_hash,verifier,nonce,return_to,switch_member_id,source_session_hash,expires_at) VALUES($1,$2,$3,$4,$5,$6,$7,clock_timestamp()+interval '5 minutes')", config.SecretHash(state), config.SecretHash(browser), login.Verifier, login.Nonce, login.ReturnTo, login.SwitchMemberID, login.SourceSessionHash)
	}
	return err
}

func (store *Store) ConsumeLogin(ctx context.Context, state, browser string) (Login, error) {
	var login Login
	err := store.pool.QueryRow(ctx, "DELETE FROM console_logins WHERE state_hash=$1 AND browser_hash=$2 AND expires_at>clock_timestamp() RETURNING verifier,nonce,return_to,switch_member_id,source_session_hash", config.SecretHash(state), config.SecretHash(browser)).Scan(&login.Verifier, &login.Nonce, &login.ReturnTo, &login.SwitchMemberID, &login.SourceSessionHash)
	return login, err
}

// Grant resolves the exact access token verified by the OIDC callback. The
// management service separately checks the Member's current eligibility.
func (store *Store) Grant(ctx context.Context, sessionID, clientID, memberID, accessTokenID string) (string, error) {
	var grantID string
	err := store.pool.QueryRow(ctx, `SELECT g.id FROM oidc_grants g JOIN oidc_access_tokens a ON a.grant_id=g.id
 WHERE a.id=$4 AND a.expires_at>clock_timestamp() AND g.session_id=$1 AND g.client_id=$2
 AND g.data->>'memberId'=$3 AND g.revoked_at IS NULL AND g.expires_at>clock_timestamp()`, sessionID, clientID, memberID, accessTokenID).Scan(&grantID)
	return grantID, err
}

func (store *Store) CreateSession(ctx context.Context, secret string, session Session, absolute time.Time) error {
	_, err := store.pool.Exec(ctx, `INSERT INTO console_sessions(secret_hash,grant_id,member_id,csrf,expires_at,absolute_expires_at) VALUES($1,$2,$3,$4,LEAST($5,clock_timestamp()+interval '30 minutes'),$5)`, config.SecretHash(secret), session.GrantID, session.MemberID, session.CSRF, absolute)
	return err
}

// Session renews only the console cookie record. It does not load or cache roles.
func (store *Store) Session(ctx context.Context, secret string) (Session, error) {
	var session Session
	err := store.pool.QueryRow(ctx, `UPDATE console_sessions SET expires_at=LEAST(absolute_expires_at,clock_timestamp()+interval '30 minutes')
 WHERE secret_hash=$1 AND expires_at>clock_timestamp() AND absolute_expires_at>clock_timestamp() RETURNING member_id,grant_id,csrf`, config.SecretHash(secret)).Scan(&session.MemberID, &session.GrantID, &session.CSRF)
	return session, err
}

func (store *Store) DeleteSession(ctx context.Context, secret string) error {
	_, err := store.pool.Exec(ctx, "DELETE FROM console_sessions WHERE secret_hash=$1", config.SecretHash(secret))
	return err
}

// SwitchSession replaces only the initiating console session. Competing switches
// and a logout invalidate that source, while a failed insert preserves it.
func (store *Store) SwitchSession(ctx context.Context, previous, secret string, session Session, absolute time.Time) error {
	return pgx.BeginFunc(ctx, store.pool, func(tx pgx.Tx) error {
		result, err := tx.Exec(ctx, `DELETE FROM console_sessions WHERE secret_hash=$1
 AND expires_at>clock_timestamp() AND absolute_expires_at>clock_timestamp()`, config.SecretHash(previous))
		if err != nil {
			return err
		}
		if result.RowsAffected() != 1 {
			return pgx.ErrNoRows
		}
		_, err = tx.Exec(ctx, `INSERT INTO console_sessions(secret_hash,grant_id,member_id,csrf,expires_at,absolute_expires_at)
 VALUES($1,$2,$3,$4,LEAST($5,clock_timestamp()+interval '30 minutes'),$5)`, config.SecretHash(secret), session.GrantID, session.MemberID, session.CSRF, absolute)
		return err
	})
}
