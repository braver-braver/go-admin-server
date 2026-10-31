package store

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
)

// Session is a stored login session.
type Session struct {
	AccountID         string
	CredentialVersion int
	CSRFToken         string
	ExpiresAt         time.Time
}

// CreateSession stores a session under the hash of its cookie token and drops
// the session being replaced (login rotates the token) and expired ones.
func (s *Store) CreateSession(ctx context.Context, tokenHash, replacedHash []byte, sess Session, ip, userAgent string) error {
	return s.tx(ctx, func(tx pgx.Tx) error {
		if replacedHash != nil {
			if _, err := tx.Exec(ctx, `DELETE FROM sessions WHERE token_hash = $1`, replacedHash); err != nil {
				return err
			}
		}
		if _, err := tx.Exec(ctx, `DELETE FROM sessions WHERE account_id = $1 AND expires_at <= now()`, sess.AccountID); err != nil {
			return err
		}
		_, err := tx.Exec(ctx, `INSERT INTO sessions (token_hash, account_id, credential_version, csrf_token, expires_at, ip, user_agent)
			VALUES ($1, $2, $3, $4, $5, $6, $7)`,
			tokenHash, sess.AccountID, sess.CredentialVersion, sess.CSRFToken, sess.ExpiresAt, ip, userAgent)
		return err
	})
}

// GetSession returns an unexpired session, or nil.
func (s *Store) GetSession(ctx context.Context, tokenHash []byte) (*Session, error) {
	var sess Session
	err := s.pool.QueryRow(ctx, `SELECT account_id, credential_version, csrf_token, expires_at
		FROM sessions WHERE token_hash = $1 AND expires_at > now()`, tokenHash).
		Scan(&sess.AccountID, &sess.CredentialVersion, &sess.CSRFToken, &sess.ExpiresAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &sess, nil
}

// DeleteSession revokes a session.
func (s *Store) DeleteSession(ctx context.Context, tokenHash []byte) error {
	_, err := s.pool.Exec(ctx, `DELETE FROM sessions WHERE token_hash = $1`, tokenHash)
	return err
}

// PurgeExpiredSessions removes expired sessions; run it periodically.
func (s *Store) PurgeExpiredSessions(ctx context.Context) (int64, error) {
	tag, err := s.pool.Exec(ctx, `DELETE FROM sessions WHERE expires_at <= now()`)
	return tag.RowsAffected(), err
}
