package db

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base32"
	"errors"
	"fmt"
	"strings"
	"time"
)

// AuthKeyPrefix starts every pre-auth key, so leaked keys are easy to spot.
const AuthKeyPrefix = "tc-auth-"

// PreAuthKey describes a stored key. The secret itself is only returned once,
// at creation; the database keeps a SHA-256 hash.
type PreAuthKey struct {
	ID        int64
	Prefix    string // first characters of the secret, for display
	UserID    int64
	UserName  string
	Reusable  bool
	Ephemeral bool
	// Preapproved: machines joining with it skip the account's machine approval.
	Preapproved bool
	Uses        int
	CreatedAt   time.Time
	ExpiresAt   time.Time
	Revoked     bool
}

// Usable reports whether the key could still register a new node at time now.
func (k PreAuthKey) Usable(now time.Time) bool {
	return !k.Revoked && now.Before(k.ExpiresAt) && (k.Reusable || k.Uses == 0)
}

type CreatePreAuthKeyParams struct {
	UserID      int64
	Reusable    bool
	Ephemeral   bool
	Preapproved bool
	TTL         time.Duration
}

var b32 = base32.StdEncoding.WithPadding(base32.NoPadding)

func hashAuthKey(secret string) []byte {
	h := sha256.Sum256([]byte(secret))
	return h[:]
}

// CreatePreAuthKey generates a new key and returns its secret (shown once).
func (d *DB) CreatePreAuthKey(ctx context.Context, p CreatePreAuthKeyParams) (string, PreAuthKey, error) {
	if p.TTL <= 0 {
		return "", PreAuthKey{}, fmt.Errorf("%w: auth key TTL must be positive", ErrInvalid)
	}
	var raw [20]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", PreAuthKey{}, err
	}
	secret := AuthKeyPrefix + strings.ToLower(b32.EncodeToString(raw[:]))
	now := d.now()
	k := PreAuthKey{
		Prefix:      secret[:len(AuthKeyPrefix)+8],
		UserID:      p.UserID,
		Reusable:    p.Reusable,
		Ephemeral:   p.Ephemeral,
		Preapproved: p.Preapproved,
		CreatedAt:   fromUnix(unix(now)),
		ExpiresAt:   fromUnix(unix(now.Add(p.TTL))),
	}
	res, err := d.sql.ExecContext(ctx, `
		INSERT INTO preauth_keys(hash, prefix, user_id, reusable, ephemeral, preapproved, created_at, expires_at)
		VALUES(?, ?, ?, ?, ?, ?, ?, ?)`,
		hashAuthKey(secret), k.Prefix, k.UserID, k.Reusable, k.Ephemeral, k.Preapproved, unix(k.CreatedAt), unix(k.ExpiresAt))
	if err != nil {
		return "", PreAuthKey{}, err
	}
	k.ID, _ = res.LastInsertId()
	if err := d.sql.QueryRowContext(ctx, `SELECT name FROM users WHERE id = ?`, k.UserID).Scan(&k.UserName); err != nil {
		return "", PreAuthKey{}, err
	}
	return secret, k, nil
}

const preauthCols = `k.id, k.prefix, k.user_id, u.name, k.reusable, k.ephemeral, k.preapproved, k.uses, k.created_at, k.expires_at, k.revoked`

type rowScanner interface{ Scan(...any) error }

func scanPreAuthKey(r rowScanner) (PreAuthKey, error) {
	var k PreAuthKey
	var created, expires int64
	err := r.Scan(&k.ID, &k.Prefix, &k.UserID, &k.UserName, &k.Reusable, &k.Ephemeral, &k.Preapproved, &k.Uses, &created, &expires, &k.Revoked)
	k.CreatedAt, k.ExpiresAt = fromUnix(created), fromUnix(expires)
	return k, err
}

// ListPreAuthKeys lists keys, optionally filtered to one user (userID 0 = all).
func (d *DB) ListPreAuthKeys(ctx context.Context, userID int64) ([]PreAuthKey, error) {
	rows, err := d.sql.QueryContext(ctx, `
		SELECT `+preauthCols+` FROM preauth_keys k JOIN users u ON u.id = k.user_id
		WHERE ? = 0 OR k.user_id = ? ORDER BY k.id`, userID, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []PreAuthKey
	for rows.Next() {
		k, err := scanPreAuthKey(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, k)
	}
	return out, rows.Err()
}

// RevokePreAuthKey makes a key unusable. Nodes already registered with it stay.
func (d *DB) RevokePreAuthKey(ctx context.Context, id int64) error {
	return d.RevokeUserPreAuthKey(ctx, id, 0)
}

// RevokeUserPreAuthKey revokes key id only if it belongs to userID (0 = any
// user). A key of another user is reported as not found.
func (d *DB) RevokeUserPreAuthKey(ctx context.Context, id, userID int64) error {
	res, err := d.sql.ExecContext(ctx, `UPDATE preauth_keys SET revoked = 1 WHERE id = ? AND (? = 0 OR user_id = ?)`, id, userID, userID)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return fmt.Errorf("auth key %d: %w", id, ErrNotFound)
	}
	return nil
}

// consumePreAuthKey validates secret inside tx and records one use.
func consumePreAuthKey(ctx context.Context, tx *sql.Tx, secret string, now time.Time) (PreAuthKey, error) {
	if !strings.HasPrefix(secret, AuthKeyPrefix) {
		return PreAuthKey{}, ErrInvalidAuthKey
	}
	k, err := scanPreAuthKey(tx.QueryRowContext(ctx, `
		SELECT `+preauthCols+` FROM preauth_keys k JOIN users u ON u.id = k.user_id
		WHERE k.hash = ?`, hashAuthKey(secret)))
	if errors.Is(err, sql.ErrNoRows) {
		return PreAuthKey{}, ErrInvalidAuthKey
	}
	if err != nil {
		return PreAuthKey{}, err
	}
	if !k.Usable(now) {
		return PreAuthKey{}, ErrInvalidAuthKey
	}
	var status string
	if err := tx.QueryRowContext(ctx, `SELECT status FROM users WHERE id = ?`, k.UserID).Scan(&status); err != nil {
		return PreAuthKey{}, err
	}
	if status != StatusActive {
		return PreAuthKey{}, ErrAccountInactive
	}
	if _, err := tx.ExecContext(ctx, `UPDATE preauth_keys SET uses = uses + 1 WHERE id = ?`, k.ID); err != nil {
		return PreAuthKey{}, err
	}
	k.Uses++
	return k, nil
}
