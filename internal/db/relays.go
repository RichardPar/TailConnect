package db

import (
	"context"
	"crypto/rand"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"
)

// RelayTokenPrefix starts every relay token.
const RelayTokenPrefix = "tc-relay-"

// RelayToken is a standalone relay's credential. The secret is only
// returned at creation; the database keeps its SHA-256 hash.
type RelayToken struct {
	ID        int64
	Name      string
	CreatedAt time.Time
	LastUsed  time.Time // zero if never used
}

// CreateRelayToken creates a credential for the relay called name and
// returns its secret (shown once).
func (d *DB) CreateRelayToken(ctx context.Context, name string) (string, RelayToken, error) {
	name = strings.TrimSpace(name)
	if name == "" || len(name) > 64 {
		return "", RelayToken{}, fmt.Errorf("%w: relay name must be 1-64 characters", ErrInvalid)
	}
	var raw [20]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", RelayToken{}, err
	}
	secret := RelayTokenPrefix + strings.ToLower(b32.EncodeToString(raw[:]))
	t := RelayToken{Name: name, CreatedAt: fromUnix(unix(d.now()))}
	res, err := d.sql.ExecContext(ctx, `INSERT INTO relay_tokens(name, hash, created_at) VALUES(?, ?, ?)`,
		name, hashAuthKey(secret), unix(t.CreatedAt))
	if err != nil {
		if strings.Contains(err.Error(), "UNIQUE") {
			return "", RelayToken{}, fmt.Errorf("relay %q: %w", name, ErrExists)
		}
		return "", RelayToken{}, err
	}
	t.ID, _ = res.LastInsertId()
	return secret, t, nil
}

// ListRelayTokens lists relay credentials by ID.
func (d *DB) ListRelayTokens(ctx context.Context) ([]RelayToken, error) {
	rows, err := d.sql.QueryContext(ctx, `SELECT id, name, created_at, last_used FROM relay_tokens ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []RelayToken
	for rows.Next() {
		var t RelayToken
		var created, used int64
		if err := rows.Scan(&t.ID, &t.Name, &created, &used); err != nil {
			return nil, err
		}
		t.CreatedAt = fromUnix(created)
		if used != 0 {
			t.LastUsed = fromUnix(used)
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

// DeleteRelayToken revokes the relay credential called name (or with that ID).
func (d *DB) DeleteRelayToken(ctx context.Context, nameOrID string) error {
	res, err := d.sql.ExecContext(ctx, `DELETE FROM relay_tokens WHERE name = ? OR CAST(id AS TEXT) = ?`, nameOrID, nameOrID)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return fmt.Errorf("relay %q: %w", nameOrID, ErrNotFound)
	}
	return nil
}

// CheckRelayToken returns the relay a secret belongs to, recording its use
// (at most once a minute, to keep writes rare).
func (d *DB) CheckRelayToken(ctx context.Context, secret string) (RelayToken, error) {
	if !strings.HasPrefix(secret, RelayTokenPrefix) {
		return RelayToken{}, ErrNotFound
	}
	var t RelayToken
	var created, used int64
	err := d.sql.QueryRowContext(ctx, `SELECT id, name, created_at, last_used FROM relay_tokens WHERE hash = ?`,
		hashAuthKey(secret)).Scan(&t.ID, &t.Name, &created, &used)
	if errors.Is(err, sql.ErrNoRows) {
		return RelayToken{}, ErrNotFound
	}
	if err != nil {
		return RelayToken{}, err
	}
	t.CreatedAt, t.LastUsed = fromUnix(created), fromUnix(used)
	if now := d.now(); now.Sub(t.LastUsed) >= time.Minute {
		d.sql.ExecContext(ctx, `UPDATE relay_tokens SET last_used = ? WHERE id = ?`, unix(now), t.ID)
		t.LastUsed = fromUnix(unix(now))
	}
	return t, nil
}
