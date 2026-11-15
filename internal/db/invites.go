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

// InvitePrefix starts every invite code.
const InvitePrefix = "tc-invite-"

// Invite is an operator-issued, single-use code that lets someone sign up
// when sign-up is invite-only. Like auth keys, only a hash is stored.
type Invite struct {
	ID        int64
	Prefix    string
	CreatedAt time.Time
	ExpiresAt time.Time
	UsedBy    string // user name, "" if unused (or the user was deleted)
	UsedAt    time.Time
	Revoked   bool
}

func (i Invite) Usable(now time.Time) bool {
	return !i.Revoked && i.UsedAt.IsZero() && now.Before(i.ExpiresAt)
}

// CreateInvite generates an invite code valid for ttl and returns it (shown once).
func (d *DB) CreateInvite(ctx context.Context, ttl time.Duration) (string, Invite, error) {
	if ttl <= 0 {
		return "", Invite{}, fmt.Errorf("%w: invite lifetime must be positive", ErrInvalid)
	}
	var raw [20]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", Invite{}, err
	}
	secret := InvitePrefix + strings.ToLower(b32.EncodeToString(raw[:]))
	now := d.now()
	inv := Invite{Prefix: secret[:len(InvitePrefix)+8], CreatedAt: fromUnix(unix(now)), ExpiresAt: fromUnix(unix(now.Add(ttl)))}
	res, err := d.sql.ExecContext(ctx, `INSERT INTO invites(hash, prefix, created_at, expires_at) VALUES(?, ?, ?, ?)`,
		hashAuthKey(secret), inv.Prefix, unix(inv.CreatedAt), unix(inv.ExpiresAt))
	if err != nil {
		return "", Invite{}, err
	}
	inv.ID, _ = res.LastInsertId()
	return secret, inv, nil
}

const inviteCols = `i.id, i.prefix, i.created_at, i.expires_at, COALESCE(u.name, ''), i.used_at, i.revoked`

func scanInvite(r rowScanner) (Invite, error) {
	var inv Invite
	var created, expires int64
	var used sql.NullInt64
	err := r.Scan(&inv.ID, &inv.Prefix, &created, &expires, &inv.UsedBy, &used, &inv.Revoked)
	inv.CreatedAt, inv.ExpiresAt = fromUnix(created), fromUnix(expires)
	if used.Valid {
		inv.UsedAt = fromUnix(used.Int64)
	}
	return inv, err
}

func (d *DB) ListInvites(ctx context.Context) ([]Invite, error) {
	rows, err := d.sql.QueryContext(ctx, `SELECT `+inviteCols+` FROM invites i LEFT JOIN users u ON u.id = i.used_by ORDER BY i.id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Invite
	for rows.Next() {
		inv, err := scanInvite(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, inv)
	}
	return out, rows.Err()
}

func (d *DB) RevokeInvite(ctx context.Context, id int64) error {
	res, err := d.sql.ExecContext(ctx, `UPDATE invites SET revoked = 1 WHERE id = ?`, id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return fmt.Errorf("invite %d: %w", id, ErrNotFound)
	}
	return nil
}

// consumeInvite validates secret inside tx and marks it used by user uid.
func consumeInvite(ctx context.Context, tx *sql.Tx, secret string, uid int64, now time.Time) error {
	secret = strings.TrimSpace(secret)
	if !strings.HasPrefix(secret, InvitePrefix) {
		return ErrInvalidInvite
	}
	inv, err := scanInvite(tx.QueryRowContext(ctx,
		`SELECT `+inviteCols+` FROM invites i LEFT JOIN users u ON u.id = i.used_by WHERE i.hash = ?`, hashAuthKey(secret)))
	if errors.Is(err, sql.ErrNoRows) {
		return ErrInvalidInvite
	}
	if err != nil {
		return err
	}
	if !inv.Usable(now) {
		return ErrInvalidInvite
	}
	_, err = tx.ExecContext(ctx, `UPDATE invites SET used_by = ?, used_at = ? WHERE id = ?`, uid, unix(now), inv.ID)
	return err
}
