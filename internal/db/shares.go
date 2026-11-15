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

// ShareLinkPrefix starts every share link code.
const ShareLinkPrefix = "tc-share-"

// Share statuses.
const (
	SharePending  = "pending"  // offered to a named account, not yet accepted
	ShareAccepted = "accepted" // in effect
)

// ErrInvalidShareLink: the code is unknown, expired or already redeemed.
var ErrInvalidShareLink = errors.New("invalid, expired or already-used share link")

// Share gives one machine's owner tenant's permission for another tenant's
// machines to connect to it. The machine can't connect back.
type Share struct {
	ID          int64
	NodeID      int64
	NodeName    string
	OwnerID     int64
	OwnerName   string
	OwnerStatus string
	OwnerDomain string // the owner account's own MagicDNS domain ("" = default)
	// RecipientID is 0 for a link nobody has redeemed yet.
	RecipientID     int64
	RecipientName   string
	RecipientStatus string
	Status          string
	Link            bool   // created as a share link
	LinkPrefix      string // display prefix of the link code
	CreatedAt       time.Time
	AcceptedAt      time.Time
	ExpiresAt       time.Time // links only: when an unredeemed link stops working
}

// InEffect reports whether the share currently lets traffic through: it was
// accepted and both accounts are active.
func (s Share) InEffect() bool {
	return s.Status == ShareAccepted && s.RecipientID != 0 && s.OwnerStatus == StatusActive && s.RecipientStatus == StatusActive
}

const shareSelect = `
	SELECT s.id, s.node_id, n.given_name, n.user_id, o.name, o.status, o.dns_domain,
	       COALESCE(s.recipient_id, 0), COALESCE(r.name, ''), COALESCE(r.status, ''),
	       s.status, s.invite_prefix, s.created_at, s.accepted_at, s.expires_at
	FROM shares s
	JOIN nodes n ON n.id = s.node_id
	JOIN users o ON o.id = n.user_id
	LEFT JOIN users r ON r.id = s.recipient_id`

func scanShare(r rowScanner) (Share, error) {
	var s Share
	var created int64
	var accepted, expires sql.NullInt64
	err := r.Scan(&s.ID, &s.NodeID, &s.NodeName, &s.OwnerID, &s.OwnerName, &s.OwnerStatus, &s.OwnerDomain,
		&s.RecipientID, &s.RecipientName, &s.RecipientStatus,
		&s.Status, &s.LinkPrefix, &created, &accepted, &expires)
	s.CreatedAt = fromUnix(created)
	if accepted.Valid {
		s.AcceptedAt = fromUnix(accepted.Int64)
	}
	if expires.Valid {
		s.ExpiresAt = fromUnix(expires.Int64)
	}
	s.Link = s.LinkPrefix != ""
	return s, err
}

func (d *DB) GetShare(ctx context.Context, id int64) (Share, error) {
	s, err := scanShare(d.sql.QueryRowContext(ctx, shareSelect+` WHERE s.id = ?`, id))
	if errors.Is(err, sql.ErrNoRows) {
		return Share{}, fmt.Errorf("share %d: %w", id, ErrNotFound)
	}
	return s, err
}

// ShareFilter selects shares; zero fields match everything. With both
// OwnerID and RecipientID set, shares matching either are returned.
type ShareFilter struct {
	OwnerID     int64
	RecipientID int64
	Accepted    bool // only accepted shares
}

func (d *DB) ListShares(ctx context.Context, f ShareFilter) ([]Share, error) {
	return listShares(ctx, d.sql, f)
}

func listShares(ctx context.Context, db queryer, f ShareFilter) ([]Share, error) {
	q := shareSelect + ` WHERE 1=1`
	var args []any
	switch {
	case f.OwnerID != 0 && f.RecipientID != 0:
		q += ` AND (n.user_id = ? OR s.recipient_id = ?)`
		args = append(args, f.OwnerID, f.RecipientID)
	case f.OwnerID != 0:
		q += ` AND n.user_id = ?`
		args = append(args, f.OwnerID)
	case f.RecipientID != 0:
		q += ` AND s.recipient_id = ?`
		args = append(args, f.RecipientID)
	}
	if f.Accepted {
		q += ` AND s.status = '` + ShareAccepted + `'`
	}
	rows, err := db.QueryContext(ctx, q+` ORDER BY s.id`, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Share
	for rows.Next() {
		s, err := scanShare(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, s)
	}
	return out, rows.Err()
}

// ShareWith offers node nodeID to the account named recipient. The share is
// pending until the recipient accepts it.
func (d *DB) ShareWith(ctx context.Context, nodeID int64, recipient string) (Share, error) {
	n, err := d.GetNode(ctx, nodeID)
	if err != nil {
		return Share{}, err
	}
	r, err := d.GetUser(ctx, recipient)
	if err != nil {
		return Share{}, err
	}
	if r.ID == n.UserID {
		return Share{}, fmt.Errorf("%w: %s already owns %s", ErrInvalid, r.Name, n.GivenName)
	}
	if !r.Active() {
		return Share{}, fmt.Errorf("%w: account %s is not active", ErrInvalid, r.Name)
	}
	res, err := d.sql.ExecContext(ctx, `INSERT INTO shares(node_id, recipient_id, status, created_at) VALUES(?, ?, ?, ?)`,
		nodeID, r.ID, SharePending, unix(d.now()))
	if isUniqueViolation(err) {
		return Share{}, fmt.Errorf("%s is already shared with %s: %w", n.GivenName, r.Name, ErrExists)
	}
	if err != nil {
		return Share{}, err
	}
	id, _ := res.LastInsertId()
	return d.GetShare(ctx, id)
}

// CreateShareLink makes a single-use link code for node nodeID, valid for
// ttl. The first other account to redeem it gets the share (already
// accepted: redeeming is accepting).
func (d *DB) CreateShareLink(ctx context.Context, nodeID int64, ttl time.Duration) (string, Share, error) {
	if ttl <= 0 {
		return "", Share{}, fmt.Errorf("%w: link lifetime must be positive", ErrInvalid)
	}
	if _, err := d.GetNode(ctx, nodeID); err != nil {
		return "", Share{}, err
	}
	var raw [20]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", Share{}, err
	}
	code := ShareLinkPrefix + strings.ToLower(b32.EncodeToString(raw[:]))
	now := d.now()
	res, err := d.sql.ExecContext(ctx, `
		INSERT INTO shares(node_id, status, invite_hash, invite_prefix, created_at, expires_at) VALUES(?, ?, ?, ?, ?, ?)`,
		nodeID, SharePending, hashAuthKey(code), code[:len(ShareLinkPrefix)+8], unix(now), unix(now.Add(ttl)))
	if err != nil {
		return "", Share{}, err
	}
	id, _ := res.LastInsertId()
	s, err := d.GetShare(ctx, id)
	return code, s, err
}

// RedeemShareLink gives the share behind code to recipientID.
func (d *DB) RedeemShareLink(ctx context.Context, code string, recipientID int64) (Share, error) {
	code = strings.TrimSpace(code)
	if !strings.HasPrefix(code, ShareLinkPrefix) {
		return Share{}, ErrInvalidShareLink
	}
	tx, err := d.sql.BeginTx(ctx, nil)
	if err != nil {
		return Share{}, err
	}
	defer tx.Rollback()
	var id, owner int64
	var expires sql.NullInt64
	var recipient sql.NullInt64
	err = tx.QueryRowContext(ctx, `
		SELECT s.id, n.user_id, s.expires_at, s.recipient_id FROM shares s JOIN nodes n ON n.id = s.node_id
		WHERE s.invite_hash = ?`, hashAuthKey(code)).Scan(&id, &owner, &expires, &recipient)
	if errors.Is(err, sql.ErrNoRows) {
		return Share{}, ErrInvalidShareLink
	}
	if err != nil {
		return Share{}, err
	}
	now := d.now()
	if recipient.Valid || (expires.Valid && unix(now) >= expires.Int64) {
		return Share{}, ErrInvalidShareLink
	}
	if owner == recipientID {
		return Share{}, fmt.Errorf("%w: that machine is already yours", ErrInvalid)
	}
	_, err = tx.ExecContext(ctx, `UPDATE shares SET recipient_id = ?, status = ?, accepted_at = ?, invite_hash = NULL WHERE id = ?`,
		recipientID, ShareAccepted, unix(now), id)
	if isUniqueViolation(err) {
		return Share{}, fmt.Errorf("that machine is already shared with you: %w", ErrExists)
	}
	if err != nil {
		return Share{}, err
	}
	if err := tx.Commit(); err != nil {
		return Share{}, err
	}
	return d.GetShare(ctx, id)
}

// AcceptShare accepts a pending share offered to recipientID.
func (d *DB) AcceptShare(ctx context.Context, id, recipientID int64) error {
	res, err := d.sql.ExecContext(ctx, `UPDATE shares SET status = ?, accepted_at = ? WHERE id = ? AND recipient_id = ? AND status = ?`,
		ShareAccepted, unix(d.now()), id, recipientID, SharePending)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return fmt.Errorf("pending share %d for you: %w", id, ErrNotFound)
	}
	return nil
}

// DeleteShare revokes (owner), declines or leaves (recipient) a share.
// actorID 0 (an operator) may delete any share; otherwise the actor must be
// the machine's owner or the recipient. Others get ErrNotFound.
func (d *DB) DeleteShare(ctx context.Context, id, actorID int64) error {
	res, err := d.sql.ExecContext(ctx, `
		DELETE FROM shares WHERE id = ? AND (? = 0 OR recipient_id = ? OR node_id IN (SELECT id FROM nodes WHERE user_id = ?))`,
		id, actorID, actorID, actorID)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return fmt.Errorf("share %d: %w", id, ErrNotFound)
	}
	return nil
}
