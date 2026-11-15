package db

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"strconv"
	"strings"
	"time"
)

// Node is a registered device. Keys are stored in their text form
// ("nodekey:...") so this package has no dependency on the key types.
type Node struct {
	ID         int64
	UserID     int64
	UserName   string
	UserStatus string // the owning account's status (StatusActive, ...)
	MachineKey string
	NodeKey    string
	DiscoKey   string
	Hostname   string // as reported by the device
	GivenName  string // unique DNS label used for MagicDNS
	Hostinfo   string // JSON
	IPv4       netip.Addr
	IPv6       netip.Addr
	Endpoints  []netip.AddrPort
	HomeRelay  int
	Ephemeral  bool
	CreatedAt  time.Time
	LastSeen   time.Time // zero = never
	ExpiresAt  time.Time // zero = never
}

// AllocFunc picks addresses for a new node given the set of IPv4s in use.
type AllocFunc func(used map[netip.Addr]bool) (v4, v6 netip.Addr, err error)

type RegisterParams struct {
	MachineKey string
	NodeKey    string
	DiscoKey   string
	Hostname   string
	Hostinfo   string // JSON
	AuthKey    string
	Alloc      AllocFunc
}

type RegisterResult struct {
	Node    Node
	Created bool // a new node row was inserted
	Rotated bool // an existing machine got a new node key
}

// applyAuthKey consumes key (if any) and moves node id to the key's user.
func applyAuthKey(ctx context.Context, tx *sql.Tx, id int64, key string, now time.Time) error {
	if key == "" {
		return nil
	}
	k, err := consumePreAuthKey(ctx, tx, key, now)
	if err != nil {
		return err
	}
	// Moving to another tenant keeps the name unless it is taken there.
	var cur string
	if err := tx.QueryRowContext(ctx, `SELECT given_name FROM nodes WHERE id = ?`, id).Scan(&cur); err != nil {
		return err
	}
	name, err := uniqueGivenName(ctx, tx, k.UserID, cur, id)
	if err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx, `UPDATE nodes SET user_id = ?, given_name = ?, ephemeral = ?, preauth_key_id = ? WHERE id = ?`,
		k.UserID, name, k.Ephemeral, k.ID, id)
	return err
}

// RegisterNode atomically validates the auth key, allocates addresses and
// creates or updates the node for p.MachineKey.
//
//   - Unknown machine: AuthKey is required; a new node is created.
//   - Known machine, same node key: hostinfo/disco are refreshed; no auth key needed.
//   - Known machine, new node key: the node key is rotated, keeping addresses
//     and name. The caller must have authenticated the machine key (the Noise
//     channel does).
//
// For a known machine an AuthKey is optional; if given, it must be valid: it
// is consumed and the node moves to that key's user.
func (d *DB) RegisterNode(ctx context.Context, p RegisterParams) (RegisterResult, error) {
	if p.Hostinfo == "" {
		p.Hostinfo = "{}"
	}
	tx, err := d.sql.BeginTx(ctx, nil)
	if err != nil {
		return RegisterResult{}, err
	}
	defer tx.Rollback()
	now := d.now()

	existing, err := scanNode(tx.QueryRowContext(ctx, nodeSelect+` WHERE n.machine_key = ?`, p.MachineKey))
	switch {
	case err == nil && existing.NodeKey == p.NodeKey:
		if _, err := tx.ExecContext(ctx,
			`UPDATE nodes SET disco_key = ?, hostname = ?, hostinfo = ?, last_seen = ? WHERE id = ?`,
			p.DiscoKey, p.Hostname, p.Hostinfo, unix(now), existing.ID); err != nil {
			return RegisterResult{}, err
		}
		if err := applyAuthKey(ctx, tx, existing.ID, p.AuthKey, now); err != nil {
			return RegisterResult{}, err
		}
		n, err := getNodeTx(ctx, tx, existing.ID)
		if err != nil {
			return RegisterResult{}, err
		}
		if n.UserStatus != StatusActive {
			return RegisterResult{}, ErrAccountInactive
		}
		return RegisterResult{Node: n}, tx.Commit()

	case err == nil:
		_, err = tx.ExecContext(ctx, `
			UPDATE nodes SET node_key = ?, disco_key = ?, hostname = ?, hostinfo = ?, last_seen = ?, endpoints = '[]'
			WHERE id = ?`,
			p.NodeKey, p.DiscoKey, p.Hostname, p.Hostinfo, unix(now), existing.ID)
		if isUniqueViolation(err) {
			return RegisterResult{}, fmt.Errorf("node key: %w", ErrExists)
		}
		if err != nil {
			return RegisterResult{}, err
		}
		if err := applyAuthKey(ctx, tx, existing.ID, p.AuthKey, now); err != nil {
			return RegisterResult{}, err
		}
		n, err := getNodeTx(ctx, tx, existing.ID)
		if err != nil {
			return RegisterResult{}, err
		}
		if n.UserStatus != StatusActive {
			return RegisterResult{}, ErrAccountInactive
		}
		return RegisterResult{Node: n, Rotated: true}, tx.Commit()

	case !errors.Is(err, sql.ErrNoRows):
		return RegisterResult{}, err
	}

	// New machine.
	k, err := consumePreAuthKey(ctx, tx, p.AuthKey, now)
	if err != nil {
		return RegisterResult{}, err
	}
	used, err := usedIPv4s(ctx, tx)
	if err != nil {
		return RegisterResult{}, err
	}
	v4, v6, err := p.Alloc(used)
	if err != nil {
		return RegisterResult{}, err
	}
	name, err := uniqueGivenName(ctx, tx, k.UserID, SanitizeName(p.Hostname), 0)
	if err != nil {
		return RegisterResult{}, err
	}
	res, err := tx.ExecContext(ctx, `
		INSERT INTO nodes(user_id, machine_key, node_key, disco_key, hostname, given_name, hostinfo,
		                  ipv4, ipv6, ephemeral, preauth_key_id, created_at, last_seen)
		VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		k.UserID, p.MachineKey, p.NodeKey, p.DiscoKey, p.Hostname, name, p.Hostinfo,
		v4.String(), v6.String(), k.Ephemeral, k.ID, unix(now), unix(now))
	if isUniqueViolation(err) {
		return RegisterResult{}, fmt.Errorf("node key: %w", ErrExists)
	}
	if err != nil {
		return RegisterResult{}, err
	}
	id, _ := res.LastInsertId()
	n, err := getNodeTx(ctx, tx, id)
	if err != nil {
		return RegisterResult{}, err
	}
	return RegisterResult{Node: n, Created: true}, tx.Commit()
}

// NodeStatus is what a node reports about itself in a map request.
type NodeStatus struct {
	DiscoKey  string
	Endpoints []netip.AddrPort
	HomeRelay int
	Hostinfo  string // JSON; "" leaves the stored hostinfo unchanged
}

// UpdateNodeStatus records what a node reported in a map request.
func (d *DB) UpdateNodeStatus(ctx context.Context, id int64, st NodeStatus) error {
	discoKey, endpoints, hostinfo := st.DiscoKey, st.Endpoints, st.Hostinfo
	if endpoints == nil {
		endpoints = []netip.AddrPort{}
	}
	eps, err := json.Marshal(endpoints)
	if err != nil {
		return err
	}
	_, err = d.sql.ExecContext(ctx, `
		UPDATE nodes SET disco_key = ?, endpoints = ?, home_relay = ?, last_seen = ?,
		       hostinfo = CASE WHEN ? = '' THEN hostinfo ELSE ? END
		WHERE id = ?`,
		discoKey, string(eps), st.HomeRelay, unix(d.now()), hostinfo, hostinfo, id)
	return err
}

// TouchNode records that the node is alive without changing anything else.
func (d *DB) TouchNode(ctx context.Context, id int64) error {
	_, err := d.sql.ExecContext(ctx, `UPDATE nodes SET last_seen = ? WHERE id = ?`, unix(d.now()), id)
	return err
}

const nodeSelect = `
	SELECT n.id, n.user_id, u.name, u.status, n.machine_key, n.node_key, n.disco_key, n.hostname, n.given_name,
	       n.hostinfo, n.ipv4, n.ipv6, n.endpoints, n.home_relay, n.ephemeral, n.created_at, n.last_seen, n.expires_at
	FROM nodes n JOIN users u ON u.id = n.user_id`

func scanNode(r rowScanner) (Node, error) {
	var n Node
	var v4, v6, eps string
	var created int64
	var lastSeen, expires sql.NullInt64
	err := r.Scan(&n.ID, &n.UserID, &n.UserName, &n.UserStatus, &n.MachineKey, &n.NodeKey, &n.DiscoKey, &n.Hostname,
		&n.GivenName, &n.Hostinfo, &v4, &v6, &eps, &n.HomeRelay, &n.Ephemeral, &created, &lastSeen, &expires)
	if err != nil {
		return Node{}, err
	}
	if n.IPv4, err = netip.ParseAddr(v4); err != nil {
		return Node{}, fmt.Errorf("node %d: bad ipv4: %w", n.ID, err)
	}
	if n.IPv6, err = netip.ParseAddr(v6); err != nil {
		return Node{}, fmt.Errorf("node %d: bad ipv6: %w", n.ID, err)
	}
	if err := json.Unmarshal([]byte(eps), &n.Endpoints); err != nil {
		return Node{}, fmt.Errorf("node %d: bad endpoints: %w", n.ID, err)
	}
	n.CreatedAt = fromUnix(created)
	n.LastSeen = fromNullUnix(lastSeen)
	n.ExpiresAt = fromNullUnix(expires)
	return n, nil
}

type querier interface {
	QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row
	QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error)
}

func getNodeTx(ctx context.Context, q querier, id int64) (Node, error) {
	n, err := scanNode(q.QueryRowContext(ctx, nodeSelect+` WHERE n.id = ?`, id))
	if errors.Is(err, sql.ErrNoRows) {
		return Node{}, fmt.Errorf("node %d: %w", id, ErrNotFound)
	}
	return n, err
}

func (d *DB) GetNode(ctx context.Context, id int64) (Node, error) { return getNodeTx(ctx, d.sql, id) }

func (d *DB) GetNodeByNodeKey(ctx context.Context, nodeKey string) (Node, error) {
	n, err := scanNode(d.sql.QueryRowContext(ctx, nodeSelect+` WHERE n.node_key = ?`, nodeKey))
	if errors.Is(err, sql.ErrNoRows) {
		return Node{}, fmt.Errorf("node key: %w", ErrNotFound)
	}
	return n, err
}

// ListNodes returns nodes ordered by ID, optionally for one user (userID 0 = all).
func (d *DB) ListNodes(ctx context.Context, userID int64) ([]Node, error) {
	rows, err := d.sql.QueryContext(ctx, nodeSelect+` WHERE ? = 0 OR n.user_id = ? ORDER BY n.id`, userID, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Node
	for rows.Next() {
		n, err := scanNode(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, n)
	}
	return out, rows.Err()
}

func (d *DB) DeleteNode(ctx context.Context, id int64) error {
	res, err := d.sql.ExecContext(ctx, `DELETE FROM nodes WHERE id = ?`, id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return fmt.Errorf("node %d: %w", id, ErrNotFound)
	}
	return nil
}

// RenameNode sets a node's MagicDNS name. name must already be a valid DNS label.
func (d *DB) RenameNode(ctx context.Context, id int64, name string) error {
	if SanitizeName(name) != name {
		return fmt.Errorf("%w: name %q: use lowercase letters, digits and '-' (max 63)", ErrInvalid, name)
	}
	res, err := d.sql.ExecContext(ctx, `UPDATE nodes SET given_name = ? WHERE id = ?`, name, id)
	if isUniqueViolation(err) {
		return fmt.Errorf("name %q: %w", name, ErrExists)
	}
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return fmt.Errorf("node %d: %w", id, ErrNotFound)
	}
	return nil
}

func usedIPv4s(ctx context.Context, q querier) (map[netip.Addr]bool, error) {
	rows, err := q.QueryContext(ctx, `SELECT ipv4 FROM nodes`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	used := map[netip.Addr]bool{}
	for rows.Next() {
		var s string
		if err := rows.Scan(&s); err != nil {
			return nil, err
		}
		if ip, err := netip.ParseAddr(s); err == nil {
			used[ip] = true
		}
	}
	return used, rows.Err()
}

// uniqueGivenName returns base, or base-2, base-3, ... whichever is free
// among userID's nodes (ignoring node selfID). Names are unique per tenant:
// two tenants can both have a "laptop".
func uniqueGivenName(ctx context.Context, q querier, userID int64, base string, selfID int64) (string, error) {
	for i := 1; ; i++ {
		cand := base
		if i > 1 {
			suffix := "-" + strconv.Itoa(i)
			cand = strings.TrimRight(truncate(base, 63-len(suffix)), "-") + suffix
		}
		var id int64
		err := q.QueryRowContext(ctx, `SELECT id FROM nodes WHERE user_id = ? AND given_name = ?`, userID, cand).Scan(&id)
		if errors.Is(err, sql.ErrNoRows) || (err == nil && id == selfID) {
			return cand, nil
		}
		if err != nil {
			return "", err
		}
	}
}

// SanitizeName turns an arbitrary hostname into a DNS label: lowercase
// a-z, 0-9 and '-', no leading/trailing '-', at most 63 characters.
// Only the first dotted component of the hostname is used.
func SanitizeName(host string) string {
	host, _, _ = strings.Cut(host, ".")
	var b strings.Builder
	dash := false
	for _, r := range strings.ToLower(host) {
		switch {
		case r >= 'a' && r <= 'z' || r >= '0' && r <= '9':
			b.WriteRune(r)
			dash = false
		case !dash && b.Len() > 0:
			b.WriteByte('-')
			dash = true
		}
	}
	s := strings.Trim(truncate(b.String(), 63), "-")
	if s == "" {
		return "node"
	}
	return s
}

func truncate(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}
