package db

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"slices"
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
	UserDomain string // the owning account's own MagicDNS domain ("" = default)
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
	Approved   bool     // false: the account requires approval and nobody has given it yet
	Tags       []string // access-rule tags
	Aliases    []string // extra MagicDNS labels that resolve to this machine
	ExitNode   bool     // may carry its account's internet traffic (off by default)
	CreatedAt  time.Time
	LastSeen   time.Time // zero = never
	ExpiresAt  time.Time // key expiry; zero = never
}

// Expired reports whether the machine's key has expired at time now.
func (n Node) Expired(now time.Time) bool { return !n.ExpiresAt.IsZero() && !now.Before(n.ExpiresAt) }

// Usable reports whether the machine may be part of the network at time
// now: its account is active, it's approved and its key hasn't expired.
func (n Node) Usable(now time.Time) bool {
	return n.UserStatus == StatusActive && n.Approved && !n.Expired(now)
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
	// KeyExpiry is how long a new or re-authenticated machine stays
	// authorised (0 = never). Re-authenticating renews it, except for
	// machines set to never expire.
	KeyExpiry time.Duration
}

type RegisterResult struct {
	Node    Node
	Created bool // a new node row was inserted
	Rotated bool // an existing machine got a new node key
}

// applyAuthKey consumes key (if any) and moves node id to the key's user.
// It renews the machine's key expiry (unless it's set to never expire) and
// works out approval: kept within the same account (a pre-approved key
// approves), recomputed when moving to another account.
func applyAuthKey(ctx context.Context, tx *sql.Tx, id int64, key string, now time.Time, keyExpiry time.Duration) error {
	if key == "" {
		return nil
	}
	k, err := consumePreAuthKey(ctx, tx, key, now)
	if err != nil {
		return err
	}
	var curUser int64
	var curApproved bool
	var curExpires sql.NullInt64
	if err := tx.QueryRowContext(ctx, `SELECT user_id, approved, expires_at FROM nodes WHERE id = ?`, id).
		Scan(&curUser, &curApproved, &curExpires); err != nil {
		return err
	}
	approved := curApproved || k.Preapproved
	if curUser != k.UserID {
		if approved, err = approvedOnJoin(ctx, tx, k); err != nil {
			return err
		}
	}
	expires := curExpires // NULL = never expires: kept within the account
	if curExpires.Valid || curUser != k.UserID {
		expires = expiryAt(now, keyExpiry) // a new account's policy applies
	}
	if _, err := tx.ExecContext(ctx, `UPDATE nodes SET approved = ?, expires_at = ? WHERE id = ?`, approved, expires, id); err != nil {
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
	// What an account granted its machine stays with that account: moving
	// drops aliases (its namespace), tags (its access rules) and the exit
	// node role, so a machine can't arrive in another account already
	// tagged into its rules or offering to carry its traffic.
	moved := ""
	if curUser != k.UserID {
		moved = ", aliases = '[]', tags = '[]', exit_node = 0"
	}
	_, err = tx.ExecContext(ctx, `UPDATE nodes SET user_id = ?, given_name = ?, ephemeral = ?, preauth_key_id = ?`+moved+` WHERE id = ?`,
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
	if err == nil || errors.Is(err, sql.ErrNoRows) {
		if terr := discoKeyTaken(ctx, tx, p.DiscoKey, existing.ID); terr != nil {
			return RegisterResult{}, terr
		}
	}
	switch {
	case err == nil && existing.NodeKey == p.NodeKey:
		if _, err := tx.ExecContext(ctx,
			`UPDATE nodes SET disco_key = ?, hostname = ?, hostinfo = ?, last_seen = ? WHERE id = ?`,
			p.DiscoKey, p.Hostname, p.Hostinfo, unix(now), existing.ID); err != nil {
			return RegisterResult{}, err
		}
		if err := applyAuthKey(ctx, tx, existing.ID, p.AuthKey, now, p.KeyExpiry); err != nil {
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
		if err := applyAuthKey(ctx, tx, existing.ID, p.AuthKey, now, p.KeyExpiry); err != nil {
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
	approved, err := approvedOnJoin(ctx, tx, k)
	if err != nil {
		return RegisterResult{}, err
	}
	res, err := tx.ExecContext(ctx, `
		INSERT INTO nodes(user_id, machine_key, node_key, disco_key, hostname, given_name, hostinfo,
		                  ipv4, ipv6, ephemeral, preauth_key_id, created_at, last_seen, approved, expires_at)
		VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		k.UserID, p.MachineKey, p.NodeKey, p.DiscoKey, p.Hostname, name, p.Hostinfo,
		v4.String(), v6.String(), k.Ephemeral, k.ID, unix(now), unix(now), approved, expiryAt(now, p.KeyExpiry))
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
	// The disco key check is part of the update, so two machines can't
	// claim one key at the same moment.
	res, err := d.sql.ExecContext(ctx, `
		UPDATE nodes SET disco_key = ?, endpoints = ?, home_relay = ?, last_seen = ?,
		       hostinfo = CASE WHEN ? = '' THEN hostinfo ELSE ? END
		WHERE id = ? AND (? = '' OR NOT EXISTS (SELECT 1 FROM nodes WHERE disco_key = ? AND id != ?))`,
		discoKey, string(eps), st.HomeRelay, unix(d.now()), hostinfo, hostinfo, id, discoKey, discoKey, id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		if err := discoKeyTaken(ctx, d.sql, discoKey, id); err != nil {
			return err
		}
		return fmt.Errorf("node %d: %w", id, ErrNotFound)
	}
	return nil
}

// discoKeyTaken returns ErrDiscoKeyTaken if a machine other than selfID
// (0: none) has disco key k ("" is never taken).
func discoKeyTaken(ctx context.Context, q querier, k string, selfID int64) error {
	if k == "" {
		return nil
	}
	var id int64
	err := q.QueryRowContext(ctx, `SELECT id FROM nodes WHERE disco_key = ? AND id != ? LIMIT 1`, k, selfID).Scan(&id)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		return nil
	case err != nil:
		return err
	}
	return ErrDiscoKeyTaken
}

// TouchNode records that the node is alive without changing anything else.
func (d *DB) TouchNode(ctx context.Context, id int64) error {
	_, err := d.sql.ExecContext(ctx, `UPDATE nodes SET last_seen = ? WHERE id = ?`, unix(d.now()), id)
	return err
}

const nodeSelect = `
	SELECT n.id, n.user_id, u.name, u.status, u.dns_domain, n.machine_key, n.node_key, n.disco_key, n.hostname, n.given_name,
	       n.hostinfo, n.ipv4, n.ipv6, n.endpoints, n.home_relay, n.ephemeral, n.approved, n.tags, n.aliases, n.exit_node, n.created_at, n.last_seen, n.expires_at
	FROM nodes n JOIN users u ON u.id = n.user_id`

func scanNode(r rowScanner) (Node, error) {
	var n Node
	var v4, v6, eps, tags, aliases string
	var created int64
	var lastSeen, expires sql.NullInt64
	err := r.Scan(&n.ID, &n.UserID, &n.UserName, &n.UserStatus, &n.UserDomain, &n.MachineKey, &n.NodeKey, &n.DiscoKey, &n.Hostname,
		&n.GivenName, &n.Hostinfo, &v4, &v6, &eps, &n.HomeRelay, &n.Ephemeral, &n.Approved, &tags, &aliases, &n.ExitNode, &created, &lastSeen, &expires)
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
	if err := json.Unmarshal([]byte(tags), &n.Tags); err != nil {
		return Node{}, fmt.Errorf("node %d: bad tags: %w", n.ID, err)
	}
	if err := json.Unmarshal([]byte(aliases), &n.Aliases); err != nil {
		return Node{}, fmt.Errorf("node %d: bad aliases: %w", n.ID, err)
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
	return listNodes(ctx, d.sql, userID)
}

func listNodes(ctx context.Context, q queryer, userID int64) ([]Node, error) {
	rows, err := q.QueryContext(ctx, nodeSelect+` WHERE ? = 0 OR n.user_id = ? ORDER BY n.id`, userID, userID)
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

// RenameNode sets a node's MagicDNS name. name must already be a valid DNS
// label, not used by another machine in the account as a name or alias. If
// it is one of the machine's own aliases, that alias is dropped.
func (d *DB) RenameNode(ctx context.Context, id int64, name string) error {
	if SanitizeName(name) != name {
		return fmt.Errorf("%w: name %q: use lowercase letters, digits and '-' (max 63)", ErrInvalid, name)
	}
	tx, err := d.sql.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	n, err := getNodeTx(ctx, tx, id)
	if err != nil {
		return err
	}
	taken, err := takenNames(ctx, tx, n.UserID, id)
	if err != nil {
		return err
	}
	if taken[name] {
		return fmt.Errorf("name %q: %w", name, ErrExists)
	}
	aliases := slices.DeleteFunc(slices.Clone(n.Aliases), func(a string) bool { return a == name })
	if aliases == nil {
		aliases = []string{}
	}
	b, _ := json.Marshal(aliases)
	_, err = tx.ExecContext(ctx, `UPDATE nodes SET given_name = ?, aliases = ? WHERE id = ?`, name, string(b), id)
	if isUniqueViolation(err) {
		return fmt.Errorf("name %q: %w", name, ErrExists)
	}
	if err != nil {
		return err
	}
	return tx.Commit()
}

// SetNodeAliases replaces a machine's aliases: extra MagicDNS labels that
// resolve to it. Each must be a valid DNS label, not the machine's own name,
// and not a name or alias of another machine in the account. Duplicates are
// dropped and the list is sorted.
func (d *DB) SetNodeAliases(ctx context.Context, id int64, aliases []string) ([]string, error) {
	out := []string{}
	for _, a := range aliases {
		a = strings.ToLower(strings.TrimSpace(a))
		if a == "" {
			continue
		}
		if SanitizeName(a) != a {
			return nil, fmt.Errorf("%w: alias %q: use lowercase letters, digits and '-' (max 63)", ErrInvalid, a)
		}
		out = append(out, a)
	}
	slices.Sort(out)
	out = slices.Compact(out)
	if len(out) > MaxAliases {
		return nil, fmt.Errorf("%w: at most %d aliases per machine", ErrInvalid, MaxAliases)
	}
	tx, err := d.sql.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	n, err := getNodeTx(ctx, tx, id)
	if err != nil {
		return nil, err
	}
	taken, err := takenNames(ctx, tx, n.UserID, id)
	if err != nil {
		return nil, err
	}
	for _, a := range out {
		if a == n.GivenName {
			return nil, fmt.Errorf("%w: alias %q is the machine's own name", ErrInvalid, a)
		}
		if taken[a] {
			return nil, fmt.Errorf("alias %q is already used by another machine: %w", a, ErrExists)
		}
	}
	b, _ := json.Marshal(out)
	if _, err := tx.ExecContext(ctx, `UPDATE nodes SET aliases = ? WHERE id = ?`, string(b), id); err != nil {
		return nil, err
	}
	return out, tx.Commit()
}

// MaxAliases bounds a machine's aliases.
const MaxAliases = 16

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
	// One query for the account's names, then pick in memory: probing
	// candidates one query at a time made a fleet of N same-named machines
	// cost O(N²) queries to join.
	taken, err := takenNames(ctx, q, userID, selfID)
	if err != nil {
		return "", err
	}
	for i := 1; ; i++ {
		cand := base
		if i > 1 {
			suffix := "-" + strconv.Itoa(i)
			cand = strings.TrimRight(truncate(base, 63-len(suffix)), "-") + suffix
		}
		if !taken[cand] {
			return cand, nil
		}
	}
}

// takenNames returns the names and aliases of userID's nodes other than
// selfID: the labels a name or alias of selfID may not use.
func takenNames(ctx context.Context, q querier, userID, selfID int64) (map[string]bool, error) {
	rows, err := q.QueryContext(ctx, `SELECT given_name, aliases FROM nodes WHERE user_id = ? AND id != ?`, userID, selfID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	taken := map[string]bool{}
	for rows.Next() {
		var n, al string
		if err := rows.Scan(&n, &al); err != nil {
			return nil, err
		}
		taken[n] = true
		var as []string
		_ = json.Unmarshal([]byte(al), &as)
		for _, a := range as {
			taken[a] = true
		}
	}
	return taken, rows.Err()
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

// approvedOnJoin reports whether a machine joining with key k starts out
// approved: unless its account requires approval and k isn't pre-approved.
func approvedOnJoin(ctx context.Context, tx *sql.Tx, k PreAuthKey) (bool, error) {
	var require bool
	if err := tx.QueryRowContext(ctx, `SELECT require_machine_approval FROM users WHERE id = ?`, k.UserID).Scan(&require); err != nil {
		return false, err
	}
	return !require || k.Preapproved, nil
}

// expiryAt is the key expiry for a machine authorised at now (NULL = never).
func expiryAt(now time.Time, d time.Duration) sql.NullInt64 {
	if d <= 0 {
		return sql.NullInt64{}
	}
	return sql.NullInt64{Int64: unix(now.Add(d)), Valid: true}
}

// ApproveNode approves a machine waiting for approval.
func (d *DB) ApproveNode(ctx context.Context, id int64) error {
	res, err := d.sql.ExecContext(ctx, `UPDATE nodes SET approved = 1 WHERE id = ?`, id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return fmt.Errorf("node %d: %w", id, ErrNotFound)
	}
	return nil
}

// SetNodeExpiry sets when a machine's key expires (zero = never).
func (d *DB) SetNodeExpiry(ctx context.Context, id int64, at time.Time) error {
	var v sql.NullInt64
	if !at.IsZero() {
		v = sql.NullInt64{Int64: unix(at), Valid: true}
	}
	res, err := d.sql.ExecContext(ctx, `UPDATE nodes SET expires_at = ? WHERE id = ?`, v, id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return fmt.Errorf("node %d: %w", id, ErrNotFound)
	}
	return nil
}

// StaleEphemeralNodes lists ephemeral machines not seen since before.
func (d *DB) StaleEphemeralNodes(ctx context.Context, before time.Time) ([]Node, error) {
	rows, err := d.sql.QueryContext(ctx, nodeSelect+` WHERE n.ephemeral = 1 AND COALESCE(n.last_seen, n.created_at) < ? ORDER BY n.id`, unix(before))
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

// SetNodeTags replaces a machine's access-rule tags (validated by the caller).
func (d *DB) SetNodeTags(ctx context.Context, id int64, tags []string) error {
	if tags == nil {
		tags = []string{}
	}
	b, _ := json.Marshal(tags)
	res, err := d.sql.ExecContext(ctx, `UPDATE nodes SET tags = ? WHERE id = ?`, string(b), id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return fmt.Errorf("node %d: %w", id, ErrNotFound)
	}
	return nil
}

// SetNodeExitNode turns a machine's exit node role on or off.
func (d *DB) SetNodeExitNode(ctx context.Context, id int64, on bool) error {
	res, err := d.sql.ExecContext(ctx, `UPDATE nodes SET exit_node = ? WHERE id = ?`, on, id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return fmt.Errorf("node %d: %w", id, ErrNotFound)
	}
	return nil
}

// CanBeExitNode reports why machine n can't be an exit node, if it can't:
// forwarding and NAT are only implemented in the Linux client.
func CanBeExitNode(n Node) error {
	var hi struct{ OS string }
	_ = json.Unmarshal([]byte(n.Hostinfo), &hi)
	if hi.OS != "linux" {
		os := hi.OS
		if os == "" {
			os = "unknown"
		}
		return fmt.Errorf("%w: %s runs %s; only Linux machines can be exit nodes", ErrInvalid, n.GivenName, os)
	}
	return nil
}
