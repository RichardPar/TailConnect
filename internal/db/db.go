// Package db is tc-control's persistent store, backed by SQLite (pure-Go
// driver, so the server cross-compiles without cgo).
package db

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/url"
	"time"

	"modernc.org/sqlite"
	sqlite3 "modernc.org/sqlite/lib"
)

var (
	ErrNotFound       = errors.New("not found")
	ErrExists         = errors.New("already exists")
	ErrInvalidAuthKey = errors.New("invalid, expired or already-used auth key")
	ErrInvalid        = errors.New("invalid argument")
	ErrInvalidInvite  = errors.New("invalid, expired or already-used invite code")
	// ErrAccountInactive: the account is pending approval or suspended, so
	// its machines may not join or stay in the network.
	ErrAccountInactive = errors.New("account is not active (pending approval or suspended)")
)

type DB struct {
	sql *sql.DB
	now func() time.Time
}

// Open opens (creating if needed) the database at path and applies migrations.
func Open(path string) (*DB, error) {
	q := url.Values{}
	q.Add("_pragma", "foreign_keys(1)")
	q.Add("_pragma", "journal_mode(WAL)")
	q.Add("_pragma", "busy_timeout(5000)")
	q.Add("_pragma", "synchronous(NORMAL)")
	q.Set("_txlock", "immediate") // take the write lock at BEGIN, avoiding upgrade deadlocks
	dsn := "file:" + path + "?" + q.Encode()

	s, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, err
	}
	d := &DB{sql: s, now: time.Now}
	if err := d.migrate(context.Background()); err != nil {
		s.Close()
		return nil, fmt.Errorf("migrate %s: %w", path, err)
	}
	return d, nil
}

func (d *DB) Close() error { return d.sql.Close() }

// SetClock overrides the time source (tests).
func (d *DB) SetClock(now func() time.Time) { d.now = now }

// migrations[i] upgrades the schema from user_version i to i+1. Append only.
var migrations = []string{
	`
CREATE TABLE settings (
	key   TEXT PRIMARY KEY,
	value TEXT NOT NULL
);
CREATE TABLE users (
	id         INTEGER PRIMARY KEY,
	name       TEXT NOT NULL UNIQUE,
	created_at INTEGER NOT NULL
);
CREATE TABLE preauth_keys (
	id         INTEGER PRIMARY KEY,
	hash       BLOB NOT NULL UNIQUE,
	prefix     TEXT NOT NULL,
	user_id    INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
	reusable   INTEGER NOT NULL,
	ephemeral  INTEGER NOT NULL,
	uses       INTEGER NOT NULL DEFAULT 0,
	created_at INTEGER NOT NULL,
	expires_at INTEGER NOT NULL,
	revoked    INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE nodes (
	id             INTEGER PRIMARY KEY,
	user_id        INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
	machine_key    TEXT NOT NULL UNIQUE,
	node_key       TEXT NOT NULL UNIQUE,
	disco_key      TEXT NOT NULL DEFAULT '',
	hostname       TEXT NOT NULL,
	given_name     TEXT NOT NULL UNIQUE,
	hostinfo       TEXT NOT NULL DEFAULT '{}',
	ipv4           TEXT NOT NULL UNIQUE,
	ipv6           TEXT NOT NULL UNIQUE,
	endpoints      TEXT NOT NULL DEFAULT '[]',
	ephemeral      INTEGER NOT NULL DEFAULT 0,
	preauth_key_id INTEGER REFERENCES preauth_keys(id) ON DELETE SET NULL,
	created_at     INTEGER NOT NULL,
	last_seen      INTEGER,
	expires_at     INTEGER
);
CREATE INDEX nodes_user ON nodes(user_id);
`,
	// 2: a generation counter bumped by any change that affects network maps,
	// so tc-control notices edits from other processes (e.g. the admin CLI).
	`
CREATE TABLE generation (
	id    INTEGER PRIMARY KEY CHECK (id = 1),
	value INTEGER NOT NULL
);
INSERT INTO generation(id, value) VALUES (1, 0);
CREATE TRIGGER nodes_gen_ins AFTER INSERT ON nodes BEGIN UPDATE generation SET value = value + 1; END;
CREATE TRIGGER nodes_gen_del AFTER DELETE ON nodes BEGIN UPDATE generation SET value = value + 1; END;
CREATE TRIGGER nodes_gen_upd AFTER UPDATE ON nodes
	WHEN OLD.node_key IS NOT NEW.node_key OR OLD.disco_key IS NOT NEW.disco_key
	  OR OLD.given_name IS NOT NEW.given_name OR OLD.endpoints IS NOT NEW.endpoints
	  OR OLD.hostinfo IS NOT NEW.hostinfo OR OLD.user_id IS NOT NEW.user_id
	  OR OLD.ipv4 IS NOT NEW.ipv4 OR OLD.ipv6 IS NOT NEW.ipv6 OR OLD.expires_at IS NOT NEW.expires_at
	BEGIN UPDATE generation SET value = value + 1; END;
CREATE TRIGGER users_gen_del AFTER DELETE ON users BEGIN UPDATE generation SET value = value + 1; END;
`,
	// 3: the relay region each node is reachable through.
	`
ALTER TABLE nodes ADD COLUMN home_relay INTEGER NOT NULL DEFAULT 0;
CREATE TRIGGER nodes_gen_relay AFTER UPDATE OF home_relay ON nodes
	WHEN OLD.home_relay IS NOT NEW.home_relay
	BEGIN UPDATE generation SET value = value + 1; END;
`,
	// 4: accounts. Each user is a tenant login with an optional password, a
	// status (pending approval, active, suspended) and a role. session_epoch
	// is bumped to invalidate web sessions (password change, suspension).
	// Invites are operator-issued codes for invite-only sign-up.
	`
ALTER TABLE users ADD COLUMN password_hash TEXT NOT NULL DEFAULT '';
ALTER TABLE users ADD COLUMN status TEXT NOT NULL DEFAULT 'active';
ALTER TABLE users ADD COLUMN role TEXT NOT NULL DEFAULT 'tenant';
ALTER TABLE users ADD COLUMN session_epoch INTEGER NOT NULL DEFAULT 0;
CREATE TRIGGER users_gen_status AFTER UPDATE OF status ON users
	WHEN OLD.status IS NOT NEW.status
	BEGIN UPDATE generation SET value = value + 1; END;
CREATE TABLE invites (
	id         INTEGER PRIMARY KEY,
	hash       BLOB NOT NULL UNIQUE,
	prefix     TEXT NOT NULL,
	created_at INTEGER NOT NULL,
	expires_at INTEGER NOT NULL,
	used_by    INTEGER REFERENCES users(id) ON DELETE SET NULL,
	used_at    INTEGER,
	revoked    INTEGER NOT NULL DEFAULT 0
);
`,
	// 5: machine names are unique per tenant (they live under
	// <tenant>.<domain>), not server-wide. SQLite can't drop a column's
	// UNIQUE constraint, so the table is rebuilt (with its triggers).
	`
CREATE TABLE nodes_new (
	id             INTEGER PRIMARY KEY,
	user_id        INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
	machine_key    TEXT NOT NULL UNIQUE,
	node_key       TEXT NOT NULL UNIQUE,
	disco_key      TEXT NOT NULL DEFAULT '',
	hostname       TEXT NOT NULL,
	given_name     TEXT NOT NULL,
	hostinfo       TEXT NOT NULL DEFAULT '{}',
	ipv4           TEXT NOT NULL UNIQUE,
	ipv6           TEXT NOT NULL UNIQUE,
	endpoints      TEXT NOT NULL DEFAULT '[]',
	ephemeral      INTEGER NOT NULL DEFAULT 0,
	preauth_key_id INTEGER REFERENCES preauth_keys(id) ON DELETE SET NULL,
	created_at     INTEGER NOT NULL,
	last_seen      INTEGER,
	expires_at     INTEGER,
	home_relay     INTEGER NOT NULL DEFAULT 0
);
INSERT INTO nodes_new(id, user_id, machine_key, node_key, disco_key, hostname, given_name, hostinfo, ipv4, ipv6,
                      endpoints, ephemeral, preauth_key_id, created_at, last_seen, expires_at, home_relay)
	SELECT id, user_id, machine_key, node_key, disco_key, hostname, given_name, hostinfo, ipv4, ipv6,
	       endpoints, ephemeral, preauth_key_id, created_at, last_seen, expires_at, home_relay FROM nodes;
DROP TABLE nodes;
ALTER TABLE nodes_new RENAME TO nodes;
CREATE INDEX nodes_user ON nodes(user_id);
CREATE UNIQUE INDEX nodes_user_name ON nodes(user_id, given_name);
CREATE TRIGGER nodes_gen_ins AFTER INSERT ON nodes BEGIN UPDATE generation SET value = value + 1; END;
CREATE TRIGGER nodes_gen_del AFTER DELETE ON nodes BEGIN UPDATE generation SET value = value + 1; END;
CREATE TRIGGER nodes_gen_upd AFTER UPDATE ON nodes
	WHEN OLD.node_key IS NOT NEW.node_key OR OLD.disco_key IS NOT NEW.disco_key
	  OR OLD.given_name IS NOT NEW.given_name OR OLD.endpoints IS NOT NEW.endpoints
	  OR OLD.hostinfo IS NOT NEW.hostinfo OR OLD.user_id IS NOT NEW.user_id
	  OR OLD.ipv4 IS NOT NEW.ipv4 OR OLD.ipv6 IS NOT NEW.ipv6 OR OLD.expires_at IS NOT NEW.expires_at
	BEGIN UPDATE generation SET value = value + 1; END;
CREATE TRIGGER nodes_gen_relay AFTER UPDATE OF home_relay ON nodes
	WHEN OLD.home_relay IS NOT NEW.home_relay
	BEGIN UPDATE generation SET value = value + 1; END;
`,
	// 6: sharing a machine with another tenant. A share names its recipient
	// (pending until accepted), or is an unclaimed link (recipient NULL,
	// invite_hash set) that the first account to redeem it accepts. Shares
	// end when the machine is deleted or moves to another tenant.
	`
CREATE TABLE shares (
	id            INTEGER PRIMARY KEY,
	node_id       INTEGER NOT NULL REFERENCES nodes(id) ON DELETE CASCADE,
	recipient_id  INTEGER REFERENCES users(id) ON DELETE CASCADE,
	status        TEXT NOT NULL,
	invite_hash   BLOB UNIQUE,
	invite_prefix TEXT NOT NULL DEFAULT '',
	created_at    INTEGER NOT NULL,
	accepted_at   INTEGER,
	expires_at    INTEGER
);
CREATE UNIQUE INDEX shares_node_recipient ON shares(node_id, recipient_id) WHERE recipient_id IS NOT NULL;
CREATE INDEX shares_recipient ON shares(recipient_id);
CREATE TRIGGER shares_gen_ins AFTER INSERT ON shares BEGIN UPDATE generation SET value = value + 1; END;
CREATE TRIGGER shares_gen_del AFTER DELETE ON shares BEGIN UPDATE generation SET value = value + 1; END;
CREATE TRIGGER shares_gen_upd AFTER UPDATE ON shares BEGIN UPDATE generation SET value = value + 1; END;
CREATE TRIGGER nodes_move_unshare AFTER UPDATE OF user_id ON nodes
	WHEN OLD.user_id IS NOT NEW.user_id
	BEGIN DELETE FROM shares WHERE node_id = NEW.id; END;
`,
	// 7: machine lifecycle. Accounts can require approval for new machines
	// (pre-approved auth keys skip it); machines record whether they're
	// approved. Approval changes affect maps, so the trigger is rebuilt.
	`
ALTER TABLE users ADD COLUMN require_machine_approval INTEGER NOT NULL DEFAULT 0;
ALTER TABLE preauth_keys ADD COLUMN preapproved INTEGER NOT NULL DEFAULT 0;
ALTER TABLE nodes ADD COLUMN approved INTEGER NOT NULL DEFAULT 1;
DROP TRIGGER nodes_gen_upd;
CREATE TRIGGER nodes_gen_upd AFTER UPDATE ON nodes
	WHEN OLD.node_key IS NOT NEW.node_key OR OLD.disco_key IS NOT NEW.disco_key
	  OR OLD.given_name IS NOT NEW.given_name OR OLD.endpoints IS NOT NEW.endpoints
	  OR OLD.hostinfo IS NOT NEW.hostinfo OR OLD.user_id IS NOT NEW.user_id
	  OR OLD.ipv4 IS NOT NEW.ipv4 OR OLD.ipv6 IS NOT NEW.ipv6 OR OLD.expires_at IS NOT NEW.expires_at
	  OR OLD.approved IS NOT NEW.approved
	BEGIN UPDATE generation SET value = value + 1; END;
`,
	// 8: access rules within an account: machine tags and per-account
	// rules ("from → to on ports"). Both affect maps.
	`
ALTER TABLE nodes ADD COLUMN tags TEXT NOT NULL DEFAULT '[]';
CREATE TRIGGER nodes_gen_tags AFTER UPDATE OF tags ON nodes
	WHEN OLD.tags IS NOT NEW.tags
	BEGIN UPDATE generation SET value = value + 1; END;
CREATE TABLE acl_rules (
	id         INTEGER PRIMARY KEY,
	user_id    INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
	src        TEXT NOT NULL,
	dst        TEXT NOT NULL,
	ports      TEXT NOT NULL,
	created_at INTEGER NOT NULL
);
CREATE INDEX acl_rules_user ON acl_rules(user_id);
CREATE TRIGGER acl_gen_ins AFTER INSERT ON acl_rules BEGIN UPDATE generation SET value = value + 1; END;
CREATE TRIGGER acl_gen_del AFTER DELETE ON acl_rules BEGIN UPDATE generation SET value = value + 1; END;
CREATE TRIGGER acl_gen_upd AFTER UPDATE ON acl_rules BEGIN UPDATE generation SET value = value + 1; END;
`,
	// 9: credentials of standalone relays (tc-relay), which ask the control
	// server which machines they may serve.
	`
CREATE TABLE relay_tokens (
	id         INTEGER PRIMARY KEY,
	name       TEXT NOT NULL UNIQUE,
	hash       BLOB NOT NULL UNIQUE,
	created_at INTEGER NOT NULL,
	last_used  INTEGER NOT NULL DEFAULT 0
);
`,
	// 10: exit nodes. A machine its owner allows to carry the account's
	// internet traffic. Off for every machine until turned on; affects maps.
	`
ALTER TABLE nodes ADD COLUMN exit_node INTEGER NOT NULL DEFAULT 0;
CREATE TRIGGER nodes_gen_exit AFTER UPDATE OF exit_node ON nodes
	WHEN OLD.exit_node IS NOT NEW.exit_node
	BEGIN UPDATE generation SET value = value + 1; END;
`,
	// 11: per-account MagicDNS domains. '' = the default <account>.<base>.
	// Changing one renames every machine in the account, so it affects maps.
	`
ALTER TABLE users ADD COLUMN dns_domain TEXT NOT NULL DEFAULT '';
CREATE UNIQUE INDEX users_dns_domain ON users(dns_domain) WHERE dns_domain != '';
CREATE TRIGGER users_gen_dns AFTER UPDATE OF dns_domain ON users
	WHEN OLD.dns_domain IS NOT NEW.dns_domain
	BEGIN UPDATE generation SET value = value + 1; END;
`,
}

// Generation returns a counter that increases whenever nodes or users change
// in a way that affects network maps.
func (d *DB) Generation(ctx context.Context) (int64, error) {
	var g int64
	err := d.sql.QueryRowContext(ctx, `SELECT value FROM generation WHERE id = 1`).Scan(&g)
	return g, err
}

func (d *DB) migrate(ctx context.Context) error {
	var v int
	if err := d.sql.QueryRowContext(ctx, `PRAGMA user_version`).Scan(&v); err != nil {
		return err
	}
	if v > len(migrations) {
		return fmt.Errorf("database schema version %d is newer than this binary supports (%d)", v, len(migrations))
	}
	for ; v < len(migrations); v++ {
		tx, err := d.sql.BeginTx(ctx, nil)
		if err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, migrations[v]); err != nil {
			tx.Rollback()
			return fmt.Errorf("migration %d: %w", v+1, err)
		}
		if _, err := tx.ExecContext(ctx, fmt.Sprintf(`PRAGMA user_version = %d`, v+1)); err != nil {
			tx.Rollback()
			return err
		}
		if err := tx.Commit(); err != nil {
			return err
		}
	}
	return nil
}

// GetSetting returns the value for key, or ErrNotFound.
func (d *DB) GetSetting(ctx context.Context, key string) (string, error) {
	var v string
	err := d.sql.QueryRowContext(ctx, `SELECT value FROM settings WHERE key = ?`, key).Scan(&v)
	if errors.Is(err, sql.ErrNoRows) {
		return "", ErrNotFound
	}
	return v, err
}

func (d *DB) SetSetting(ctx context.Context, key, value string) error {
	_, err := d.sql.ExecContext(ctx,
		`INSERT INTO settings(key, value) VALUES(?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value`,
		key, value)
	return err
}

// SetSettingIfAbsent stores value only if key is unset, and returns whichever
// value is stored afterwards. Safe against concurrent first-time initialisation.
func (d *DB) SetSettingIfAbsent(ctx context.Context, key, value string) (string, error) {
	if _, err := d.sql.ExecContext(ctx,
		`INSERT INTO settings(key, value) VALUES(?, ?) ON CONFLICT(key) DO NOTHING`, key, value); err != nil {
		return "", err
	}
	return d.GetSetting(ctx, key)
}

func unix(t time.Time) int64 { return t.Unix() }

func fromUnix(v int64) time.Time { return time.Unix(v, 0).UTC() }

func fromNullUnix(v sql.NullInt64) time.Time {
	if !v.Valid {
		return time.Time{}
	}
	return fromUnix(v.Int64)
}

func nullUnix(t time.Time) sql.NullInt64 {
	if t.IsZero() {
		return sql.NullInt64{}
	}
	return sql.NullInt64{Int64: t.Unix(), Valid: true}
}

func isUniqueViolation(err error) bool {
	var se *sqlite.Error
	if !errors.As(err, &se) {
		return false
	}
	return se.Code() == sqlite3.SQLITE_CONSTRAINT_UNIQUE || se.Code() == sqlite3.SQLITE_CONSTRAINT_PRIMARYKEY
}

// SQLForTest exposes the database handle to other packages' tests, for
// setting up states the API doesn't offer directly. Not for production use.
func (d *DB) SQLForTest() *sql.DB { return d.sql }
