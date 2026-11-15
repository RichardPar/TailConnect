package db

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"regexp"
	"time"
)

// Account statuses.
const (
	StatusActive    = "active"
	StatusPending   = "pending"   // signed up, awaiting operator approval
	StatusSuspended = "suspended" // machines are cut off; cannot sign in
)

// Account roles.
const (
	RoleTenant   = "tenant"   // manages its own machines and keys
	RoleOperator = "operator" // manages the whole server
)

// User is a tenant account: one login that owns machines and auth keys.
type User struct {
	ID           int64
	Name         string
	Status       string
	Role         string
	PasswordHash string `json:"-"` // "" = no password set (cannot sign in to the web portal)
	SessionEpoch int64  `json:"-"` // bumped to invalidate web sessions
	CreatedAt    time.Time
}

func (u User) Active() bool      { return u.Status == StatusActive }
func (u User) Operator() bool    { return u.Role == RoleOperator }
func (u User) HasPassword() bool { return u.PasswordHash != "" }

// User names are DNS labels (they become part of machine names), 1-32
// characters, lowercase letters, digits and inner hyphens.
var userNameRE = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,30}[a-z0-9])?$`)

// ValidUserName reports whether name is an acceptable user name.
func ValidUserName(name string) bool { return userNameRE.MatchString(name) }

func invalidName(name string) error {
	return fmt.Errorf("%w: name %q: use 1-32 lowercase letters, digits or '-' (not at the start or end)", ErrInvalid, name)
}

// NewAccount describes an account to create.
type NewAccount struct {
	Name         string
	PasswordHash string // optional
	Status       string // default StatusActive
	Role         string // default RoleTenant
	// Invite, if set, must be a usable invite code; it is consumed.
	Invite string
}

// CreateUser creates an active tenant account without a password (the
// admin CLI's `users create`).
func (d *DB) CreateUser(ctx context.Context, name string) (User, error) {
	return d.CreateAccount(ctx, NewAccount{Name: name})
}

// CreateAccount creates an account, consuming an invite code if one is given.
func (d *DB) CreateAccount(ctx context.Context, a NewAccount) (User, error) {
	if !ValidUserName(a.Name) {
		return User{}, invalidName(a.Name)
	}
	if a.Status == "" {
		a.Status = StatusActive
	}
	if a.Role == "" {
		a.Role = RoleTenant
	}
	if !validStatus(a.Status) || !validRole(a.Role) {
		return User{}, fmt.Errorf("%w: status %q / role %q", ErrInvalid, a.Status, a.Role)
	}
	tx, err := d.sql.BeginTx(ctx, nil)
	if err != nil {
		return User{}, err
	}
	defer tx.Rollback()
	now := d.now()
	res, err := tx.ExecContext(ctx, `INSERT INTO users(name, created_at, password_hash, status, role) VALUES(?, ?, ?, ?, ?)`,
		a.Name, unix(now), a.PasswordHash, a.Status, a.Role)
	if isUniqueViolation(err) {
		return User{}, fmt.Errorf("user %q: %w", a.Name, ErrExists)
	}
	if err != nil {
		return User{}, err
	}
	id, _ := res.LastInsertId()
	if a.Invite != "" {
		if err := consumeInvite(ctx, tx, a.Invite, id, now); err != nil {
			return User{}, err
		}
	}
	if err := tx.Commit(); err != nil {
		return User{}, err
	}
	return User{ID: id, Name: a.Name, Status: a.Status, Role: a.Role, PasswordHash: a.PasswordHash, CreatedAt: fromUnix(unix(now))}, nil
}

func validStatus(s string) bool {
	return s == StatusActive || s == StatusPending || s == StatusSuspended
}
func validRole(r string) bool { return r == RoleTenant || r == RoleOperator }

const userCols = `id, name, status, role, password_hash, session_epoch, created_at`

func scanUser(r rowScanner) (User, error) {
	var u User
	var created int64
	err := r.Scan(&u.ID, &u.Name, &u.Status, &u.Role, &u.PasswordHash, &u.SessionEpoch, &created)
	u.CreatedAt = fromUnix(created)
	return u, err
}

func (d *DB) GetUser(ctx context.Context, name string) (User, error) {
	u, err := scanUser(d.sql.QueryRowContext(ctx, `SELECT `+userCols+` FROM users WHERE name = ?`, name))
	if errors.Is(err, sql.ErrNoRows) {
		return User{}, fmt.Errorf("user %q: %w", name, ErrNotFound)
	}
	return u, err
}

func (d *DB) GetUserByID(ctx context.Context, id int64) (User, error) {
	u, err := scanUser(d.sql.QueryRowContext(ctx, `SELECT `+userCols+` FROM users WHERE id = ?`, id))
	if errors.Is(err, sql.ErrNoRows) {
		return User{}, fmt.Errorf("user %d: %w", id, ErrNotFound)
	}
	return u, err
}

func (d *DB) ListUsers(ctx context.Context) ([]User, error) {
	rows, err := d.sql.QueryContext(ctx, `SELECT `+userCols+` FROM users ORDER BY name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []User
	for rows.Next() {
		u, err := scanUser(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, u)
	}
	return out, rows.Err()
}

// updateUser runs an UPDATE on one user by name and bumps its session
// epoch, so existing web sessions must sign in again.
func (d *DB) updateUser(ctx context.Context, name, set string, args ...any) error {
	args = append(args, name)
	res, err := d.sql.ExecContext(ctx, `UPDATE users SET `+set+`, session_epoch = session_epoch + 1 WHERE name = ?`, args...)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return fmt.Errorf("user %q: %w", name, ErrNotFound)
	}
	return nil
}

// SetPassword stores a new password hash ("" removes the password) and
// signs the user out everywhere.
func (d *DB) SetPassword(ctx context.Context, name, hash string) error {
	return d.updateUser(ctx, name, `password_hash = ?`, hash)
}

// SetUserStatus approves, suspends or reactivates an account.
func (d *DB) SetUserStatus(ctx context.Context, name, status string) error {
	if !validStatus(status) {
		return fmt.Errorf("%w: status %q", ErrInvalid, status)
	}
	return d.updateUser(ctx, name, `status = ?`, status)
}

// SetUserRole makes an account an operator or a tenant.
func (d *DB) SetUserRole(ctx context.Context, name, role string) error {
	if !validRole(role) {
		return fmt.Errorf("%w: role %q", ErrInvalid, role)
	}
	return d.updateUser(ctx, name, `role = ?`, role)
}

// DeleteUser removes a user along with their nodes and auth keys.
func (d *DB) DeleteUser(ctx context.Context, name string) error {
	res, err := d.sql.ExecContext(ctx, `DELETE FROM users WHERE name = ?`, name)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return fmt.Errorf("user %q: %w", name, ErrNotFound)
	}
	return nil
}
