package db

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"regexp"
	"time"
)

type User struct {
	ID        int64
	Name      string
	CreatedAt time.Time
}

var userNameRE = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,62}$`)

// ValidUserName reports whether name is an acceptable user name.
func ValidUserName(name string) bool { return userNameRE.MatchString(name) }

func (d *DB) CreateUser(ctx context.Context, name string) (User, error) {
	if !ValidUserName(name) {
		return User{}, fmt.Errorf("%w: user name %q: use lowercase letters, digits, '.', '_' or '-'", ErrInvalid, name)
	}
	now := d.now()
	res, err := d.sql.ExecContext(ctx, `INSERT INTO users(name, created_at) VALUES(?, ?)`, name, unix(now))
	if isUniqueViolation(err) {
		return User{}, fmt.Errorf("user %q: %w", name, ErrExists)
	}
	if err != nil {
		return User{}, err
	}
	id, _ := res.LastInsertId()
	return User{ID: id, Name: name, CreatedAt: fromUnix(unix(now))}, nil
}

func (d *DB) GetUser(ctx context.Context, name string) (User, error) {
	var u User
	var created int64
	err := d.sql.QueryRowContext(ctx, `SELECT id, name, created_at FROM users WHERE name = ?`, name).
		Scan(&u.ID, &u.Name, &created)
	if errors.Is(err, sql.ErrNoRows) {
		return User{}, fmt.Errorf("user %q: %w", name, ErrNotFound)
	}
	u.CreatedAt = fromUnix(created)
	return u, err
}

func (d *DB) ListUsers(ctx context.Context) ([]User, error) {
	rows, err := d.sql.QueryContext(ctx, `SELECT id, name, created_at FROM users ORDER BY name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []User
	for rows.Next() {
		var u User
		var created int64
		if err := rows.Scan(&u.ID, &u.Name, &created); err != nil {
			return nil, err
		}
		u.CreatedAt = fromUnix(created)
		out = append(out, u)
	}
	return out, rows.Err()
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
