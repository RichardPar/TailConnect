package db

import (
	"context"
	"fmt"
	"time"
)

// Rule is an access rule of one account (see package acl for semantics).
type Rule struct {
	ID        int64
	UserID    int64
	UserName  string
	Src       string
	Dst       string
	Ports     string
	CreatedAt time.Time
}

// ListRules lists access rules, of one account or all (userID 0).
func (d *DB) ListRules(ctx context.Context, userID int64) ([]Rule, error) {
	return listRules(ctx, d.sql, userID)
}

func listRules(ctx context.Context, q queryer, userID int64) ([]Rule, error) {
	rows, err := q.QueryContext(ctx, `
		SELECT r.id, r.user_id, u.name, r.src, r.dst, r.ports, r.created_at
		FROM acl_rules r JOIN users u ON u.id = r.user_id
		WHERE ? = 0 OR r.user_id = ? ORDER BY r.id`, userID, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Rule
	for rows.Next() {
		var r Rule
		var created int64
		if err := rows.Scan(&r.ID, &r.UserID, &r.UserName, &r.Src, &r.Dst, &r.Ports, &created); err != nil {
			return nil, err
		}
		r.CreatedAt = fromUnix(created)
		out = append(out, r)
	}
	return out, rows.Err()
}

// AddRule adds an access rule to an account (validated by the caller).
func (d *DB) AddRule(ctx context.Context, userID int64, src, dst, ports string) (Rule, error) {
	now := d.now()
	res, err := d.sql.ExecContext(ctx, `INSERT INTO acl_rules(user_id, src, dst, ports, created_at) VALUES(?, ?, ?, ?, ?)`,
		userID, src, dst, ports, unix(now))
	if err != nil {
		return Rule{}, err
	}
	id, _ := res.LastInsertId()
	return Rule{ID: id, UserID: userID, Src: src, Dst: dst, Ports: ports, CreatedAt: fromUnix(unix(now))}, nil
}

// DeleteRule removes rule id if it belongs to userID (0 = any account).
func (d *DB) DeleteRule(ctx context.Context, id, userID int64) error {
	res, err := d.sql.ExecContext(ctx, `DELETE FROM acl_rules WHERE id = ? AND (? = 0 OR user_id = ?)`, id, userID, userID)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return fmt.Errorf("rule %d: %w", id, ErrNotFound)
	}
	return nil
}
