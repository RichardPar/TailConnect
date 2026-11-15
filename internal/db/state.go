package db

import (
	"context"
	"database/sql"
)

// queryer is a *sql.DB or a *sql.Tx.
type queryer interface {
	QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error)
	QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row
}

// State is everything network maps are built from, read at one instant.
type State struct {
	Generation int64
	Nodes      []Node
	Shares     []Share // accepted shares only
	Rules      []Rule
}

// ReadState reads the generation, nodes, accepted shares and access rules
// in one read transaction, so they are consistent with each other: separate
// reads could see a rule but not the tags it refers to, and briefly cut
// machines off from each other.
func (d *DB) ReadState(ctx context.Context) (State, error) {
	tx, err := d.sql.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return State{}, err
	}
	defer tx.Rollback()
	var st State
	if err := tx.QueryRowContext(ctx, `SELECT value FROM generation WHERE id = 1`).Scan(&st.Generation); err != nil {
		return State{}, err
	}
	if st.Nodes, err = listNodes(ctx, tx, 0); err != nil {
		return State{}, err
	}
	if st.Shares, err = listShares(ctx, tx, ShareFilter{Accepted: true}); err != nil {
		return State{}, err
	}
	if st.Rules, err = listRules(ctx, tx, 0); err != nil {
		return State{}, err
	}
	return st, tx.Commit()
}
