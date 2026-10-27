package repository

import (
	"context"
	"fmt"
	"strings"

	"github.com/jmoiron/sqlx"
)

// AccountLabels returns sign-in names for Entra account keys, including keys of
// deleted accounts, so stored keys can be shown as names outside account management.
func (p *PostgresRepository) AccountLabels(ctx context.Context) (map[string]string, error) {
	rows := []struct {
		Username string `db:"username"`
		Label    string `db:"label"`
	}{}
	if err := p.db.SelectContext(ctx, &rows, "SELECT username, label FROM account_labels"); err != nil {
		return nil, fmt.Errorf("listing account labels: %w", err)
	}
	labels := make(map[string]string, len(rows))
	for _, row := range rows {
		labels[row.Username] = row.Label
	}
	return labels, nil
}

// saveAccountLabel records the latest sign-in name for an Entra account key. An
// empty name keeps the last known label rather than exposing the key again.
func saveAccountLabel(ctx context.Context, tx *sqlx.Tx, username, label string) error {
	label = strings.TrimSpace(label)
	if !strings.HasPrefix(username, "entra:") || label == "" {
		return nil
	}
	_, err := tx.ExecContext(ctx, `INSERT INTO account_labels (username, label) VALUES ($1, $2)
		ON CONFLICT (username) DO UPDATE SET label = EXCLUDED.label, updated_at = NOW()`,
		username, label,
	)
	return err
}
