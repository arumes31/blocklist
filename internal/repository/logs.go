package repository

import (
	"context"
	"fmt"
	"strings"
	"time"

	"blocklist/internal/models"
)

func (p *PostgresRepository) ListLogs(ctx context.Context, filter models.LogFilter) ([]models.AuditLog, int, error) {
	logs := []models.AuditLog{}
	args := []any{models.EventActions}
	where := " WHERE COALESCE(action = ANY($1::text[]), FALSE)"
	if filter.Category == "system" {
		where = " WHERE NOT COALESCE(action = ANY($1::text[]), FALSE)"
	} else if filter.Category != "events" {
		return nil, 0, fmt.Errorf("invalid log category")
	}
	clauses := []string{where}
	cutoff, err := p.logRetention.Cutoff(filter.Category, time.Now())
	if err != nil {
		return nil, 0, fmt.Errorf("resolving log retention: %w", err)
	}
	args = append(args, cutoff)
	clauses = append(clauses, " AND timestamp >= $2")
	// Entra accounts are shown by sign-in name, so filters accept that name as
	// well as the stored account key.
	if filter.Actor != "" {
		args = append(args, filter.Actor)
		clauses = append(clauses, fmt.Sprintf(
			" AND (actor = $%d OR actor IN (SELECT username FROM account_labels WHERE lower(label) = lower($%d)))",
			len(args), len(args),
		))
	}
	if filter.Action != "" {
		args = append(args, filter.Action)
		clauses = append(clauses, fmt.Sprintf(" AND action = $%d", len(args)))
	}
	if filter.Query != "" {
		args = append(args, "%"+filter.Query+"%")
		clauses = append(clauses, fmt.Sprintf(
			" AND (target ILIKE $%d OR reason ILIKE $%d OR target IN (SELECT username FROM account_labels WHERE label ILIKE $%d))",
			len(args), len(args), len(args),
		))
	}
	where = strings.Join(clauses, "")
	var total int
	if err := p.db.GetContext(ctx, &total, "SELECT count(*) FROM audit_logs"+where, args...); err != nil {
		return nil, 0, fmt.Errorf("counting logs: %w", err)
	}
	args = append(args, filter.Limit, filter.Offset)
	query := "SELECT id, timestamp, actor, action, target, reason FROM audit_logs" + where +
		fmt.Sprintf(" ORDER BY timestamp DESC, id DESC LIMIT $%d OFFSET $%d", len(args)-1, len(args))
	if err := p.db.SelectContext(ctx, &logs, query, args...); err != nil {
		return nil, 0, fmt.Errorf("listing logs: %w", err)
	}
	return logs, total, nil
}
