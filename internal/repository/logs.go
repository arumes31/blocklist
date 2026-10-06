package repository

import (
	"context"
	"fmt"
	"strings"

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
	for _, item := range []struct{ column, value string }{
		{column: "actor", value: filter.Actor}, {column: "action", value: filter.Action},
	} {
		if item.value != "" {
			args = append(args, item.value)
			clauses = append(clauses, fmt.Sprintf(" AND %s = $%d", item.column, len(args)))
		}
	}
	if filter.Query != "" {
		args = append(args, "%"+filter.Query+"%")
		clauses = append(clauses, fmt.Sprintf(" AND (target ILIKE $%d OR reason ILIKE $%d)", len(args), len(args)))
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
