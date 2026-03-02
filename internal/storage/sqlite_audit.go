package storage

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"time"
)

// ============================================================
// Audit Log Operations
// ============================================================

// CreateAuditLog creates a new audit log entry.
func (s *SQLiteStore) CreateAuditLog(ctx context.Context, log *AuditLog) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if log.ID == "" {
		log.ID = generateID()
	}
	if log.Timestamp.IsZero() {
		log.Timestamp = time.Now()
	}
	log.CreatedAt = time.Now()

	detailsJSON, _ := json.Marshal(log.Details)

	_, err := s.db.ExecContext(ctx,
		`INSERT INTO audit_logs (id, timestamp, event_type, username, source_ip, target_host, action, result, details, created_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		log.ID, log.Timestamp, log.EventType, log.Username, log.SourceIP, log.TargetHost, log.Action, log.Result, string(detailsJSON), log.CreatedAt,
	)
	if err != nil {
		return fmt.Errorf("failed to create audit log: %w", err)
	}
	return nil
}

// ListAuditLogs returns audit logs with optional filters.
func (s *SQLiteStore) ListAuditLogs(ctx context.Context, username, eventType string, startTime, endTime time.Time, limit, offset int) ([]AuditLog, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	query := `SELECT id, timestamp, event_type, username, source_ip, target_host, action, result, details, created_at
	          FROM audit_logs WHERE 1=1`
	args := []interface{}{}

	if username != "" {
		query += " AND username = ?"
		args = append(args, username)
	}
	if eventType != "" {
		query += " AND event_type = ?"
		args = append(args, eventType)
	}
	if !startTime.IsZero() {
		query += " AND timestamp >= ?"
		args = append(args, startTime)
	}
	if !endTime.IsZero() {
		query += " AND timestamp <= ?"
		args = append(args, endTime)
	}

	query += " ORDER BY timestamp DESC"

	if limit > 0 {
		query += " LIMIT ?"
		args = append(args, limit)
	}
	if offset > 0 {
		query += " OFFSET ?"
		args = append(args, offset)
	}

	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("failed to query audit logs: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var logs []AuditLog
	for rows.Next() {
		var log AuditLog
		var sourceIP, targetHost, detailsJSON sql.NullString
		if err := rows.Scan(&log.ID, &log.Timestamp, &log.EventType, &log.Username, &sourceIP, &targetHost, &log.Action, &log.Result, &detailsJSON, &log.CreatedAt); err != nil {
			return nil, fmt.Errorf("failed to scan audit log: %w", err)
		}
		log.SourceIP = sourceIP.String
		log.TargetHost = targetHost.String
		if detailsJSON.Valid && detailsJSON.String != "" {
			_ = json.Unmarshal([]byte(detailsJSON.String), &log.Details)
		}
		logs = append(logs, log)
	}
	return logs, rows.Err()
}

// CleanupAuditLogs deletes audit logs older than the specified time.
func (s *SQLiteStore) CleanupAuditLogs(ctx context.Context, before time.Time) (int64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	result, err := s.db.ExecContext(ctx, "DELETE FROM audit_logs WHERE timestamp < ?", before)
	if err != nil {
		return 0, fmt.Errorf("failed to cleanup audit logs: %w", err)
	}
	return result.RowsAffected()
}
