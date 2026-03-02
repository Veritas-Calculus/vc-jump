package storage

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
)

// Session operations.

// GetSession retrieves a session by ID.
func (s *SQLiteStore) GetSession(ctx context.Context, id string) (*Session, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var session Session
	var endTime sql.NullTime
	var recording sql.NullString
	err := s.db.QueryRowContext(ctx,
		"SELECT id, username, source_ip, target_host, start_time, end_time, recording FROM sessions WHERE id = ?",
		id,
	).Scan(&session.ID, &session.Username, &session.SourceIP, &session.TargetHost, &session.StartTime, &endTime, &recording)

	if err == sql.ErrNoRows {
		return nil, errors.New("session not found")
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get session: %w", err)
	}

	if endTime.Valid {
		session.EndTime = endTime.Time
	}
	if recording.Valid {
		session.Recording = recording.String
	}

	return &session, nil
}

// ListSessions returns sessions, optionally filtered by username.
func (s *SQLiteStore) ListSessions(ctx context.Context, username string, limit int) ([]Session, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	query := "SELECT id, username, source_ip, target_host, start_time, end_time, recording FROM sessions"
	var args []interface{}

	if username != "" {
		query += " WHERE username = ?"
		args = append(args, username)
	}

	query += " ORDER BY start_time DESC"

	if limit > 0 {
		query += " LIMIT ?"
		args = append(args, limit)
	}

	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("failed to list sessions: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var sessions []Session
	for rows.Next() {
		var session Session
		var endTime sql.NullTime
		var recording sql.NullString
		if err := rows.Scan(&session.ID, &session.Username, &session.SourceIP, &session.TargetHost, &session.StartTime, &endTime, &recording); err != nil {
			return nil, fmt.Errorf("failed to scan session: %w", err)
		}

		if endTime.Valid {
			session.EndTime = endTime.Time
		}
		if recording.Valid {
			session.Recording = recording.String
		}

		sessions = append(sessions, session)
	}

	return sessions, nil
}

// CountSessions returns the total number of sessions.
func (s *SQLiteStore) CountSessions(ctx context.Context) (int, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var count int
	err := s.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM sessions").Scan(&count)
	if err != nil {
		return 0, fmt.Errorf("failed to count sessions: %w", err)
	}
	return count, nil
}

// CreateSession creates a new session.
func (s *SQLiteStore) CreateSession(ctx context.Context, session *Session) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if session.ID == "" {
		session.ID = generateID()
	}

	var endTime, recording interface{}
	if !session.EndTime.IsZero() {
		endTime = session.EndTime
	}
	if session.Recording != "" {
		recording = session.Recording
	}

	_, err := s.db.ExecContext(ctx,
		"INSERT INTO sessions (id, username, source_ip, target_host, start_time, end_time, recording) VALUES (?, ?, ?, ?, ?, ?, ?)",
		session.ID, session.Username, session.SourceIP, session.TargetHost, session.StartTime, endTime, recording,
	)
	if err != nil {
		return fmt.Errorf("failed to create session: %w", err)
	}

	return nil
}

// UpdateSession updates an existing session.
func (s *SQLiteStore) UpdateSession(ctx context.Context, session *Session) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	var endTime, recording interface{}
	if !session.EndTime.IsZero() {
		endTime = session.EndTime
	}
	if session.Recording != "" {
		recording = session.Recording
	}

	result, err := s.db.ExecContext(ctx,
		"UPDATE sessions SET username = ?, source_ip = ?, target_host = ?, start_time = ?, end_time = ?, recording = ? WHERE id = ?",
		session.Username, session.SourceIP, session.TargetHost, session.StartTime, endTime, recording, session.ID,
	)
	if err != nil {
		return fmt.Errorf("failed to update session: %w", err)
	}

	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		return errors.New("session not found")
	}

	return nil
}

// ListActiveSessions returns all sessions that have no end time (currently active).
func (s *SQLiteStore) ListActiveSessions(ctx context.Context) ([]Session, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	rows, err := s.db.QueryContext(ctx,
		"SELECT id, username, source_ip, target_host, start_time, end_time, recording FROM sessions WHERE end_time IS NULL ORDER BY start_time DESC",
	)
	if err != nil {
		return nil, fmt.Errorf("failed to list active sessions: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var sessions []Session
	for rows.Next() {
		var session Session
		var endTime sql.NullTime
		var recording sql.NullString
		if err := rows.Scan(&session.ID, &session.Username, &session.SourceIP, &session.TargetHost, &session.StartTime, &endTime, &recording); err != nil {
			return nil, fmt.Errorf("failed to scan session: %w", err)
		}

		if endTime.Valid {
			session.EndTime = endTime.Time
		}
		if recording.Valid {
			session.Recording = recording.String
		}

		sessions = append(sessions, session)
	}

	return sessions, nil
}

// CleanupStaleSessions closes all sessions that have no end time.
// This should be called on startup to clean up sessions that were not properly closed.
func (s *SQLiteStore) CleanupStaleSessions(ctx context.Context) (int64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	result, err := s.db.ExecContext(ctx,
		"UPDATE sessions SET end_time = start_time WHERE end_time IS NULL",
	)
	if err != nil {
		return 0, fmt.Errorf("failed to cleanup stale sessions: %w", err)
	}

	rowsAffected, _ := result.RowsAffected()
	return rowsAffected, nil
}

// Close closes the database connection.
func (s *SQLiteStore) Close() error {
	return s.db.Close()
}
