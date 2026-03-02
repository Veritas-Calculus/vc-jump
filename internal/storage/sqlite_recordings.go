package storage

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
)

// ============================================================
// Recording Operations
// ============================================================

// GetRecording retrieves a recording by ID.
func (s *SQLiteStore) GetRecording(ctx context.Context, id string) (*Recording, error) {
	if id == "" {
		return nil, errors.New("recording ID cannot be empty")
	}

	s.mu.RLock()
	defer s.mu.RUnlock()

	var rec Recording
	var sessionID, storagePath, s3Bucket, s3Key, checksum sql.NullString
	var endTime sql.NullTime

	err := s.db.QueryRowContext(ctx,
		`SELECT id, session_id, username, hostname, filename, storage_type, storage_path, 
		        s3_bucket, s3_key, file_size, duration, start_time, end_time, checksum, is_complete, created_at, updated_at
		 FROM recordings WHERE id = ?`,
		id,
	).Scan(
		&rec.ID, &sessionID, &rec.Username, &rec.HostName, &rec.Filename, &rec.StorageType,
		&storagePath, &s3Bucket, &s3Key, &rec.FileSize, &rec.Duration,
		&rec.StartTime, &endTime, &checksum, &rec.IsComplete, &rec.CreatedAt, &rec.UpdatedAt,
	)

	if err == sql.ErrNoRows {
		return nil, errors.New("recording not found")
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get recording: %w", err)
	}

	if sessionID.Valid {
		rec.SessionID = sessionID.String
	}
	if storagePath.Valid {
		rec.StoragePath = storagePath.String
	}
	if s3Bucket.Valid {
		rec.S3Bucket = s3Bucket.String
	}
	if s3Key.Valid {
		rec.S3Key = s3Key.String
	}
	if endTime.Valid {
		rec.EndTime = endTime.Time
	}
	if checksum.Valid {
		rec.Checksum = checksum.String
	}

	return &rec, nil
}

// GetRecordingBySessionID retrieves a recording by session ID.
func (s *SQLiteStore) GetRecordingBySessionID(ctx context.Context, sessionID string) (*Recording, error) {
	if sessionID == "" {
		return nil, errors.New("session ID cannot be empty")
	}

	s.mu.RLock()
	defer s.mu.RUnlock()

	var rec Recording
	var sessID, storagePath, s3Bucket, s3Key, checksum sql.NullString
	var endTime sql.NullTime

	err := s.db.QueryRowContext(ctx,
		`SELECT id, session_id, username, hostname, filename, storage_type, storage_path, 
		        s3_bucket, s3_key, file_size, duration, start_time, end_time, checksum, is_complete, created_at, updated_at
		 FROM recordings WHERE session_id = ?`,
		sessionID,
	).Scan(
		&rec.ID, &sessID, &rec.Username, &rec.HostName, &rec.Filename, &rec.StorageType,
		&storagePath, &s3Bucket, &s3Key, &rec.FileSize, &rec.Duration,
		&rec.StartTime, &endTime, &checksum, &rec.IsComplete, &rec.CreatedAt, &rec.UpdatedAt,
	)

	if err == sql.ErrNoRows {
		return nil, errors.New("recording not found")
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get recording by session ID: %w", err)
	}

	if sessID.Valid {
		rec.SessionID = sessID.String
	}
	if storagePath.Valid {
		rec.StoragePath = storagePath.String
	}
	if s3Bucket.Valid {
		rec.S3Bucket = s3Bucket.String
	}
	if s3Key.Valid {
		rec.S3Key = s3Key.String
	}
	if endTime.Valid {
		rec.EndTime = endTime.Time
	}
	if checksum.Valid {
		rec.Checksum = checksum.String
	}

	return &rec, nil
}

// ListRecordings returns recordings with optional username filter and pagination.
func (s *SQLiteStore) ListRecordings(ctx context.Context, username string, limit, offset int) ([]Recording, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	query := `SELECT id, session_id, username, hostname, filename, storage_type, storage_path, 
	                 s3_bucket, s3_key, file_size, duration, start_time, end_time, checksum, is_complete, created_at, updated_at
	          FROM recordings`
	args := []interface{}{}

	if username != "" {
		query += " WHERE username = ?"
		args = append(args, username)
	}

	query += " ORDER BY start_time DESC"

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
		return nil, fmt.Errorf("failed to list recordings: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var recordings []Recording
	for rows.Next() {
		var rec Recording
		var sessionID, storagePath, s3Bucket, s3Key, checksum sql.NullString
		var endTime sql.NullTime

		if err := rows.Scan(
			&rec.ID, &sessionID, &rec.Username, &rec.HostName, &rec.Filename, &rec.StorageType,
			&storagePath, &s3Bucket, &s3Key, &rec.FileSize, &rec.Duration,
			&rec.StartTime, &endTime, &checksum, &rec.IsComplete, &rec.CreatedAt, &rec.UpdatedAt,
		); err != nil {
			return nil, fmt.Errorf("failed to scan recording: %w", err)
		}

		if sessionID.Valid {
			rec.SessionID = sessionID.String
		}
		if storagePath.Valid {
			rec.StoragePath = storagePath.String
		}
		if s3Bucket.Valid {
			rec.S3Bucket = s3Bucket.String
		}
		if s3Key.Valid {
			rec.S3Key = s3Key.String
		}
		if endTime.Valid {
			rec.EndTime = endTime.Time
		}
		if checksum.Valid {
			rec.Checksum = checksum.String
		}

		recordings = append(recordings, rec)
	}

	return recordings, rows.Err()
}

// CreateRecording creates a new recording metadata entry.
func (s *SQLiteStore) CreateRecording(ctx context.Context, recording *Recording) error {
	if recording == nil {
		return errors.New("recording cannot be nil")
	}
	if recording.Username == "" {
		return errors.New("recording username cannot be empty")
	}
	if recording.HostName == "" {
		return errors.New("recording hostname cannot be empty")
	}
	if recording.Filename == "" {
		return errors.New("recording filename cannot be empty")
	}
	if recording.StorageType == "" {
		return errors.New("recording storage_type cannot be empty")
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if recording.ID == "" {
		recording.ID = uuid.New().String()
	}
	now := time.Now()
	recording.CreatedAt = now
	recording.UpdatedAt = now

	var sessionID, storagePath, s3Bucket, s3Key, checksum interface{}
	var endTime interface{}

	if recording.SessionID != "" {
		sessionID = recording.SessionID
	}
	if recording.StoragePath != "" {
		storagePath = recording.StoragePath
	}
	if recording.S3Bucket != "" {
		s3Bucket = recording.S3Bucket
	}
	if recording.S3Key != "" {
		s3Key = recording.S3Key
	}
	if recording.Checksum != "" {
		checksum = recording.Checksum
	}
	if !recording.EndTime.IsZero() {
		endTime = recording.EndTime
	}

	_, err := s.db.ExecContext(ctx,
		`INSERT INTO recordings (id, session_id, username, hostname, filename, storage_type, storage_path, 
		                         s3_bucket, s3_key, file_size, duration, start_time, end_time, checksum, is_complete, created_at, updated_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		recording.ID, sessionID, recording.Username, recording.HostName, recording.Filename, recording.StorageType,
		storagePath, s3Bucket, s3Key, recording.FileSize, recording.Duration,
		recording.StartTime, endTime, checksum, recording.IsComplete, recording.CreatedAt, recording.UpdatedAt,
	)
	if err != nil {
		return fmt.Errorf("failed to create recording: %w", err)
	}

	return nil
}

// UpdateRecording updates an existing recording metadata entry.
func (s *SQLiteStore) UpdateRecording(ctx context.Context, recording *Recording) error {
	if recording == nil {
		return errors.New("recording cannot be nil")
	}
	if recording.ID == "" {
		return errors.New("recording ID cannot be empty")
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	recording.UpdatedAt = time.Now()

	var sessionID, storagePath, s3Bucket, s3Key, checksum interface{}
	var endTime interface{}

	if recording.SessionID != "" {
		sessionID = recording.SessionID
	}
	if recording.StoragePath != "" {
		storagePath = recording.StoragePath
	}
	if recording.S3Bucket != "" {
		s3Bucket = recording.S3Bucket
	}
	if recording.S3Key != "" {
		s3Key = recording.S3Key
	}
	if recording.Checksum != "" {
		checksum = recording.Checksum
	}
	if !recording.EndTime.IsZero() {
		endTime = recording.EndTime
	}

	result, err := s.db.ExecContext(ctx,
		`UPDATE recordings SET session_id = ?, username = ?, hostname = ?, filename = ?, storage_type = ?, storage_path = ?,
		                       s3_bucket = ?, s3_key = ?, file_size = ?, duration = ?, start_time = ?, end_time = ?,
		                       checksum = ?, is_complete = ?, updated_at = ?
		 WHERE id = ?`,
		sessionID, recording.Username, recording.HostName, recording.Filename, recording.StorageType, storagePath,
		s3Bucket, s3Key, recording.FileSize, recording.Duration, recording.StartTime, endTime,
		checksum, recording.IsComplete, recording.UpdatedAt, recording.ID,
	)
	if err != nil {
		return fmt.Errorf("failed to update recording: %w", err)
	}

	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		return errors.New("recording not found")
	}

	return nil
}

// DeleteRecording deletes a recording metadata entry by ID.
func (s *SQLiteStore) DeleteRecording(ctx context.Context, id string) error {
	if id == "" {
		return errors.New("recording ID cannot be empty")
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	result, err := s.db.ExecContext(ctx, "DELETE FROM recordings WHERE id = ?", id)
	if err != nil {
		return fmt.Errorf("failed to delete recording: %w", err)
	}

	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		return errors.New("recording not found")
	}

	return nil
}

// CleanupRecordings deletes recording metadata older than the specified time.
func (s *SQLiteStore) CleanupRecordings(ctx context.Context, before time.Time) (int64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	result, err := s.db.ExecContext(ctx, "DELETE FROM recordings WHERE start_time < ?", before)
	if err != nil {
		return 0, fmt.Errorf("failed to cleanup recordings: %w", err)
	}
	return result.RowsAffected()
}
