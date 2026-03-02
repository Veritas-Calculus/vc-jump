package storage

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"
)

// Settings operations.

// GetSetting retrieves a setting value.
func (s *SQLiteStore) GetSetting(ctx context.Context, key string) (string, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var value string
	err := s.db.QueryRowContext(ctx, "SELECT value FROM settings WHERE key = ?", key).Scan(&value)
	if err == sql.ErrNoRows {
		return "", errors.New("setting not found")
	}
	if err != nil {
		return "", fmt.Errorf("failed to get setting: %w", err)
	}

	return value, nil
}

// SetSetting sets a setting value.
func (s *SQLiteStore) SetSetting(ctx context.Context, key, value string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	_, err := s.db.ExecContext(ctx,
		"INSERT OR REPLACE INTO settings (key, value, updated_at) VALUES (?, ?, ?)",
		key, value, time.Now(),
	)
	if err != nil {
		return fmt.Errorf("failed to set setting: %w", err)
	}

	return nil
}

// DB returns the underlying database connection for advanced queries.
func (s *SQLiteStore) DB() *sql.DB {
	return s.db
}
