package storage

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
)

// API Key operations.

// CreateApiKey creates a new API key.
func (s *SQLiteStore) CreateApiKey(ctx context.Context, key *ApiKey) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if key.ID == "" {
		key.ID = uuid.New().String()
	}
	key.CreatedAt = time.Now()
	key.IsActive = true

	scopesJSON, _ := json.Marshal(key.Scopes)

	_, err := s.db.ExecContext(ctx,
		`INSERT INTO api_keys (id, user_id, name, description, token_prefix, token_hash, scopes, expires_at, is_active, created_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		key.ID, key.UserID, key.Name, key.Description, key.TokenPrefix, key.TokenHash,
		string(scopesJSON), key.ExpiresAt, key.IsActive, key.CreatedAt,
	)
	if err != nil {
		return fmt.Errorf("failed to create api key: %w", err)
	}

	return nil
}

// GetApiKey retrieves an API key by ID.
func (s *SQLiteStore) GetApiKey(ctx context.Context, id string) (*ApiKey, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	return s.scanApiKey(s.db.QueryRowContext(ctx,
		`SELECT id, user_id, name, description, token_prefix, token_hash, scopes,
		        last_used_at, expires_at, is_active, created_at
		 FROM api_keys WHERE id = ?`, id,
	))
}

// GetApiKeyByTokenHash retrieves an active API key by its token hash.
func (s *SQLiteStore) GetApiKeyByTokenHash(ctx context.Context, tokenHash string) (*ApiKey, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	return s.scanApiKey(s.db.QueryRowContext(ctx,
		`SELECT id, user_id, name, description, token_prefix, token_hash, scopes,
		        last_used_at, expires_at, is_active, created_at
		 FROM api_keys WHERE token_hash = ? AND is_active = 1`, tokenHash,
	))
}

// ListApiKeysByUser returns all API keys for a user.
func (s *SQLiteStore) ListApiKeysByUser(ctx context.Context, userID string) ([]ApiKey, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	rows, err := s.db.QueryContext(ctx,
		`SELECT id, user_id, name, description, token_prefix, token_hash, scopes,
		        last_used_at, expires_at, is_active, created_at
		 FROM api_keys WHERE user_id = ? ORDER BY created_at DESC`, userID,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to list api keys: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var keys []ApiKey
	for rows.Next() {
		key, err := s.scanApiKeyRow(rows)
		if err != nil {
			return nil, err
		}
		keys = append(keys, *key)
	}

	return keys, nil
}

// UpdateApiKeyLastUsed updates the last_used_at timestamp.
func (s *SQLiteStore) UpdateApiKeyLastUsed(ctx context.Context, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	_, err := s.db.ExecContext(ctx,
		"UPDATE api_keys SET last_used_at = ? WHERE id = ?",
		time.Now(), id,
	)
	return err
}

// DeactivateApiKey disables an API key without deleting it.
func (s *SQLiteStore) DeactivateApiKey(ctx context.Context, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	result, err := s.db.ExecContext(ctx,
		"UPDATE api_keys SET is_active = 0 WHERE id = ?", id,
	)
	if err != nil {
		return fmt.Errorf("failed to deactivate api key: %w", err)
	}

	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		return errors.New("api key not found")
	}

	return nil
}

// DeleteApiKey permanently removes an API key.
func (s *SQLiteStore) DeleteApiKey(ctx context.Context, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	result, err := s.db.ExecContext(ctx, "DELETE FROM api_keys WHERE id = ?", id)
	if err != nil {
		return fmt.Errorf("failed to delete api key: %w", err)
	}

	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		return errors.New("api key not found")
	}

	return nil
}

// DeleteApiKeysByUser removes all API keys for a user.
func (s *SQLiteStore) DeleteApiKeysByUser(ctx context.Context, userID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	_, err := s.db.ExecContext(ctx, "DELETE FROM api_keys WHERE user_id = ?", userID)
	return err
}

// scanApiKey scans a single api_key row from a QueryRow result.
func (s *SQLiteStore) scanApiKey(row *sql.Row) (*ApiKey, error) {
	var key ApiKey
	var description sql.NullString
	var scopesJSON string
	var lastUsedAt, expiresAt sql.NullTime

	err := row.Scan(
		&key.ID, &key.UserID, &key.Name, &description, &key.TokenPrefix, &key.TokenHash,
		&scopesJSON, &lastUsedAt, &expiresAt, &key.IsActive, &key.CreatedAt,
	)
	if err == sql.ErrNoRows {
		return nil, errors.New("api key not found")
	}
	if err != nil {
		return nil, fmt.Errorf("failed to scan api key: %w", err)
	}

	if description.Valid {
		key.Description = description.String
	}
	if lastUsedAt.Valid {
		key.LastUsedAt = &lastUsedAt.Time
	}
	if expiresAt.Valid {
		key.ExpiresAt = &expiresAt.Time
	}
	if err := json.Unmarshal([]byte(scopesJSON), &key.Scopes); err != nil {
		key.Scopes = nil
	}

	return &key, nil
}

// scanApiKeyRow scans a single api_key row from a Rows iterator.
func (s *SQLiteStore) scanApiKeyRow(rows *sql.Rows) (*ApiKey, error) {
	var key ApiKey
	var description sql.NullString
	var scopesJSON string
	var lastUsedAt, expiresAt sql.NullTime

	err := rows.Scan(
		&key.ID, &key.UserID, &key.Name, &description, &key.TokenPrefix, &key.TokenHash,
		&scopesJSON, &lastUsedAt, &expiresAt, &key.IsActive, &key.CreatedAt,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to scan api key: %w", err)
	}

	if description.Valid {
		key.Description = description.String
	}
	if lastUsedAt.Valid {
		key.LastUsedAt = &lastUsedAt.Time
	}
	if expiresAt.Valid {
		key.ExpiresAt = &expiresAt.Time
	}
	if err := json.Unmarshal([]byte(scopesJSON), &key.Scopes); err != nil {
		key.Scopes = nil
	}

	return &key, nil
}
