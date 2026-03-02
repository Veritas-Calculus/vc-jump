package storage

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"
)

// Token operations for session management.

// Token represents an authentication token.
type Token struct {
	ID        string    `json:"id"`
	UserID    string    `json:"user_id"`
	TokenHash string    `json:"token_hash"`
	TokenType string    `json:"token_type"` // "session", "api", "refresh"
	ExpiresAt time.Time `json:"expires_at"`
	CreatedAt time.Time `json:"created_at"`
}

// ApiKey represents an API key for programmatic access (e.g., Terraform, CI/CD).
type ApiKey struct {
	ID          string     `json:"id"`
	UserID      string     `json:"user_id"`
	Name        string     `json:"name"`
	Description string     `json:"description,omitempty"`
	TokenPrefix string     `json:"token_prefix"` // First 8 chars of the token for identification.
	TokenHash   string     `json:"-"`            // SHA256 hash, never exposed via API.
	Scopes      []string   `json:"scopes"`       // Permission scopes, empty means inherit all user permissions.
	LastUsedAt  *time.Time `json:"last_used_at,omitempty"`
	ExpiresAt   *time.Time `json:"expires_at,omitempty"` // nil means never expires.
	IsActive    bool       `json:"is_active"`
	CreatedAt   time.Time  `json:"created_at"`
}

// CreateToken creates a new token.
func (s *SQLiteStore) CreateToken(ctx context.Context, token *Token) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if token.ID == "" {
		token.ID = generateID()
	}
	token.CreatedAt = time.Now()

	_, err := s.db.ExecContext(ctx,
		"INSERT INTO tokens (id, user_id, token_hash, token_type, expires_at, created_at) VALUES (?, ?, ?, ?, ?, ?)",
		token.ID, token.UserID, token.TokenHash, token.TokenType, token.ExpiresAt, token.CreatedAt,
	)
	if err != nil {
		return fmt.Errorf("failed to create token: %w", err)
	}

	return nil
}

// GetTokenByHash retrieves a token by its hash.
func (s *SQLiteStore) GetTokenByHash(ctx context.Context, tokenHash string) (*Token, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var token Token
	err := s.db.QueryRowContext(ctx,
		"SELECT id, user_id, token_hash, token_type, expires_at, created_at FROM tokens WHERE token_hash = ?",
		tokenHash,
	).Scan(&token.ID, &token.UserID, &token.TokenHash, &token.TokenType, &token.ExpiresAt, &token.CreatedAt)

	if err == sql.ErrNoRows {
		return nil, errors.New("token not found")
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get token: %w", err)
	}

	return &token, nil
}

// DeleteToken deletes a token.
func (s *SQLiteStore) DeleteToken(ctx context.Context, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	_, err := s.db.ExecContext(ctx, "DELETE FROM tokens WHERE id = ?", id)
	return err
}

// DeleteExpiredTokens removes expired tokens.
func (s *SQLiteStore) DeleteExpiredTokens(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	_, err := s.db.ExecContext(ctx, "DELETE FROM tokens WHERE expires_at < ?", time.Now())
	return err
}

// DeleteUserTokens removes all tokens for a user.
func (s *SQLiteStore) DeleteUserTokens(ctx context.Context, userID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	_, err := s.db.ExecContext(ctx, "DELETE FROM tokens WHERE user_id = ?", userID)
	return err
}
