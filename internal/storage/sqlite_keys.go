package storage

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"
)

// SSHKey represents an SSH key in storage.
type SSHKey struct {
	ID          string    `json:"id"`
	Name        string    `json:"name"`
	PrivateKey  string    `json:"private_key"` //nolint:gosec // G117: SSH private key storage field
	PublicKey   string    `json:"public_key"`
	Fingerprint string    `json:"fingerprint"`
	KeyType     string    `json:"key_type"`
	CreatedAt   time.Time `json:"created_at"`
	ExpiresAt   time.Time `json:"expires_at,omitempty"`
}

// SSHKeyStore extends Store with SSH key operations.
type SSHKeyStore interface {
	Store
	// SSH Key operations.
	GetSSHKey(ctx context.Context, id string) (*SSHKey, error)
	GetSSHKeyByFingerprint(ctx context.Context, fingerprint string) (*SSHKey, error)
	ListSSHKeys(ctx context.Context) ([]SSHKey, error)
	CreateSSHKey(ctx context.Context, key *SSHKey) error
	DeleteSSHKey(ctx context.Context, id string) error
}

// GetSSHKey retrieves an SSH key by ID.
func (s *SQLiteStore) GetSSHKey(ctx context.Context, id string) (*SSHKey, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var key SSHKey
	var expiresAt sql.NullTime
	err := s.db.QueryRowContext(ctx,
		"SELECT id, name, private_key, public_key, fingerprint, key_type, created_at, expires_at FROM ssh_keys WHERE id = ?",
		id,
	).Scan(&key.ID, &key.Name, &key.PrivateKey, &key.PublicKey, &key.Fingerprint, &key.KeyType, &key.CreatedAt, &expiresAt)

	if err == sql.ErrNoRows {
		return nil, errors.New("ssh key not found")
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get ssh key: %w", err)
	}

	if expiresAt.Valid {
		key.ExpiresAt = expiresAt.Time
	}

	return &key, nil
}

// GetSSHKeyByFingerprint retrieves an SSH key by fingerprint.
func (s *SQLiteStore) GetSSHKeyByFingerprint(ctx context.Context, fingerprint string) (*SSHKey, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var key SSHKey
	var expiresAt sql.NullTime
	err := s.db.QueryRowContext(ctx,
		"SELECT id, name, private_key, public_key, fingerprint, key_type, created_at, expires_at FROM ssh_keys WHERE fingerprint = ?",
		fingerprint,
	).Scan(&key.ID, &key.Name, &key.PrivateKey, &key.PublicKey, &key.Fingerprint, &key.KeyType, &key.CreatedAt, &expiresAt)

	if err == sql.ErrNoRows {
		return nil, errors.New("ssh key not found")
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get ssh key: %w", err)
	}

	if expiresAt.Valid {
		key.ExpiresAt = expiresAt.Time
	}

	return &key, nil
}

// ListSSHKeys returns all SSH keys.
func (s *SQLiteStore) ListSSHKeys(ctx context.Context) ([]SSHKey, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	rows, err := s.db.QueryContext(ctx,
		"SELECT id, name, private_key, public_key, fingerprint, key_type, created_at, expires_at FROM ssh_keys ORDER BY created_at DESC",
	)
	if err != nil {
		return nil, fmt.Errorf("failed to list ssh keys: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var keys []SSHKey
	for rows.Next() {
		var key SSHKey
		var expiresAt sql.NullTime
		if err := rows.Scan(&key.ID, &key.Name, &key.PrivateKey, &key.PublicKey, &key.Fingerprint, &key.KeyType, &key.CreatedAt, &expiresAt); err != nil {
			return nil, fmt.Errorf("failed to scan ssh key: %w", err)
		}

		if expiresAt.Valid {
			key.ExpiresAt = expiresAt.Time
		}

		keys = append(keys, key)
	}

	return keys, nil
}

// CreateSSHKey creates a new SSH key.
func (s *SQLiteStore) CreateSSHKey(ctx context.Context, key *SSHKey) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if key.ID == "" {
		key.ID = generateID()
	}
	key.CreatedAt = time.Now()

	var expiresAt interface{}
	if !key.ExpiresAt.IsZero() {
		expiresAt = key.ExpiresAt
	}

	_, err := s.db.ExecContext(ctx,
		"INSERT INTO ssh_keys (id, name, private_key, public_key, fingerprint, key_type, created_at, expires_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
		key.ID, key.Name, key.PrivateKey, key.PublicKey, key.Fingerprint, key.KeyType, key.CreatedAt, expiresAt,
	)
	if err != nil {
		return fmt.Errorf("failed to create ssh key: %w", err)
	}

	return nil
}

// DeleteSSHKey deletes an SSH key.
func (s *SQLiteStore) DeleteSSHKey(ctx context.Context, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	result, err := s.db.ExecContext(ctx, "DELETE FROM ssh_keys WHERE id = ?", id)
	if err != nil {
		return fmt.Errorf("failed to delete ssh key: %w", err)
	}

	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		return errors.New("ssh key not found")
	}

	return nil
}
