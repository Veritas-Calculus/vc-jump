package storage

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"
)

// User operations.

// GetUser retrieves a user by ID.
func (s *SQLiteStore) GetUser(ctx context.Context, id string) (*User, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var user User
	var groupsJSON, publicKeysJSON string
	var allowedHostsJSON, passwordHash, source, otpSecret sql.NullString
	var lastLoginAt sql.NullTime
	err := s.db.QueryRowContext(ctx,
		"SELECT id, username, password_hash, groups, public_keys, allowed_hosts, source, totp_secret, otp_enabled, otp_verified, is_active, last_login_at, created_at, updated_at FROM users WHERE id = ?",
		id,
	).Scan(&user.ID, &user.Username, &passwordHash, &groupsJSON, &publicKeysJSON, &allowedHostsJSON, &source, &otpSecret, &user.OTPEnabled, &user.OTPVerified, &user.IsActive, &lastLoginAt, &user.CreatedAt, &user.UpdatedAt)

	if err == sql.ErrNoRows {
		return nil, errors.New("user not found")
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get user: %w", err)
	}

	if passwordHash.Valid {
		user.PasswordHash = passwordHash.String
	}
	if source.Valid {
		user.Source = UserSource(source.String)
	}
	if otpSecret.Valid {
		user.OTPSecret = otpSecret.String
	}
	if lastLoginAt.Valid {
		user.LastLoginAt = lastLoginAt.Time
	}
	if err := json.Unmarshal([]byte(groupsJSON), &user.Groups); err != nil {
		user.Groups = nil
	}
	if err := json.Unmarshal([]byte(publicKeysJSON), &user.PublicKeys); err != nil {
		user.PublicKeys = nil
	}
	if allowedHostsJSON.Valid {
		if err := json.Unmarshal([]byte(allowedHostsJSON.String), &user.AllowedHosts); err != nil {
			user.AllowedHosts = nil
		}
	}

	return &user, nil
}

// GetUserByUsername retrieves a user by username.
func (s *SQLiteStore) GetUserByUsername(ctx context.Context, username string) (*User, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var user User
	var groupsJSON, publicKeysJSON string
	var allowedHostsJSON, passwordHash, source, otpSecret sql.NullString
	var lastLoginAt sql.NullTime
	err := s.db.QueryRowContext(ctx,
		"SELECT id, username, password_hash, groups, public_keys, allowed_hosts, source, totp_secret, otp_enabled, otp_verified, is_active, last_login_at, created_at, updated_at FROM users WHERE username = ?",
		username,
	).Scan(&user.ID, &user.Username, &passwordHash, &groupsJSON, &publicKeysJSON, &allowedHostsJSON, &source, &otpSecret, &user.OTPEnabled, &user.OTPVerified, &user.IsActive, &lastLoginAt, &user.CreatedAt, &user.UpdatedAt)

	if err == sql.ErrNoRows {
		return nil, errors.New("user not found")
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get user: %w", err)
	}

	if passwordHash.Valid {
		user.PasswordHash = passwordHash.String
	}
	if source.Valid {
		user.Source = UserSource(source.String)
	}
	if otpSecret.Valid {
		user.OTPSecret = otpSecret.String
	}
	if lastLoginAt.Valid {
		user.LastLoginAt = lastLoginAt.Time
	}
	if err := json.Unmarshal([]byte(groupsJSON), &user.Groups); err != nil {
		user.Groups = nil
	}
	if err := json.Unmarshal([]byte(publicKeysJSON), &user.PublicKeys); err != nil {
		user.PublicKeys = nil
	}
	if allowedHostsJSON.Valid {
		if err := json.Unmarshal([]byte(allowedHostsJSON.String), &user.AllowedHosts); err != nil {
			user.AllowedHosts = nil
		}
	}

	return &user, nil
}

// ListUsers returns all users.
func (s *SQLiteStore) ListUsers(ctx context.Context) ([]User, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	rows, err := s.db.QueryContext(ctx,
		"SELECT id, username, password_hash, groups, public_keys, allowed_hosts, source, totp_secret, otp_enabled, otp_verified, is_active, last_login_at, created_at, updated_at FROM users ORDER BY username",
	)
	if err != nil {
		return nil, fmt.Errorf("failed to list users: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var users []User
	for rows.Next() {
		var user User
		var groupsJSON, publicKeysJSON string
		var allowedHostsJSON, passwordHash, source, otpSecret sql.NullString
		var lastLoginAt sql.NullTime
		if err := rows.Scan(&user.ID, &user.Username, &passwordHash, &groupsJSON, &publicKeysJSON, &allowedHostsJSON, &source, &otpSecret, &user.OTPEnabled, &user.OTPVerified, &user.IsActive, &lastLoginAt, &user.CreatedAt, &user.UpdatedAt); err != nil {
			return nil, fmt.Errorf("failed to scan user: %w", err)
		}

		if passwordHash.Valid {
			user.PasswordHash = passwordHash.String
		}
		if source.Valid {
			user.Source = UserSource(source.String)
		}
		if otpSecret.Valid {
			user.OTPSecret = otpSecret.String
		}
		if lastLoginAt.Valid {
			user.LastLoginAt = lastLoginAt.Time
		}
		if err := json.Unmarshal([]byte(groupsJSON), &user.Groups); err != nil {
			user.Groups = nil
		}
		if err := json.Unmarshal([]byte(publicKeysJSON), &user.PublicKeys); err != nil {
			user.PublicKeys = nil
		}
		if allowedHostsJSON.Valid {
			if err := json.Unmarshal([]byte(allowedHostsJSON.String), &user.AllowedHosts); err != nil {
				user.AllowedHosts = nil
			}
		}

		users = append(users, user)
	}

	return users, nil
}

// CreateUser creates a new user.
func (s *SQLiteStore) CreateUser(ctx context.Context, user *User) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if user.ID == "" {
		user.ID = generateID()
	}
	if user.Source == "" {
		user.Source = UserSourceLocal
	}
	user.CreatedAt = time.Now()
	user.UpdatedAt = time.Now()

	groupsJSON, _ := json.Marshal(user.Groups)
	publicKeysJSON, _ := json.Marshal(user.PublicKeys)
	allowedHostsJSON, _ := json.Marshal(user.AllowedHosts)

	_, err := s.db.ExecContext(ctx,
		"INSERT INTO users (id, username, password_hash, groups, public_keys, allowed_hosts, source, is_active, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
		user.ID, user.Username, user.PasswordHash, string(groupsJSON), string(publicKeysJSON), string(allowedHostsJSON), string(user.Source), user.IsActive, user.CreatedAt, user.UpdatedAt,
	)
	if err != nil {
		return fmt.Errorf("failed to create user: %w", err)
	}

	return nil
}

// UpdateUser updates an existing user.
func (s *SQLiteStore) UpdateUser(ctx context.Context, user *User) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	user.UpdatedAt = time.Now()

	groupsJSON, _ := json.Marshal(user.Groups)
	publicKeysJSON, _ := json.Marshal(user.PublicKeys)
	allowedHostsJSON, _ := json.Marshal(user.AllowedHosts)

	result, err := s.db.ExecContext(ctx,
		"UPDATE users SET username = ?, groups = ?, public_keys = ?, allowed_hosts = ?, is_active = ?, updated_at = ? WHERE id = ?",
		user.Username, string(groupsJSON), string(publicKeysJSON), string(allowedHostsJSON), user.IsActive, user.UpdatedAt, user.ID,
	)
	if err != nil {
		return fmt.Errorf("failed to update user: %w", err)
	}

	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		return errors.New("user not found")
	}

	return nil
}

// DeleteUser deletes a user.
func (s *SQLiteStore) DeleteUser(ctx context.Context, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	result, err := s.db.ExecContext(ctx, "DELETE FROM users WHERE id = ?", id)
	if err != nil {
		return fmt.Errorf("failed to delete user: %w", err)
	}

	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		return errors.New("user not found")
	}

	return nil
}

// UserWithPassword extends User with password hash.
type UserWithPassword struct {
	User
	PasswordHash string `json:"password_hash,omitempty"`
	TOTPSecret   string `json:"totp_secret,omitempty"`
	IsActive     bool   `json:"is_active"`
}

// GetUserWithPassword retrieves a user with password hash by username.
func (s *SQLiteStore) GetUserWithPassword(ctx context.Context, username string) (*UserWithPassword, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var user UserWithPassword
	var groupsJSON, publicKeysJSON, allowedHostsJSON string
	var passwordHash, totpSecret sql.NullString
	var lastLoginAt sql.NullTime
	var isActive int
	err := s.db.QueryRowContext(ctx,
		"SELECT id, username, password_hash, groups, public_keys, allowed_hosts, totp_secret, is_active, last_login_at, created_at, updated_at FROM users WHERE username = ?",
		username,
	).Scan(&user.ID, &user.Username, &passwordHash, &groupsJSON, &publicKeysJSON, &allowedHostsJSON, &totpSecret, &isActive, &lastLoginAt, &user.CreatedAt, &user.UpdatedAt)

	if err == sql.ErrNoRows {
		return nil, errors.New("user not found")
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get user: %w", err)
	}

	if passwordHash.Valid {
		user.PasswordHash = passwordHash.String
	}
	if totpSecret.Valid {
		user.TOTPSecret = totpSecret.String
	}
	user.IsActive = isActive == 1
	if lastLoginAt.Valid {
		user.LastLoginAt = lastLoginAt.Time
	}
	if err := json.Unmarshal([]byte(groupsJSON), &user.Groups); err != nil {
		user.Groups = nil
	}
	if err := json.Unmarshal([]byte(publicKeysJSON), &user.PublicKeys); err != nil {
		user.PublicKeys = nil
	}
	if err := json.Unmarshal([]byte(allowedHostsJSON), &user.AllowedHosts); err != nil {
		user.AllowedHosts = nil
	}

	return &user, nil
}

// CreateUserWithPassword creates a new user with password.
func (s *SQLiteStore) CreateUserWithPassword(ctx context.Context, user *UserWithPassword) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if user.ID == "" {
		user.ID = generateID()
	}
	if user.Source == "" {
		user.Source = UserSourceLocal
	}
	user.CreatedAt = time.Now()
	user.UpdatedAt = time.Now()

	groupsJSON, _ := json.Marshal(user.Groups)
	publicKeysJSON, _ := json.Marshal(user.PublicKeys)
	allowedHostsJSON, _ := json.Marshal(user.AllowedHosts)

	var passwordHash, totpSecret interface{}
	if user.PasswordHash != "" {
		passwordHash = user.PasswordHash
	}
	if user.TOTPSecret != "" {
		totpSecret = user.TOTPSecret
	}

	isActive := 0
	if user.IsActive {
		isActive = 1
	}

	_, err := s.db.ExecContext(ctx,
		"INSERT INTO users (id, username, password_hash, groups, public_keys, allowed_hosts, source, totp_secret, is_active, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
		user.ID, user.Username, passwordHash, string(groupsJSON), string(publicKeysJSON), string(allowedHostsJSON), string(user.Source), totpSecret, isActive, user.CreatedAt, user.UpdatedAt,
	)
	if err != nil {
		return fmt.Errorf("failed to create user: %w", err)
	}

	return nil
}

// UpdateUserPassword updates a user's password hash.
func (s *SQLiteStore) UpdateUserPassword(ctx context.Context, userID, passwordHash string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	result, err := s.db.ExecContext(ctx,
		"UPDATE users SET password_hash = ?, updated_at = ? WHERE id = ?",
		passwordHash, time.Now(), userID,
	)
	if err != nil {
		return fmt.Errorf("failed to update password: %w", err)
	}

	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		return errors.New("user not found")
	}

	return nil
}

// UpdateUserLastLogin updates a user's last login time.
func (s *SQLiteStore) UpdateUserLastLogin(ctx context.Context, userID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	result, err := s.db.ExecContext(ctx,
		"UPDATE users SET last_login_at = ? WHERE id = ?",
		time.Now(), userID,
	)
	if err != nil {
		return fmt.Errorf("failed to update last login: %w", err)
	}

	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		return errors.New("user not found")
	}

	return nil
}
