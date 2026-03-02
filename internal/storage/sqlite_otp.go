package storage

import (
	"context"
	"fmt"
	"time"
)

// OTP-related methods.

// SetUserOTPSecret sets the OTP secret for a user.
func (s *SQLiteStore) SetUserOTPSecret(ctx context.Context, userID, secret string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	_, err := s.db.ExecContext(ctx,
		"UPDATE users SET totp_secret = ?, updated_at = ? WHERE id = ?",
		secret, time.Now(), userID,
	)
	if err != nil {
		return fmt.Errorf("failed to set OTP secret: %w", err)
	}
	return nil
}

// EnableUserOTP enables OTP for a user (marks as verified).
func (s *SQLiteStore) EnableUserOTP(ctx context.Context, userID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	_, err := s.db.ExecContext(ctx,
		"UPDATE users SET otp_enabled = 1, otp_verified = 1, updated_at = ? WHERE id = ?",
		time.Now(), userID,
	)
	if err != nil {
		return fmt.Errorf("failed to enable OTP: %w", err)
	}
	return nil
}

// DisableUserOTP disables OTP for a user and clears the secret.
func (s *SQLiteStore) DisableUserOTP(ctx context.Context, userID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	_, err := s.db.ExecContext(ctx,
		"UPDATE users SET otp_enabled = 0, otp_verified = 0, totp_secret = NULL, updated_at = ? WHERE id = ?",
		time.Now(), userID,
	)
	if err != nil {
		return fmt.Errorf("failed to disable OTP: %w", err)
	}
	return nil
}

// GetAllSettings retrieves all settings.
func (s *SQLiteStore) GetAllSettings(ctx context.Context) (map[string]string, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	rows, err := s.db.QueryContext(ctx, "SELECT key, value FROM settings")
	if err != nil {
		return nil, fmt.Errorf("failed to list settings: %w", err)
	}
	defer func() { _ = rows.Close() }()

	settings := make(map[string]string)
	for rows.Next() {
		var key, value string
		if err := rows.Scan(&key, &value); err != nil {
			return nil, fmt.Errorf("failed to scan setting: %w", err)
		}
		settings[key] = value
	}
	return settings, rows.Err()
}
