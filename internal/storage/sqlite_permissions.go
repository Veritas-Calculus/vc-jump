package storage

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"
)

// Host Permission operations.

// GetHostPermissions returns all host permissions for a user.
func (s *SQLiteStore) GetHostPermissions(ctx context.Context, userID string) ([]HostPermission, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	rows, err := s.db.QueryContext(ctx,
		`SELECT id, user_id, host_id, can_sudo, expires_at, created_at, updated_at
		 FROM host_permissions WHERE user_id = ?`,
		userID,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to get host permissions: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var perms []HostPermission
	for rows.Next() {
		var perm HostPermission
		var expiresAt sql.NullTime

		if err := rows.Scan(&perm.ID, &perm.UserID, &perm.HostID, &perm.CanSudo, &expiresAt, &perm.CreatedAt, &perm.UpdatedAt); err != nil {
			return nil, fmt.Errorf("failed to scan permission: %w", err)
		}

		if expiresAt.Valid {
			perm.ExpiresAt = expiresAt.Time
		}
		perms = append(perms, perm)
	}

	return perms, rows.Err()
}

// ListAllHostPermissions returns all host permissions in the system.
func (s *SQLiteStore) ListAllHostPermissions(ctx context.Context) ([]HostPermission, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	rows, err := s.db.QueryContext(ctx,
		`SELECT id, user_id, host_id, can_sudo, expires_at, created_at, updated_at
		 FROM host_permissions ORDER BY created_at DESC`,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to list host permissions: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var perms []HostPermission
	for rows.Next() {
		var perm HostPermission
		var expiresAt sql.NullTime

		if err := rows.Scan(&perm.ID, &perm.UserID, &perm.HostID, &perm.CanSudo, &expiresAt, &perm.CreatedAt, &perm.UpdatedAt); err != nil {
			return nil, fmt.Errorf("failed to scan permission: %w", err)
		}

		if expiresAt.Valid {
			perm.ExpiresAt = expiresAt.Time
		}
		perms = append(perms, perm)
	}

	return perms, rows.Err()
}

// GetHostPermission returns a specific host permission.
func (s *SQLiteStore) GetHostPermission(ctx context.Context, userID, hostID string) (*HostPermission, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var perm HostPermission
	var expiresAt sql.NullTime

	err := s.db.QueryRowContext(ctx,
		`SELECT id, user_id, host_id, can_sudo, expires_at, created_at, updated_at
		 FROM host_permissions WHERE user_id = ? AND host_id = ?`,
		userID, hostID,
	).Scan(&perm.ID, &perm.UserID, &perm.HostID, &perm.CanSudo, &expiresAt, &perm.CreatedAt, &perm.UpdatedAt)
	if err == sql.ErrNoRows {
		return nil, errors.New("permission not found")
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get permission: %w", err)
	}

	if expiresAt.Valid {
		perm.ExpiresAt = expiresAt.Time
	}

	return &perm, nil
}

// GrantHostAccess grants a user access to a host.
func (s *SQLiteStore) GrantHostAccess(ctx context.Context, perm *HostPermission) error {
	if perm.UserID == "" || perm.HostID == "" {
		return errors.New("userID and hostID are required")
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if perm.ID == "" {
		perm.ID = generateID()
	}
	perm.CreatedAt = time.Now()
	perm.UpdatedAt = perm.CreatedAt

	var expiresAt interface{}
	if !perm.ExpiresAt.IsZero() {
		expiresAt = perm.ExpiresAt
	}

	_, err := s.db.ExecContext(ctx,
		`INSERT OR REPLACE INTO host_permissions (id, user_id, host_id, can_sudo, expires_at, created_at, updated_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?)`,
		perm.ID, perm.UserID, perm.HostID, perm.CanSudo, expiresAt, perm.CreatedAt, perm.UpdatedAt,
	)
	if err != nil {
		return fmt.Errorf("failed to grant host access: %w", err)
	}

	return nil
}

// RevokeHostAccess removes a user's access to a host.
func (s *SQLiteStore) RevokeHostAccess(ctx context.Context, userID, hostID string) error {
	if userID == "" || hostID == "" {
		return errors.New("userID and hostID are required")
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	_, err := s.db.ExecContext(ctx,
		"DELETE FROM host_permissions WHERE user_id = ? AND host_id = ?",
		userID, hostID,
	)
	if err != nil {
		return fmt.Errorf("failed to revoke host access: %w", err)
	}

	return nil
}

// RevokeHostAccessByID removes a host permission by its ID.
func (s *SQLiteStore) RevokeHostAccessByID(ctx context.Context, id string) error {
	if id == "" {
		return errors.New("id is required")
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	result, err := s.db.ExecContext(ctx,
		"DELETE FROM host_permissions WHERE id = ?",
		id,
	)
	if err != nil {
		return fmt.Errorf("failed to revoke host access: %w", err)
	}

	rows, _ := result.RowsAffected()
	if rows == 0 {
		return errors.New("permission not found")
	}

	return nil
}

// ListUsersWithHostAccess returns all users with access to a specific host.
func (s *SQLiteStore) ListUsersWithHostAccess(ctx context.Context, hostID string) ([]HostPermission, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	rows, err := s.db.QueryContext(ctx,
		`SELECT id, user_id, host_id, can_sudo, expires_at, created_at, updated_at
		 FROM host_permissions WHERE host_id = ?`,
		hostID,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to list users with host access: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var perms []HostPermission
	for rows.Next() {
		var perm HostPermission
		var expiresAt sql.NullTime

		if err := rows.Scan(&perm.ID, &perm.UserID, &perm.HostID, &perm.CanSudo, &expiresAt, &perm.CreatedAt, &perm.UpdatedAt); err != nil {
			return nil, fmt.Errorf("failed to scan permission: %w", err)
		}

		if expiresAt.Valid {
			perm.ExpiresAt = expiresAt.Time
		}
		perms = append(perms, perm)
	}

	return perms, rows.Err()
}

// InitDefaultRoles initializes the default system roles if they don't exist.
func (s *SQLiteStore) InitDefaultRoles(ctx context.Context) error {
	defaultRoles := []struct {
		Name        string
		DisplayName string
		Description string
		Permissions []string
	}{
		{
			Name:        "admin",
			DisplayName: "Administrator",
			Description: "Full system access",
			Permissions: []string{
				"host:connect", "host:view", "host:create", "host:update", "host:delete",
				"user:view", "user:create", "user:update", "user:delete",
				"session:view", "session:watch", "session:terminate",
				"recording:view", "recording:delete",
				"sshkey:view", "sshkey:create", "sshkey:delete",
				"iam:view", "iam:manage",
				"audit:view",
				"settings:view", "settings:update",
			},
		},
		{
			Name:        "developer",
			DisplayName: "Developer",
			Description: "Access to assigned hosts for development",
			Permissions: []string{
				"host:connect", "host:view",
				"session:view",
				"recording:view",
			},
		},
		{
			Name:        "ops",
			DisplayName: "Operations",
			Description: "Access to assigned hosts for operations",
			Permissions: []string{
				"host:connect", "host:view", "host:create", "host:update",
				"user:view",
				"session:view", "session:watch",
				"recording:view",
				"sshkey:view", "sshkey:create",
			},
		},
		{
			Name:        "tester",
			DisplayName: "Tester",
			Description: "Limited access for testing",
			Permissions: []string{
				"host:connect", "host:view",
				"session:view",
			},
		},
		{
			Name:        "auditor",
			DisplayName: "Auditor",
			Description: "Read-only access to logs and sessions",
			Permissions: []string{
				"host:view",
				"user:view",
				"session:view",
				"recording:view",
				"audit:view",
			},
		},
	}

	for _, r := range defaultRoles {
		// Check if role already exists.
		_, err := s.GetRoleByName(ctx, r.Name)
		if err == nil {
			continue // Role exists.
		}

		role := &Role{
			Name:        r.Name,
			DisplayName: r.DisplayName,
			Description: r.Description,
			Permissions: r.Permissions,
			IsSystem:    true,
		}
		if err := s.CreateRole(ctx, role); err != nil {
			return fmt.Errorf("failed to create default role %s: %w", r.Name, err)
		}
	}

	return nil
}
