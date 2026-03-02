package storage

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
)

// RBAC Role operations.

// GetRole retrieves a role by ID.
func (s *SQLiteStore) GetRole(ctx context.Context, id string) (*Role, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var role Role
	var permissionsJSON string
	var description sql.NullString

	err := s.db.QueryRowContext(ctx,
		"SELECT id, name, display_name, description, permissions, is_system, created_at, updated_at FROM roles WHERE id = ?",
		id,
	).Scan(&role.ID, &role.Name, &role.DisplayName, &description, &permissionsJSON, &role.IsSystem, &role.CreatedAt, &role.UpdatedAt)
	if err == sql.ErrNoRows {
		return nil, errors.New("role not found")
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get role: %w", err)
	}

	if description.Valid {
		role.Description = description.String
	}
	if err := json.Unmarshal([]byte(permissionsJSON), &role.Permissions); err != nil {
		role.Permissions = []string{}
	}

	return &role, nil
}

// GetRoleByName retrieves a role by name.
func (s *SQLiteStore) GetRoleByName(ctx context.Context, name string) (*Role, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var role Role
	var permissionsJSON string
	var description sql.NullString

	err := s.db.QueryRowContext(ctx,
		"SELECT id, name, display_name, description, permissions, is_system, created_at, updated_at FROM roles WHERE name = ?",
		name,
	).Scan(&role.ID, &role.Name, &role.DisplayName, &description, &permissionsJSON, &role.IsSystem, &role.CreatedAt, &role.UpdatedAt)
	if err == sql.ErrNoRows {
		return nil, errors.New("role not found")
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get role: %w", err)
	}

	if description.Valid {
		role.Description = description.String
	}
	if err := json.Unmarshal([]byte(permissionsJSON), &role.Permissions); err != nil {
		role.Permissions = []string{}
	}

	return &role, nil
}

// ListRoles lists all roles.
func (s *SQLiteStore) ListRoles(ctx context.Context) ([]Role, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	rows, err := s.db.QueryContext(ctx,
		"SELECT id, name, display_name, description, permissions, is_system, created_at, updated_at FROM roles ORDER BY name",
	)
	if err != nil {
		return nil, fmt.Errorf("failed to list roles: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var roles []Role
	for rows.Next() {
		var role Role
		var permissionsJSON string
		var description sql.NullString

		if err := rows.Scan(&role.ID, &role.Name, &role.DisplayName, &description, &permissionsJSON, &role.IsSystem, &role.CreatedAt, &role.UpdatedAt); err != nil {
			return nil, fmt.Errorf("failed to scan role: %w", err)
		}

		if description.Valid {
			role.Description = description.String
		}
		if err := json.Unmarshal([]byte(permissionsJSON), &role.Permissions); err != nil {
			role.Permissions = []string{}
		}
		roles = append(roles, role)
	}

	return roles, rows.Err()
}

// CreateRole creates a new role.
func (s *SQLiteStore) CreateRole(ctx context.Context, role *Role) error {
	if role.Name == "" {
		return errors.New("role name is required")
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if role.ID == "" {
		role.ID = generateID()
	}
	role.CreatedAt = time.Now()
	role.UpdatedAt = role.CreatedAt

	permissionsJSON, err := json.Marshal(role.Permissions)
	if err != nil {
		return fmt.Errorf("failed to marshal permissions: %w", err)
	}

	_, err = s.db.ExecContext(ctx,
		`INSERT INTO roles (id, name, display_name, description, permissions, is_system, created_at, updated_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		role.ID, role.Name, role.DisplayName, role.Description, string(permissionsJSON), role.IsSystem, role.CreatedAt, role.UpdatedAt,
	)
	if err != nil {
		if strings.Contains(err.Error(), "UNIQUE constraint failed") {
			return errors.New("role with this name already exists")
		}
		return fmt.Errorf("failed to create role: %w", err)
	}

	return nil
}

// UpdateRole updates an existing role.
func (s *SQLiteStore) UpdateRole(ctx context.Context, role *Role) error {
	if role.ID == "" {
		return errors.New("role ID is required")
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	role.UpdatedAt = time.Now()

	permissionsJSON, err := json.Marshal(role.Permissions)
	if err != nil {
		return fmt.Errorf("failed to marshal permissions: %w", err)
	}

	result, err := s.db.ExecContext(ctx,
		`UPDATE roles SET name = ?, display_name = ?, description = ?, permissions = ?, updated_at = ? WHERE id = ?`,
		role.Name, role.DisplayName, role.Description, string(permissionsJSON), role.UpdatedAt, role.ID,
	)
	if err != nil {
		return fmt.Errorf("failed to update role: %w", err)
	}

	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		return errors.New("role not found")
	}

	return nil
}

// DeleteRole deletes a role by ID.
func (s *SQLiteStore) DeleteRole(ctx context.Context, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Check if it's a system role.
	var isSystem bool
	err := s.db.QueryRowContext(ctx, "SELECT is_system FROM roles WHERE id = ?", id).Scan(&isSystem)
	if err == sql.ErrNoRows {
		return errors.New("role not found")
	}
	if err != nil {
		return fmt.Errorf("failed to check role: %w", err)
	}
	if isSystem {
		return errors.New("cannot delete system role")
	}

	_, err = s.db.ExecContext(ctx, "DELETE FROM roles WHERE id = ?", id)
	if err != nil {
		return fmt.Errorf("failed to delete role: %w", err)
	}

	return nil
}

// User-Role operations.

// GetUserRoles returns all roles assigned to a user.
func (s *SQLiteStore) GetUserRoles(ctx context.Context, userID string) ([]Role, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	rows, err := s.db.QueryContext(ctx,
		`SELECT r.id, r.name, r.display_name, r.description, r.permissions, r.is_system, r.created_at, r.updated_at
		 FROM roles r
		 INNER JOIN user_roles ur ON r.id = ur.role_id
		 WHERE ur.user_id = ?
		 ORDER BY r.name`,
		userID,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to get user roles: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var roles []Role
	for rows.Next() {
		var role Role
		var permissionsJSON string
		var description sql.NullString

		if err := rows.Scan(&role.ID, &role.Name, &role.DisplayName, &description, &permissionsJSON, &role.IsSystem, &role.CreatedAt, &role.UpdatedAt); err != nil {
			return nil, fmt.Errorf("failed to scan role: %w", err)
		}

		if description.Valid {
			role.Description = description.String
		}
		if err := json.Unmarshal([]byte(permissionsJSON), &role.Permissions); err != nil {
			role.Permissions = []string{}
		}
		roles = append(roles, role)
	}

	return roles, rows.Err()
}

// AssignRole assigns a role to a user.
func (s *SQLiteStore) AssignRole(ctx context.Context, userID, roleID string) error {
	if userID == "" || roleID == "" {
		return errors.New("userID and roleID are required")
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	id := generateID()
	_, err := s.db.ExecContext(ctx,
		"INSERT OR IGNORE INTO user_roles (id, user_id, role_id, created_at) VALUES (?, ?, ?, ?)",
		id, userID, roleID, time.Now(),
	)
	if err != nil {
		return fmt.Errorf("failed to assign role: %w", err)
	}

	return nil
}

// RevokeRole removes a role from a user.
func (s *SQLiteStore) RevokeRole(ctx context.Context, userID, roleID string) error {
	if userID == "" || roleID == "" {
		return errors.New("userID and roleID are required")
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	_, err := s.db.ExecContext(ctx,
		"DELETE FROM user_roles WHERE user_id = ? AND role_id = ?",
		userID, roleID,
	)
	if err != nil {
		return fmt.Errorf("failed to revoke role: %w", err)
	}

	return nil
}

// RoleDiff describes the changes made by a declarative role set operation.
type RoleDiff struct {
	Added   []string // Role IDs that were newly assigned.
	Removed []string // Role IDs that were removed.
}

// SetUserRoles declaratively sets the complete list of roles for a user,
// replacing any existing role assignments. This is transactional — either
// all changes apply or none do. Returns the diff of what changed.
func (s *SQLiteStore) SetUserRoles(ctx context.Context, userID string, roleIDs []string) (*RoleDiff, error) {
	if userID == "" {
		return nil, errors.New("userID is required")
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	// Get current roles (within the lock, no separate mu needed).
	currentRoles, err := s.getUserRoleIDsLocked(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("failed to get current roles: %w", err)
	}

	// Compute diff.
	currentSet := toStringSet(currentRoles)
	desiredSet := toStringSet(roleIDs)
	diff := &RoleDiff{}
	for id := range desiredSet {
		if !currentSet[id] {
			diff.Added = append(diff.Added, id)
		}
	}
	for id := range currentSet {
		if !desiredSet[id] {
			diff.Removed = append(diff.Removed, id)
		}
	}

	// If nothing changed, return early.
	if len(diff.Added) == 0 && len(diff.Removed) == 0 {
		return diff, nil
	}

	// Execute in a transaction.
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	// Delete all existing role assignments.
	_, err = tx.ExecContext(ctx, "DELETE FROM user_roles WHERE user_id = ?", userID)
	if err != nil {
		return nil, fmt.Errorf("failed to clear user roles: %w", err)
	}

	// Insert the desired roles.
	now := time.Now()
	for _, roleID := range roleIDs {
		id := uuid.New().String()
		_, err = tx.ExecContext(ctx,
			"INSERT INTO user_roles (id, user_id, role_id, created_at) VALUES (?, ?, ?, ?)",
			id, userID, roleID, now,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to assign role %s: %w", roleID, err)
		}
	}

	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("failed to commit role changes: %w", err)
	}

	return diff, nil
}

// getUserRoleIDsLocked returns role IDs for a user. Must be called with s.mu held.
func (s *SQLiteStore) getUserRoleIDsLocked(ctx context.Context, userID string) ([]string, error) {
	rows, err := s.db.QueryContext(ctx,
		"SELECT role_id FROM user_roles WHERE user_id = ?", userID,
	)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()

	var ids []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		ids = append(ids, id)
	}
	return ids, rows.Err()
}

// HostPermissionDiff describes the changes made by a declarative permission set operation.
type HostPermissionDiff struct {
	Added   []string // Host IDs that were newly granted.
	Removed []string // Host IDs whose permissions were removed.
	Updated []string // Host IDs whose permissions were modified (e.g. sudo changed).
}

// SetUserHostPermissions declaratively sets the complete list of host permissions
// for a user, replacing any existing permissions. This is transactional.
func (s *SQLiteStore) SetUserHostPermissions(ctx context.Context, userID string, perms []HostPermission) (*HostPermissionDiff, error) {
	if userID == "" {
		return nil, errors.New("userID is required")
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	// Get current permissions (within lock).
	currentPerms, err := s.getUserHostPermissionsLocked(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("failed to get current permissions: %w", err)
	}

	// Build maps for diff computation.
	currentMap := make(map[string]HostPermission)
	for _, p := range currentPerms {
		currentMap[p.HostID] = p
	}
	desiredMap := make(map[string]HostPermission)
	for _, p := range perms {
		desiredMap[p.HostID] = p
	}

	diff := &HostPermissionDiff{}
	for hostID := range desiredMap {
		if _, exists := currentMap[hostID]; !exists {
			diff.Added = append(diff.Added, hostID)
		} else {
			// Check if properties changed.
			cur := currentMap[hostID]
			des := desiredMap[hostID]
			if cur.CanSudo != des.CanSudo || !cur.ExpiresAt.Equal(des.ExpiresAt) {
				diff.Updated = append(diff.Updated, hostID)
			}
		}
	}
	for hostID := range currentMap {
		if _, exists := desiredMap[hostID]; !exists {
			diff.Removed = append(diff.Removed, hostID)
		}
	}

	// If nothing changed, return early.
	if len(diff.Added) == 0 && len(diff.Removed) == 0 && len(diff.Updated) == 0 {
		return diff, nil
	}

	// Execute in a transaction.
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	// Delete all existing permissions for this user.
	_, err = tx.ExecContext(ctx, "DELETE FROM host_permissions WHERE user_id = ?", userID)
	if err != nil {
		return nil, fmt.Errorf("failed to clear host permissions: %w", err)
	}

	// Insert the desired permissions.
	now := time.Now()
	for _, perm := range perms {
		id := uuid.New().String()
		var expiresAt interface{}
		if !perm.ExpiresAt.IsZero() {
			expiresAt = perm.ExpiresAt
		}

		_, err = tx.ExecContext(ctx,
			`INSERT INTO host_permissions (id, user_id, host_id, can_sudo, expires_at, created_at, updated_at)
			 VALUES (?, ?, ?, ?, ?, ?, ?)`,
			id, userID, perm.HostID, perm.CanSudo, expiresAt, now, now,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to grant permission for host %s: %w", perm.HostID, err)
		}
	}

	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("failed to commit permission changes: %w", err)
	}

	return diff, nil
}

// getUserHostPermissionsLocked returns permissions for a user. Must be called with s.mu held.
func (s *SQLiteStore) getUserHostPermissionsLocked(ctx context.Context, userID string) ([]HostPermission, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT id, user_id, host_id, can_sudo, expires_at, created_at, updated_at
		 FROM host_permissions WHERE user_id = ?`, userID,
	)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()

	var perms []HostPermission
	for rows.Next() {
		var p HostPermission
		var expiresAt sql.NullTime
		if err := rows.Scan(&p.ID, &p.UserID, &p.HostID, &p.CanSudo, &expiresAt, &p.CreatedAt, &p.UpdatedAt); err != nil {
			return nil, err
		}
		if expiresAt.Valid {
			p.ExpiresAt = expiresAt.Time
		}
		perms = append(perms, p)
	}
	return perms, rows.Err()
}

// toStringSet converts a slice to a set (map) for efficient lookup.
func toStringSet(items []string) map[string]bool {
	set := make(map[string]bool, len(items))
	for _, item := range items {
		set[item] = true
	}
	return set
}
