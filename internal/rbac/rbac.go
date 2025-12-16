// Package rbac provides Role-Based Access Control (RBAC) functionality for vc-jump.
package rbac

import (
	"context"
	"errors"
	"sync"
	"time"
)

// Predefined roles.
const (
	RoleAdmin     = "admin"     // Full system access.
	RoleDeveloper = "developer" // Access to assigned hosts for development.
	RoleOps       = "ops"       // Access to assigned hosts for operations.
	RoleTester    = "tester"    // Limited access for testing.
	RoleAuditor   = "auditor"   // Read-only access to logs and sessions.
)

// Predefined permissions.
const (
	// Host permissions.
	PermHostConnect = "host:connect" // Can SSH to assigned hosts.
	PermHostView    = "host:view"    // Can view host list.
	PermHostCreate  = "host:create"  // Can create hosts.
	PermHostUpdate  = "host:update"  // Can update hosts.
	PermHostDelete  = "host:delete"  // Can delete hosts.

	// User permissions.
	PermUserView   = "user:view"   // Can view user list.
	PermUserCreate = "user:create" // Can create users.
	PermUserUpdate = "user:update" // Can update users.
	PermUserDelete = "user:delete" // Can delete users.

	// Session permissions.
	PermSessionView      = "session:view"      // Can view session history.
	PermSessionWatch     = "session:watch"     // Can watch live sessions.
	PermSessionTerminate = "session:terminate" // Can terminate sessions.

	// Recording permissions.
	PermRecordingView   = "recording:view"   // Can view recordings.
	PermRecordingDelete = "recording:delete" // Can delete recordings.

	// SSH Key permissions.
	PermSSHKeyView   = "sshkey:view"   // Can view SSH keys.
	PermSSHKeyCreate = "sshkey:create" // Can create SSH keys.
	PermSSHKeyDelete = "sshkey:delete" // Can delete SSH keys.

	// IAM permissions.
	PermIAMView   = "iam:view"   // Can view IAM settings.
	PermIAMManage = "iam:manage" // Can manage roles/permissions.

	// Audit permissions.
	PermAuditView = "audit:view" // Can view audit logs.

	// Settings permissions.
	PermSettingsView   = "settings:view"   // Can view settings.
	PermSettingsUpdate = "settings:update" // Can update settings.
)

// Role represents a role with associated permissions.
type Role struct {
	ID          string    `json:"id"`
	Name        string    `json:"name"`
	DisplayName string    `json:"display_name"`
	Description string    `json:"description"`
	Permissions []string  `json:"permissions"`
	IsSystem    bool      `json:"is_system"` // System roles cannot be deleted.
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

// UserRole represents the assignment of a role to a user.
type UserRole struct {
	ID        string    `json:"id"`
	UserID    string    `json:"user_id"`
	RoleID    string    `json:"role_id"`
	CreatedAt time.Time `json:"created_at"`
}

// HostPermission represents a user's permission to access a specific host.
type HostPermission struct {
	ID        string    `json:"id"`
	UserID    string    `json:"user_id"`
	HostID    string    `json:"host_id"`
	CanSudo   bool      `json:"can_sudo"`   // Can execute sudo commands.
	ExpiresAt time.Time `json:"expires_at"` // Zero means no expiration.
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// Store defines the interface for RBAC data persistence.
type Store interface {
	// Role operations.
	GetRole(ctx context.Context, id string) (*Role, error)
	GetRoleByName(ctx context.Context, name string) (*Role, error)
	ListRoles(ctx context.Context) ([]Role, error)
	CreateRole(ctx context.Context, role *Role) error
	UpdateRole(ctx context.Context, role *Role) error
	DeleteRole(ctx context.Context, id string) error

	// UserRole operations.
	GetUserRoles(ctx context.Context, userID string) ([]Role, error)
	AssignRole(ctx context.Context, userID, roleID string) error
	RevokeRole(ctx context.Context, userID, roleID string) error

	// HostPermission operations.
	GetHostPermissions(ctx context.Context, userID string) ([]HostPermission, error)
	GetHostPermission(ctx context.Context, userID, hostID string) (*HostPermission, error)
	GrantHostAccess(ctx context.Context, perm *HostPermission) error
	RevokeHostAccess(ctx context.Context, userID, hostID string) error
	ListUsersWithHostAccess(ctx context.Context, hostID string) ([]HostPermission, error)
}

// Manager handles RBAC operations with caching.
type Manager struct {
	store Store
	mu    sync.RWMutex
	cache *permissionCache
}

type permissionCache struct {
	userPermissions map[string][]string // userID -> permissions
	userHosts       map[string][]string // userID -> hostIDs
	ttl             time.Duration
	lastUpdate      map[string]time.Time
}

// NewManager creates a new RBAC Manager.
func NewManager(store Store) *Manager {
	return &Manager{
		store: store,
		cache: &permissionCache{
			userPermissions: make(map[string][]string),
			userHosts:       make(map[string][]string),
			ttl:             5 * time.Minute,
			lastUpdate:      make(map[string]time.Time),
		},
	}
}

// HasPermission checks if a user has a specific permission.
func (m *Manager) HasPermission(ctx context.Context, userID, permission string) (bool, error) {
	if userID == "" || permission == "" {
		return false, errors.New("userID and permission are required")
	}

	permissions, err := m.GetUserPermissions(ctx, userID)
	if err != nil {
		return false, err
	}

	for _, p := range permissions {
		if p == permission {
			return true, nil
		}
	}
	return false, nil
}

// CanAccessHost checks if a user can access a specific host.
func (m *Manager) CanAccessHost(ctx context.Context, userID, hostID string) (bool, error) {
	if userID == "" || hostID == "" {
		return false, errors.New("userID and hostID are required")
	}

	// First check if user has host:connect permission.
	hasConnect, err := m.HasPermission(ctx, userID, PermHostConnect)
	if err != nil {
		return false, err
	}
	if !hasConnect {
		return false, nil
	}

	// Check if user is admin (can access all hosts).
	isAdmin, err := m.IsAdmin(ctx, userID)
	if err != nil {
		return false, err
	}
	if isAdmin {
		return true, nil
	}

	// Check specific host permission.
	perm, err := m.store.GetHostPermission(ctx, userID, hostID)
	if err != nil {
		return false, nil // No permission found.
	}

	// Check expiration.
	if !perm.ExpiresAt.IsZero() && perm.ExpiresAt.Before(time.Now()) {
		return false, nil
	}

	return true, nil
}

// IsAdmin checks if a user has admin role.
func (m *Manager) IsAdmin(ctx context.Context, userID string) (bool, error) {
	roles, err := m.store.GetUserRoles(ctx, userID)
	if err != nil {
		return false, err
	}

	for _, role := range roles {
		if role.Name == RoleAdmin {
			return true, nil
		}
	}
	return false, nil
}

// GetUserPermissions returns all permissions for a user.
func (m *Manager) GetUserPermissions(ctx context.Context, userID string) ([]string, error) {
	// Check cache first.
	m.mu.RLock()
	if perms, ok := m.cache.userPermissions[userID]; ok {
		if lastUpdate, exists := m.cache.lastUpdate[userID]; exists {
			if time.Since(lastUpdate) < m.cache.ttl {
				m.mu.RUnlock()
				return perms, nil
			}
		}
	}
	m.mu.RUnlock()

	// Get from store.
	roles, err := m.store.GetUserRoles(ctx, userID)
	if err != nil {
		return nil, err
	}

	// Collect all permissions from roles.
	permSet := make(map[string]struct{})
	for _, role := range roles {
		for _, perm := range role.Permissions {
			permSet[perm] = struct{}{}
		}
	}

	permissions := make([]string, 0, len(permSet))
	for perm := range permSet {
		permissions = append(permissions, perm)
	}

	// Update cache.
	m.mu.Lock()
	m.cache.userPermissions[userID] = permissions
	m.cache.lastUpdate[userID] = time.Now()
	m.mu.Unlock()

	return permissions, nil
}

// GetAccessibleHosts returns all host IDs a user can access.
// Returns nil for admins (meaning all hosts).
func (m *Manager) GetAccessibleHosts(ctx context.Context, userID string) ([]string, error) {
	// Check if admin (can access all).
	isAdmin, err := m.IsAdmin(ctx, userID)
	if err != nil {
		return nil, err
	}
	if isAdmin {
		return nil, nil // nil means all hosts.
	}

	// Get specific host permissions.
	perms, err := m.store.GetHostPermissions(ctx, userID)
	if err != nil {
		return nil, err
	}

	hostIDs := make([]string, 0, len(perms))
	now := time.Now()
	for _, perm := range perms {
		// Skip expired permissions.
		if !perm.ExpiresAt.IsZero() && perm.ExpiresAt.Before(now) {
			continue
		}
		hostIDs = append(hostIDs, perm.HostID)
	}

	return hostIDs, nil
}

// InvalidateCache clears the cache for a specific user.
func (m *Manager) InvalidateCache(userID string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.cache.userPermissions, userID)
	delete(m.cache.userHosts, userID)
	delete(m.cache.lastUpdate, userID)
}

// InvalidateAllCache clears the entire cache.
func (m *Manager) InvalidateAllCache() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.cache.userPermissions = make(map[string][]string)
	m.cache.userHosts = make(map[string][]string)
	m.cache.lastUpdate = make(map[string]time.Time)
}

// DefaultRoles returns the default system roles.
func DefaultRoles() []Role {
	return []Role{
		{
			Name:        RoleAdmin,
			DisplayName: "Administrator",
			Description: "Full system access",
			Permissions: []string{
				PermHostConnect, PermHostView, PermHostCreate, PermHostUpdate, PermHostDelete,
				PermUserView, PermUserCreate, PermUserUpdate, PermUserDelete,
				PermSessionView, PermSessionWatch, PermSessionTerminate,
				PermRecordingView, PermRecordingDelete,
				PermSSHKeyView, PermSSHKeyCreate, PermSSHKeyDelete,
				PermIAMView, PermIAMManage,
				PermAuditView,
				PermSettingsView, PermSettingsUpdate,
			},
			IsSystem: true,
		},
		{
			Name:        RoleDeveloper,
			DisplayName: "Developer",
			Description: "Access to assigned hosts for development",
			Permissions: []string{
				PermHostConnect, PermHostView,
			},
			IsSystem: true,
		},
		{
			Name:        RoleOps,
			DisplayName: "Operations",
			Description: "Access to assigned hosts for operations",
			Permissions: []string{
				PermHostConnect, PermHostView, PermHostCreate, PermHostUpdate,
				PermSSHKeyView, PermSSHKeyCreate,
			},
			IsSystem: true,
		},
		{
			Name:        RoleTester,
			DisplayName: "Tester",
			Description: "Limited access for testing",
			Permissions: []string{
				PermHostConnect, PermHostView,
			},
			IsSystem: true,
		},
		{
			Name:        RoleAuditor,
			DisplayName: "Auditor",
			Description: "Read-only access to logs and sessions",
			Permissions: []string{
				PermHostView,
				PermSessionView,
				PermRecordingView,
				PermAuditView,
			},
			IsSystem: true,
		},
	}
}
