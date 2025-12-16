// Package rbac provides Role-Based Access Control functionality.
package rbac

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"
)

// mockStore implements the Store interface for testing.
type mockStore struct {
	mu              sync.RWMutex
	roles           map[string]*Role
	rolesByName     map[string]*Role
	userRoles       map[string][]Role
	hostPermissions map[string][]HostPermission
}

func newMockStore() *mockStore {
	return &mockStore{
		roles:           make(map[string]*Role),
		rolesByName:     make(map[string]*Role),
		userRoles:       make(map[string][]Role),
		hostPermissions: make(map[string][]HostPermission),
	}
}

func (m *mockStore) GetRole(_ context.Context, id string) (*Role, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if role, ok := m.roles[id]; ok {
		return role, nil
	}
	return nil, errors.New("role not found")
}

func (m *mockStore) GetRoleByName(_ context.Context, name string) (*Role, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if role, ok := m.rolesByName[name]; ok {
		return role, nil
	}
	return nil, errors.New("role not found")
}

func (m *mockStore) ListRoles(_ context.Context) ([]Role, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	roles := make([]Role, 0, len(m.roles))
	for _, r := range m.roles {
		roles = append(roles, *r)
	}
	return roles, nil
}

func (m *mockStore) CreateRole(_ context.Context, role *Role) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.roles[role.ID] = role
	m.rolesByName[role.Name] = role
	return nil
}

func (m *mockStore) UpdateRole(_ context.Context, role *Role) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.roles[role.ID] = role
	m.rolesByName[role.Name] = role
	return nil
}

func (m *mockStore) DeleteRole(_ context.Context, id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if role, ok := m.roles[id]; ok {
		delete(m.rolesByName, role.Name)
	}
	delete(m.roles, id)
	return nil
}

func (m *mockStore) GetUserRoles(_ context.Context, userID string) ([]Role, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if roles, ok := m.userRoles[userID]; ok {
		return roles, nil
	}
	return []Role{}, nil
}

func (m *mockStore) AssignRole(_ context.Context, userID, roleID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	role, ok := m.roles[roleID]
	if !ok {
		return errors.New("role not found")
	}
	m.userRoles[userID] = append(m.userRoles[userID], *role)
	return nil
}

func (m *mockStore) RevokeRole(_ context.Context, userID, roleID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	roles := m.userRoles[userID]
	newRoles := make([]Role, 0, len(roles))
	for _, r := range roles {
		if r.ID != roleID {
			newRoles = append(newRoles, r)
		}
	}
	m.userRoles[userID] = newRoles
	return nil
}

func (m *mockStore) GetHostPermissions(_ context.Context, userID string) ([]HostPermission, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if perms, ok := m.hostPermissions[userID]; ok {
		return perms, nil
	}
	return []HostPermission{}, nil
}

func (m *mockStore) GetHostPermission(_ context.Context, userID, hostID string) (*HostPermission, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	perms, ok := m.hostPermissions[userID]
	if !ok {
		return nil, errors.New("no permissions")
	}
	for _, p := range perms {
		if p.HostID == hostID {
			return &p, nil
		}
	}
	return nil, errors.New("permission not found")
}

func (m *mockStore) GrantHostAccess(_ context.Context, perm *HostPermission) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.hostPermissions[perm.UserID] = append(m.hostPermissions[perm.UserID], *perm)
	return nil
}

func (m *mockStore) RevokeHostAccess(_ context.Context, userID, hostID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	perms := m.hostPermissions[userID]
	newPerms := make([]HostPermission, 0, len(perms))
	for _, p := range perms {
		if p.HostID != hostID {
			newPerms = append(newPerms, p)
		}
	}
	m.hostPermissions[userID] = newPerms
	return nil
}

func (m *mockStore) ListUsersWithHostAccess(_ context.Context, hostID string) ([]HostPermission, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	var result []HostPermission
	for _, perms := range m.hostPermissions {
		for _, p := range perms {
			if p.HostID == hostID {
				result = append(result, p)
			}
		}
	}
	return result, nil
}

// TestNewManager verifies Manager initialization.
func TestNewManager(t *testing.T) {
	store := newMockStore()
	m := NewManager(store)
	if m == nil {
		t.Fatal("NewManager() returned nil")
	}
	if m.store == nil {
		t.Error("store not set")
	}
	if m.cache == nil {
		t.Error("cache not initialized")
	}
}

// TestDefaultRoles verifies that default roles are correctly defined.
func TestDefaultRoles(t *testing.T) {
	roles := DefaultRoles()

	expectedNames := []string{
		RoleAdmin,
		RoleDeveloper,
		RoleOps,
		RoleTester,
		RoleAuditor,
	}

	if len(roles) != len(expectedNames) {
		t.Fatalf("expected %d roles, got %d", len(expectedNames), len(roles))
	}

	nameSet := make(map[string]bool)
	for _, r := range roles {
		nameSet[r.Name] = true
		if !r.IsSystem {
			t.Errorf("default role %q should be marked as system role", r.Name)
		}
		if len(r.Permissions) == 0 {
			t.Errorf("role %q has no permissions", r.Name)
		}
	}

	for _, name := range expectedNames {
		if !nameSet[name] {
			t.Errorf("expected role %q not found", name)
		}
	}
}

// TestAdminRoleHasAllPermissions verifies admin role has all permissions.
func TestAdminRoleHasAllPermissions(t *testing.T) {
	roles := DefaultRoles()
	var adminRole *Role
	for i, r := range roles {
		if r.Name == RoleAdmin {
			adminRole = &roles[i]
			break
		}
	}

	if adminRole == nil {
		t.Fatal("admin role not found")
	}

	requiredPerms := []string{
		PermHostConnect, PermHostView, PermHostCreate, PermHostUpdate, PermHostDelete,
		PermUserView, PermUserCreate, PermUserUpdate, PermUserDelete,
		PermSessionView, PermSessionWatch, PermSessionTerminate,
		PermRecordingView, PermRecordingDelete,
		PermSSHKeyView, PermSSHKeyCreate, PermSSHKeyDelete,
		PermIAMView, PermIAMManage,
		PermAuditView,
		PermSettingsView, PermSettingsUpdate,
	}

	permSet := make(map[string]bool)
	for _, p := range adminRole.Permissions {
		permSet[p] = true
	}

	for _, perm := range requiredPerms {
		if !permSet[perm] {
			t.Errorf("admin role missing permission: %s", perm)
		}
	}
}

// TestHasPermission verifies permission checking.
func TestHasPermission(t *testing.T) {
	store := newMockStore()
	m := NewManager(store)
	ctx := context.Background()

	role := &Role{
		ID:          "role-dev",
		Name:        "developer",
		Permissions: []string{PermHostView, PermHostConnect, PermSessionView},
	}
	if err := store.CreateRole(ctx, role); err != nil {
		t.Fatal(err)
	}
	if err := store.AssignRole(ctx, "user-dev", "role-dev"); err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		userID     string
		permission string
		expected   bool
	}{
		{"user-dev", PermHostView, true},
		{"user-dev", PermHostConnect, true},
		{"user-dev", PermSessionView, true},
		{"user-dev", PermHostCreate, false},
		{"user-dev", PermIAMManage, false},
		{"unknown-user", PermHostView, false},
	}

	for _, tc := range tests {
		result, err := m.HasPermission(ctx, tc.userID, tc.permission)
		if err != nil {
			t.Errorf("HasPermission(%q, %q) error: %v", tc.userID, tc.permission, err)
			continue
		}
		if result != tc.expected {
			t.Errorf("HasPermission(%q, %q) = %v, want %v",
				tc.userID, tc.permission, result, tc.expected)
		}
	}
}

// TestHasPermissionEmptyParams verifies error handling for empty parameters.
func TestHasPermissionEmptyParams(t *testing.T) {
	store := newMockStore()
	m := NewManager(store)
	ctx := context.Background()

	_, err := m.HasPermission(ctx, "", "perm")
	if err == nil {
		t.Error("expected error for empty userID")
	}

	_, err = m.HasPermission(ctx, "user", "")
	if err == nil {
		t.Error("expected error for empty permission")
	}
}

// TestHasPermissionMultipleRoles verifies permission with multiple roles.
func TestHasPermissionMultipleRoles(t *testing.T) {
	store := newMockStore()
	m := NewManager(store)
	ctx := context.Background()

	role1 := &Role{
		ID:          "role-1",
		Name:        "viewer",
		Permissions: []string{PermHostView, PermUserView},
	}
	role2 := &Role{
		ID:          "role-2",
		Name:        "connector",
		Permissions: []string{PermHostConnect},
	}
	_ = store.CreateRole(ctx, role1)
	_ = store.CreateRole(ctx, role2)
	_ = store.AssignRole(ctx, "multi-user", "role-1")
	_ = store.AssignRole(ctx, "multi-user", "role-2")

	// User should have permissions from both roles.
	has, _ := m.HasPermission(ctx, "multi-user", PermHostView)
	if !has {
		t.Error("expected PermHostView from role-1")
	}
	has, _ = m.HasPermission(ctx, "multi-user", PermHostConnect)
	if !has {
		t.Error("expected PermHostConnect from role-2")
	}
	has, _ = m.HasPermission(ctx, "multi-user", PermUserView)
	if !has {
		t.Error("expected PermUserView from role-1")
	}
}

// TestCanAccessHost verifies host access checking.
func TestCanAccessHost(t *testing.T) {
	store := newMockStore()
	m := NewManager(store)
	ctx := context.Background()

	// Create role with connect permission.
	role := &Role{
		ID:          "role-conn",
		Name:        "connector",
		Permissions: []string{PermHostConnect},
	}
	_ = store.CreateRole(ctx, role)
	_ = store.AssignRole(ctx, "user-1", "role-conn")

	// Grant access to specific host.
	perm := &HostPermission{
		ID:     "hp-1",
		UserID: "user-1",
		HostID: "host-1",
	}
	_ = store.GrantHostAccess(ctx, perm)

	tests := []struct {
		userID   string
		hostID   string
		expected bool
	}{
		{"user-1", "host-1", true},
		{"user-1", "host-2", false},
		{"user-2", "host-1", false},
	}

	for _, tc := range tests {
		result, _ := m.CanAccessHost(ctx, tc.userID, tc.hostID)
		if result != tc.expected {
			t.Errorf("CanAccessHost(%q, %q) = %v, want %v",
				tc.userID, tc.hostID, result, tc.expected)
		}
	}
}

// TestCanAccessHostEmptyParams verifies error handling for empty parameters.
func TestCanAccessHostEmptyParams(t *testing.T) {
	store := newMockStore()
	m := NewManager(store)
	ctx := context.Background()

	_, err := m.CanAccessHost(ctx, "", "host")
	if err == nil {
		t.Error("expected error for empty userID")
	}

	_, err = m.CanAccessHost(ctx, "user", "")
	if err == nil {
		t.Error("expected error for empty hostID")
	}
}

// TestCanAccessHostExpired verifies expired permissions are rejected.
func TestCanAccessHostExpired(t *testing.T) {
	store := newMockStore()
	m := NewManager(store)
	ctx := context.Background()

	role := &Role{
		ID:          "role-conn",
		Name:        "connector",
		Permissions: []string{PermHostConnect},
	}
	_ = store.CreateRole(ctx, role)
	_ = store.AssignRole(ctx, "user-1", "role-conn")

	expiredTime := time.Now().Add(-1 * time.Hour)
	perm := &HostPermission{
		ID:        "hp-expired",
		UserID:    "user-1",
		HostID:    "host-1",
		ExpiresAt: expiredTime,
	}
	_ = store.GrantHostAccess(ctx, perm)

	can, _ := m.CanAccessHost(ctx, "user-1", "host-1")
	if can {
		t.Error("expired permission should be rejected")
	}
}

// TestCanAccessHostNotExpired verifies non-expired permissions are accepted.
func TestCanAccessHostNotExpired(t *testing.T) {
	store := newMockStore()
	m := NewManager(store)
	ctx := context.Background()

	role := &Role{
		ID:          "role-conn",
		Name:        "connector",
		Permissions: []string{PermHostConnect},
	}
	_ = store.CreateRole(ctx, role)
	_ = store.AssignRole(ctx, "user-1", "role-conn")

	futureTime := time.Now().Add(24 * time.Hour)
	perm := &HostPermission{
		ID:        "hp-future",
		UserID:    "user-1",
		HostID:    "host-1",
		ExpiresAt: futureTime,
	}
	_ = store.GrantHostAccess(ctx, perm)

	can, _ := m.CanAccessHost(ctx, "user-1", "host-1")
	if !can {
		t.Error("non-expired permission should be accepted")
	}
}

// TestIsAdmin verifies admin role detection.
func TestIsAdmin(t *testing.T) {
	store := newMockStore()
	m := NewManager(store)
	ctx := context.Background()

	adminRole := &Role{
		ID:          "role-admin",
		Name:        RoleAdmin,
		Permissions: []string{PermHostConnect, PermIAMManage},
	}
	devRole := &Role{
		ID:          "role-dev",
		Name:        RoleDeveloper,
		Permissions: []string{PermHostConnect},
	}
	_ = store.CreateRole(ctx, adminRole)
	_ = store.CreateRole(ctx, devRole)
	_ = store.AssignRole(ctx, "admin-user", "role-admin")
	_ = store.AssignRole(ctx, "dev-user", "role-dev")

	isAdmin, _ := m.IsAdmin(ctx, "admin-user")
	if !isAdmin {
		t.Error("expected admin-user to be admin")
	}

	isAdmin, _ = m.IsAdmin(ctx, "dev-user")
	if isAdmin {
		t.Error("expected dev-user to not be admin")
	}

	isAdmin, _ = m.IsAdmin(ctx, "unknown-user")
	if isAdmin {
		t.Error("expected unknown-user to not be admin")
	}
}

// TestAdminCanAccessAllHosts verifies admin can access all hosts.
func TestAdminCanAccessAllHosts(t *testing.T) {
	store := newMockStore()
	m := NewManager(store)
	ctx := context.Background()

	adminRole := &Role{
		ID:          "role-admin",
		Name:        RoleAdmin,
		Permissions: []string{PermHostConnect},
	}
	_ = store.CreateRole(ctx, adminRole)
	_ = store.AssignRole(ctx, "admin-user", "role-admin")

	// Admin should be able to access any host without explicit permission.
	can, _ := m.CanAccessHost(ctx, "admin-user", "any-host-id")
	if !can {
		t.Error("admin should be able to access any host")
	}
}

// TestGetUserPermissions verifies aggregated permission retrieval.
func TestGetUserPermissions(t *testing.T) {
	store := newMockStore()
	m := NewManager(store)
	ctx := context.Background()

	role1 := &Role{
		ID:          "role-1",
		Name:        "viewer",
		Permissions: []string{PermHostView, PermUserView},
	}
	role2 := &Role{
		ID:          "role-2",
		Name:        "manager",
		Permissions: []string{PermHostView, PermHostCreate}, // PermHostView duplicated
	}
	_ = store.CreateRole(ctx, role1)
	_ = store.CreateRole(ctx, role2)
	_ = store.AssignRole(ctx, "user-1", "role-1")
	_ = store.AssignRole(ctx, "user-1", "role-2")

	perms, err := m.GetUserPermissions(ctx, "user-1")
	if err != nil {
		t.Fatal(err)
	}

	// Should have unique permissions only.
	expected := map[string]bool{
		PermHostView:   true,
		PermHostCreate: true,
		PermUserView:   true,
	}

	if len(perms) != len(expected) {
		t.Errorf("expected %d permissions, got %d", len(expected), len(perms))
	}

	for _, p := range perms {
		if !expected[p] {
			t.Errorf("unexpected permission: %s", p)
		}
	}
}

// TestGetUserPermissionsNoRoles verifies empty permissions for users without roles.
func TestGetUserPermissionsNoRoles(t *testing.T) {
	store := newMockStore()
	m := NewManager(store)
	ctx := context.Background()

	perms, err := m.GetUserPermissions(ctx, "no-roles-user")
	if err != nil {
		t.Fatal(err)
	}

	if len(perms) != 0 {
		t.Errorf("expected 0 permissions, got %d", len(perms))
	}
}

// TestGetAccessibleHosts verifies accessible host retrieval.
func TestGetAccessibleHosts(t *testing.T) {
	store := newMockStore()
	m := NewManager(store)
	ctx := context.Background()

	role := &Role{
		ID:          "role-conn",
		Name:        "connector",
		Permissions: []string{PermHostConnect},
	}
	_ = store.CreateRole(ctx, role)
	_ = store.AssignRole(ctx, "user-1", "role-conn")

	// Grant access to multiple hosts.
	_ = store.GrantHostAccess(ctx, &HostPermission{ID: "hp-1", UserID: "user-1", HostID: "host-1"})
	_ = store.GrantHostAccess(ctx, &HostPermission{ID: "hp-2", UserID: "user-1", HostID: "host-2"})

	hosts, err := m.GetAccessibleHosts(ctx, "user-1")
	if err != nil {
		t.Fatal(err)
	}

	if len(hosts) != 2 {
		t.Errorf("expected 2 hosts, got %d", len(hosts))
	}
}

// TestGetAccessibleHostsAdmin verifies admin gets nil (all hosts).
func TestGetAccessibleHostsAdmin(t *testing.T) {
	store := newMockStore()
	m := NewManager(store)
	ctx := context.Background()

	adminRole := &Role{
		ID:          "role-admin",
		Name:        RoleAdmin,
		Permissions: []string{PermHostConnect},
	}
	_ = store.CreateRole(ctx, adminRole)
	_ = store.AssignRole(ctx, "admin-user", "role-admin")

	hosts, err := m.GetAccessibleHosts(ctx, "admin-user")
	if err != nil {
		t.Fatal(err)
	}

	if hosts != nil {
		t.Error("expected nil (all hosts) for admin")
	}
}

// TestInvalidateCache verifies cache invalidation for a user.
func TestInvalidateCache(t *testing.T) {
	store := newMockStore()
	m := NewManager(store)
	ctx := context.Background()

	role := &Role{
		ID:          "role-1",
		Name:        "test",
		Permissions: []string{PermHostView},
	}
	_ = store.CreateRole(ctx, role)
	_ = store.AssignRole(ctx, "user-1", "role-1")

	// Populate cache.
	_, _ = m.GetUserPermissions(ctx, "user-1")

	// Verify cache is populated.
	m.mu.RLock()
	_, exists := m.cache.userPermissions["user-1"]
	m.mu.RUnlock()
	if !exists {
		t.Fatal("cache should be populated")
	}

	// Invalidate cache.
	m.InvalidateCache("user-1")

	// Verify cache is cleared.
	m.mu.RLock()
	_, exists = m.cache.userPermissions["user-1"]
	m.mu.RUnlock()
	if exists {
		t.Error("cache should be cleared")
	}
}

// TestInvalidateAllCache verifies full cache invalidation.
func TestInvalidateAllCache(t *testing.T) {
	store := newMockStore()
	m := NewManager(store)
	ctx := context.Background()

	role := &Role{
		ID:          "role-1",
		Name:        "test",
		Permissions: []string{PermHostView},
	}
	_ = store.CreateRole(ctx, role)
	_ = store.AssignRole(ctx, "user-1", "role-1")
	_ = store.AssignRole(ctx, "user-2", "role-1")

	// Populate cache for multiple users.
	_, _ = m.GetUserPermissions(ctx, "user-1")
	_, _ = m.GetUserPermissions(ctx, "user-2")

	// Invalidate all cache.
	m.InvalidateAllCache()

	// Verify all cache is cleared.
	m.mu.RLock()
	if len(m.cache.userPermissions) != 0 {
		t.Error("cache.userPermissions should be empty")
	}
	if len(m.cache.lastUpdate) != 0 {
		t.Error("cache.lastUpdate should be empty")
	}
	m.mu.RUnlock()
}

// TestPermissionConstants verifies all permission constants are unique.
func TestPermissionConstants(t *testing.T) {
	perms := []string{
		PermHostView, PermHostCreate, PermHostUpdate, PermHostDelete, PermHostConnect,
		PermUserView, PermUserCreate, PermUserUpdate, PermUserDelete,
		PermSessionView, PermSessionWatch, PermSessionTerminate,
		PermRecordingView, PermRecordingDelete,
		PermSSHKeyView, PermSSHKeyCreate, PermSSHKeyDelete,
		PermIAMView, PermIAMManage,
		PermAuditView,
		PermSettingsView, PermSettingsUpdate,
	}

	seen := make(map[string]bool)
	for _, p := range perms {
		if seen[p] {
			t.Errorf("duplicate permission constant: %s", p)
		}
		seen[p] = true
	}
}

// TestRoleConstantValues verifies role constant values.
func TestRoleConstantValues(t *testing.T) {
	tests := []struct {
		constant string
		value    string
	}{
		{RoleAdmin, "admin"},
		{RoleDeveloper, "developer"},
		{RoleOps, "ops"},
		{RoleTester, "tester"},
		{RoleAuditor, "auditor"},
	}

	for _, tc := range tests {
		if tc.constant != tc.value {
			t.Errorf("role constant %q has unexpected value %q", tc.value, tc.constant)
		}
	}
}

// TestCacheExpiration verifies cache TTL behavior.
func TestCacheExpiration(t *testing.T) {
	store := newMockStore()
	m := NewManager(store)
	ctx := context.Background()

	// Set very short TTL for testing.
	m.cache.ttl = 1 * time.Millisecond

	role := &Role{
		ID:          "role-1",
		Name:        "test",
		Permissions: []string{PermHostView},
	}
	_ = store.CreateRole(ctx, role)
	_ = store.AssignRole(ctx, "user-1", "role-1")

	// First call should populate cache.
	_, _ = m.GetUserPermissions(ctx, "user-1")

	// Wait for TTL to expire.
	time.Sleep(5 * time.Millisecond)

	// Next call should refresh from store due to expired cache.
	// Add a new permission to the role.
	role.Permissions = []string{PermHostView, PermHostConnect}
	_ = store.UpdateRole(ctx, role)
	// Need to refresh userRoles as mock store returns copied roles
	store.userRoles["user-1"] = []Role{*role}

	perms, _ := m.GetUserPermissions(ctx, "user-1")

	// Should have the updated permissions.
	hasConnect := false
	for _, p := range perms {
		if p == PermHostConnect {
			hasConnect = true
			break
		}
	}
	if !hasConnect {
		t.Error("expected refreshed permissions from store after cache expiration")
	}
}

