package storage

import (
	"context"
	"testing"
	"time"
)

func TestSetUserRoles_BasicReplacement(t *testing.T) {
	store := newTestSQLiteStore(t)
	ctx := context.Background()
	userID := createTestUser(t, store, "roles-user1")

	// Create two roles.
	role1 := &Role{Name: "role-a", DisplayName: "Role A", Permissions: []string{"host:view"}}
	role2 := &Role{Name: "role-b", DisplayName: "Role B", Permissions: []string{"host:connect"}}
	role3 := &Role{Name: "role-c", DisplayName: "Role C", Permissions: []string{"user:view"}}
	for _, r := range []*Role{role1, role2, role3} {
		if err := store.CreateRole(ctx, r); err != nil {
			t.Fatalf("CreateRole failed: %v", err)
		}
	}

	// Assign role1 and role2 initially.
	if err := store.AssignRole(ctx, userID, role1.ID); err != nil {
		t.Fatalf("AssignRole failed: %v", err)
	}
	if err := store.AssignRole(ctx, userID, role2.ID); err != nil {
		t.Fatalf("AssignRole failed: %v", err)
	}

	// Declaratively set to role2 and role3 (remove role1, keep role2, add role3).
	diff, err := store.SetUserRoles(ctx, userID, []string{role2.ID, role3.ID})
	if err != nil {
		t.Fatalf("SetUserRoles failed: %v", err)
	}

	// Verify diff.
	if len(diff.Added) != 1 {
		t.Errorf("expected 1 added, got %d", len(diff.Added))
	}
	if len(diff.Removed) != 1 {
		t.Errorf("expected 1 removed, got %d", len(diff.Removed))
	}

	// Verify final state.
	roles, err := store.GetUserRoles(ctx, userID)
	if err != nil {
		t.Fatalf("GetUserRoles failed: %v", err)
	}
	if len(roles) != 2 {
		t.Fatalf("expected 2 roles, got %d", len(roles))
	}

	roleNames := map[string]bool{}
	for _, r := range roles {
		roleNames[r.Name] = true
	}
	if !roleNames["role-b"] || !roleNames["role-c"] {
		t.Errorf("expected role-b and role-c, got %v", roleNames)
	}
}

func TestSetUserRoles_NoChange(t *testing.T) {
	store := newTestSQLiteStore(t)
	ctx := context.Background()
	userID := createTestUser(t, store, "roles-user2")

	role := &Role{Name: "role-x", DisplayName: "Role X", Permissions: []string{"host:view"}}
	if err := store.CreateRole(ctx, role); err != nil {
		t.Fatalf("CreateRole failed: %v", err)
	}
	if err := store.AssignRole(ctx, userID, role.ID); err != nil {
		t.Fatalf("AssignRole failed: %v", err)
	}

	// Set to the same role — should be a no-op.
	diff, err := store.SetUserRoles(ctx, userID, []string{role.ID})
	if err != nil {
		t.Fatalf("SetUserRoles failed: %v", err)
	}
	if len(diff.Added) != 0 || len(diff.Removed) != 0 {
		t.Errorf("expected no changes, got added=%d removed=%d", len(diff.Added), len(diff.Removed))
	}
}

func TestSetUserRoles_ClearAll(t *testing.T) {
	store := newTestSQLiteStore(t)
	ctx := context.Background()
	userID := createTestUser(t, store, "roles-user3")

	role := &Role{Name: "role-clear", DisplayName: "Role Clear", Permissions: []string{"host:view"}}
	if err := store.CreateRole(ctx, role); err != nil {
		t.Fatalf("CreateRole failed: %v", err)
	}
	if err := store.AssignRole(ctx, userID, role.ID); err != nil {
		t.Fatalf("AssignRole failed: %v", err)
	}

	// Set to empty — clear all roles.
	diff, err := store.SetUserRoles(ctx, userID, []string{})
	if err != nil {
		t.Fatalf("SetUserRoles failed: %v", err)
	}
	if len(diff.Removed) != 1 {
		t.Errorf("expected 1 removed, got %d", len(diff.Removed))
	}

	roles, _ := store.GetUserRoles(ctx, userID)
	if len(roles) != 0 {
		t.Errorf("expected 0 roles after clear, got %d", len(roles))
	}
}

func TestSetUserRoles_EmptyUserID(t *testing.T) {
	store := newTestSQLiteStore(t)
	ctx := context.Background()

	_, err := store.SetUserRoles(ctx, "", []string{"some-role"})
	if err == nil {
		t.Fatal("expected error for empty userID")
	}
}

func TestSetUserHostPermissions_BasicReplacement(t *testing.T) {
	store := newTestSQLiteStore(t)
	ctx := context.Background()
	userID := createTestUser(t, store, "perms-user1")

	// Create hosts.
	host1 := &Host{Name: "host-1", Addr: "10.0.0.1", Port: 22}
	host2 := &Host{Name: "host-2", Addr: "10.0.0.2", Port: 22}
	host3 := &Host{Name: "host-3", Addr: "10.0.0.3", Port: 22}
	for _, h := range []*Host{host1, host2, host3} {
		if err := store.CreateHost(ctx, h); err != nil {
			t.Fatalf("CreateHost failed: %v", err)
		}
	}

	// Grant access to host1 and host2 initially.
	if err := store.GrantHostAccess(ctx, &HostPermission{UserID: userID, HostID: host1.ID, CanSudo: false}); err != nil {
		t.Fatalf("GrantHostAccess failed: %v", err)
	}
	if err := store.GrantHostAccess(ctx, &HostPermission{UserID: userID, HostID: host2.ID, CanSudo: false}); err != nil {
		t.Fatalf("GrantHostAccess failed: %v", err)
	}

	// Declaratively set to host2 (with sudo change) and host3 (new).
	diff, err := store.SetUserHostPermissions(ctx, userID, []HostPermission{
		{UserID: userID, HostID: host2.ID, CanSudo: true},  // Updated: sudo changed.
		{UserID: userID, HostID: host3.ID, CanSudo: false}, // Added.
	})
	if err != nil {
		t.Fatalf("SetUserHostPermissions failed: %v", err)
	}

	// Verify diff.
	if len(diff.Added) != 1 {
		t.Errorf("expected 1 added, got %d: %v", len(diff.Added), diff.Added)
	}
	if len(diff.Removed) != 1 {
		t.Errorf("expected 1 removed, got %d: %v", len(diff.Removed), diff.Removed)
	}
	if len(diff.Updated) != 1 {
		t.Errorf("expected 1 updated, got %d: %v", len(diff.Updated), diff.Updated)
	}

	// Verify final state.
	perms, err := store.GetHostPermissions(ctx, userID)
	if err != nil {
		t.Fatalf("GetHostPermissions failed: %v", err)
	}
	if len(perms) != 2 {
		t.Fatalf("expected 2 permissions, got %d", len(perms))
	}

	permMap := map[string]HostPermission{}
	for _, p := range perms {
		permMap[p.HostID] = p
	}
	if !permMap[host2.ID].CanSudo {
		t.Error("expected host2 to have sudo")
	}
	if permMap[host3.ID].CanSudo {
		t.Error("expected host3 to not have sudo")
	}
}

func TestSetUserHostPermissions_ClearAll(t *testing.T) {
	store := newTestSQLiteStore(t)
	ctx := context.Background()
	userID := createTestUser(t, store, "perms-user2")

	host := &Host{Name: "host-clear", Addr: "10.0.0.1", Port: 22}
	if err := store.CreateHost(ctx, host); err != nil {
		t.Fatalf("CreateHost failed: %v", err)
	}
	if err := store.GrantHostAccess(ctx, &HostPermission{UserID: userID, HostID: host.ID}); err != nil {
		t.Fatalf("GrantHostAccess failed: %v", err)
	}

	// Set to empty — clear all permissions.
	diff, err := store.SetUserHostPermissions(ctx, userID, []HostPermission{})
	if err != nil {
		t.Fatalf("SetUserHostPermissions failed: %v", err)
	}
	if len(diff.Removed) != 1 {
		t.Errorf("expected 1 removed, got %d", len(diff.Removed))
	}

	perms, _ := store.GetHostPermissions(ctx, userID)
	if len(perms) != 0 {
		t.Errorf("expected 0 permissions after clear, got %d", len(perms))
	}
}

func TestSetUserHostPermissions_WithExpiry(t *testing.T) {
	store := newTestSQLiteStore(t)
	ctx := context.Background()
	userID := createTestUser(t, store, "perms-user3")

	host := &Host{Name: "host-expiry", Addr: "10.0.0.1", Port: 22}
	if err := store.CreateHost(ctx, host); err != nil {
		t.Fatalf("CreateHost failed: %v", err)
	}

	expires := time.Now().Add(24 * time.Hour)
	_, err := store.SetUserHostPermissions(ctx, userID, []HostPermission{
		{UserID: userID, HostID: host.ID, CanSudo: true, ExpiresAt: expires},
	})
	if err != nil {
		t.Fatalf("SetUserHostPermissions failed: %v", err)
	}

	perms, _ := store.GetHostPermissions(ctx, userID)
	if len(perms) != 1 {
		t.Fatalf("expected 1 permission, got %d", len(perms))
	}
	if perms[0].ExpiresAt.IsZero() {
		t.Error("expected ExpiresAt to be set")
	}
	if !perms[0].CanSudo {
		t.Error("expected CanSudo to be true")
	}
}

func TestSetUserHostPermissions_EmptyUserID(t *testing.T) {
	store := newTestSQLiteStore(t)
	ctx := context.Background()

	_, err := store.SetUserHostPermissions(ctx, "", []HostPermission{})
	if err == nil {
		t.Fatal("expected error for empty userID")
	}
}
