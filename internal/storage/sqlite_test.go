package storage

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/Veritas-Calculus/vc-jump/internal/config"
)

func TestNewSQLiteStore(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "test.db")

	cfg := config.StorageConfig{
		Type:   "sqlite",
		DBPath: dbPath,
	}

	store, err := NewSQLiteStore(cfg)
	if err != nil {
		t.Fatalf("failed to create SQLite store: %v", err)
	}
	defer store.Close()

	if store.db == nil {
		t.Error("expected db to be initialized")
	}
}

func TestNewSQLiteStore_EmptyPath(t *testing.T) {
	cfg := config.StorageConfig{
		Type:   "sqlite",
		DBPath: "",
	}

	_, err := NewSQLiteStore(cfg)
	if err == nil {
		t.Error("expected error for empty db_path")
	}
}

func TestSQLiteStore_HostOperations(t *testing.T) {
	store := createTestStore(t)
	defer store.Close()
	ctx := context.Background()

	// Create host.
	host := &Host{
		Name:   "test-host",
		Addr:   "192.168.1.1",
		Port:   22,
		Users:  []string{"admin"},
		Groups: []string{"ops"},
	}

	err := store.CreateHost(ctx, host)
	if err != nil {
		t.Fatalf("failed to create host: %v", err)
	}
	if host.ID == "" {
		t.Error("expected host ID to be set")
	}

	// Get host by ID.
	retrieved, err := store.GetHost(ctx, host.ID)
	if err != nil {
		t.Fatalf("failed to get host: %v", err)
	}
	if retrieved.Name != host.Name {
		t.Errorf("expected name %s, got %s", host.Name, retrieved.Name)
	}

	// Get host by name.
	retrieved, err = store.GetHostByName(ctx, "test-host")
	if err != nil {
		t.Fatalf("failed to get host by name: %v", err)
	}
	if retrieved.Addr != host.Addr {
		t.Errorf("expected addr %s, got %s", host.Addr, retrieved.Addr)
	}

	// List hosts.
	hosts, err := store.ListHosts(ctx)
	if err != nil {
		t.Fatalf("failed to list hosts: %v", err)
	}
	if len(hosts) != 1 {
		t.Errorf("expected 1 host, got %d", len(hosts))
	}

	// Update host.
	host.Addr = "192.168.1.2"
	err = store.UpdateHost(ctx, host)
	if err != nil {
		t.Fatalf("failed to update host: %v", err)
	}

	retrieved, _ = store.GetHost(ctx, host.ID)
	if retrieved.Addr != "192.168.1.2" {
		t.Errorf("expected updated addr, got %s", retrieved.Addr)
	}

	// Delete host.
	err = store.DeleteHost(ctx, host.ID)
	if err != nil {
		t.Fatalf("failed to delete host: %v", err)
	}

	_, err = store.GetHost(ctx, host.ID)
	if err == nil {
		t.Error("expected error after delete")
	}
}

func TestSQLiteStore_UserOperations(t *testing.T) {
	store := createTestStore(t)
	defer store.Close()
	ctx := context.Background()

	// Create user.
	user := &User{
		Username:   "testuser",
		Groups:     []string{"admin", "users"},
		PublicKeys: []string{"ssh-ed25519 AAAA..."},
	}

	err := store.CreateUser(ctx, user)
	if err != nil {
		t.Fatalf("failed to create user: %v", err)
	}
	if user.ID == "" {
		t.Error("expected user ID to be set")
	}

	// Get user by ID.
	retrieved, err := store.GetUser(ctx, user.ID)
	if err != nil {
		t.Fatalf("failed to get user: %v", err)
	}
	if retrieved.Username != user.Username {
		t.Errorf("expected username %s, got %s", user.Username, retrieved.Username)
	}

	// Get user by username.
	retrieved, err = store.GetUserByUsername(ctx, "testuser")
	if err != nil {
		t.Fatalf("failed to get user by username: %v", err)
	}
	if len(retrieved.Groups) != 2 {
		t.Errorf("expected 2 groups, got %d", len(retrieved.Groups))
	}

	// List users.
	users, err := store.ListUsers(ctx)
	if err != nil {
		t.Fatalf("failed to list users: %v", err)
	}
	if len(users) != 1 {
		t.Errorf("expected 1 user, got %d", len(users))
	}

	// Update user.
	user.Groups = []string{"admin"}
	err = store.UpdateUser(ctx, user)
	if err != nil {
		t.Fatalf("failed to update user: %v", err)
	}

	retrieved, _ = store.GetUser(ctx, user.ID)
	if len(retrieved.Groups) != 1 {
		t.Errorf("expected 1 group after update, got %d", len(retrieved.Groups))
	}

	// Delete user.
	err = store.DeleteUser(ctx, user.ID)
	if err != nil {
		t.Fatalf("failed to delete user: %v", err)
	}

	_, err = store.GetUser(ctx, user.ID)
	if err == nil {
		t.Error("expected error after delete")
	}
}

func TestSQLiteStore_SessionOperations(t *testing.T) {
	store := createTestStore(t)
	defer store.Close()
	ctx := context.Background()

	// Create session.
	session := &Session{
		Username:   "testuser",
		SourceIP:   "10.0.0.1",
		TargetHost: "server1",
		StartTime:  time.Now(),
	}

	err := store.CreateSession(ctx, session)
	if err != nil {
		t.Fatalf("failed to create session: %v", err)
	}
	if session.ID == "" {
		t.Error("expected session ID to be set")
	}

	// Get session.
	retrieved, err := store.GetSession(ctx, session.ID)
	if err != nil {
		t.Fatalf("failed to get session: %v", err)
	}
	if retrieved.Username != session.Username {
		t.Errorf("expected username %s, got %s", session.Username, retrieved.Username)
	}

	// List sessions.
	sessions, err := store.ListSessions(ctx, "", 0)
	if err != nil {
		t.Fatalf("failed to list sessions: %v", err)
	}
	if len(sessions) != 1 {
		t.Errorf("expected 1 session, got %d", len(sessions))
	}

	// List sessions by username.
	sessions, err = store.ListSessions(ctx, "testuser", 0)
	if err != nil {
		t.Fatalf("failed to list sessions by username: %v", err)
	}
	if len(sessions) != 1 {
		t.Errorf("expected 1 session, got %d", len(sessions))
	}

	// Update session.
	session.EndTime = time.Now()
	err = store.UpdateSession(ctx, session)
	if err != nil {
		t.Fatalf("failed to update session: %v", err)
	}

	retrieved, _ = store.GetSession(ctx, session.ID)
	if retrieved.EndTime.IsZero() {
		t.Error("expected end_time to be set")
	}
}

func TestSQLiteStore_ListActiveSessions(t *testing.T) {
	store := createTestStore(t)
	defer store.Close()
	ctx := context.Background()

	// Create an active session (no end time).
	activeSession := &Session{
		Username:   "user1",
		SourceIP:   "10.0.0.1",
		TargetHost: "server1",
		StartTime:  time.Now(),
	}
	if err := store.CreateSession(ctx, activeSession); err != nil {
		t.Fatalf("failed to create active session: %v", err)
	}

	// Create a completed session (with end time).
	completedSession := &Session{
		Username:   "user2",
		SourceIP:   "10.0.0.2",
		TargetHost: "server2",
		StartTime:  time.Now().Add(-time.Hour),
		EndTime:    time.Now(),
	}
	if err := store.CreateSession(ctx, completedSession); err != nil {
		t.Fatalf("failed to create completed session: %v", err)
	}

	// List active sessions.
	activeSessions, err := store.ListActiveSessions(ctx)
	if err != nil {
		t.Fatalf("failed to list active sessions: %v", err)
	}

	if len(activeSessions) != 1 {
		t.Errorf("expected 1 active session, got %d", len(activeSessions))
	}

	if activeSessions[0].Username != "user1" {
		t.Errorf("expected username user1, got %s", activeSessions[0].Username)
	}

	// Mark the active session as completed.
	activeSession.EndTime = time.Now()
	if err := store.UpdateSession(ctx, activeSession); err != nil {
		t.Fatalf("failed to update session: %v", err)
	}

	// Now there should be no active sessions.
	activeSessions, err = store.ListActiveSessions(ctx)
	if err != nil {
		t.Fatalf("failed to list active sessions: %v", err)
	}

	if len(activeSessions) != 0 {
		t.Errorf("expected 0 active sessions, got %d", len(activeSessions))
	}
}

func TestSQLiteStore_SSHKeyOperations(t *testing.T) {
	store := createTestStore(t)
	defer store.Close()
	ctx := context.Background()

	// Create SSH key.
	key := &SSHKey{
		Name:        "test-key",
		PrivateKey:  "-----BEGIN PRIVATE KEY-----\n...\n-----END PRIVATE KEY-----",
		PublicKey:   "ssh-ed25519 AAAA...",
		Fingerprint: "SHA256:abc123",
		KeyType:     "ed25519",
	}

	err := store.CreateSSHKey(ctx, key)
	if err != nil {
		t.Fatalf("failed to create SSH key: %v", err)
	}
	if key.ID == "" {
		t.Error("expected key ID to be set")
	}

	// Get key by ID.
	retrieved, err := store.GetSSHKey(ctx, key.ID)
	if err != nil {
		t.Fatalf("failed to get SSH key: %v", err)
	}
	if retrieved.Name != key.Name {
		t.Errorf("expected name %s, got %s", key.Name, retrieved.Name)
	}

	// Get key by fingerprint.
	retrieved, err = store.GetSSHKeyByFingerprint(ctx, "SHA256:abc123")
	if err != nil {
		t.Fatalf("failed to get key by fingerprint: %v", err)
	}
	if retrieved.KeyType != "ed25519" {
		t.Errorf("expected key type ed25519, got %s", retrieved.KeyType)
	}

	// List keys.
	keys, err := store.ListSSHKeys(ctx)
	if err != nil {
		t.Fatalf("failed to list keys: %v", err)
	}
	if len(keys) != 1 {
		t.Errorf("expected 1 key, got %d", len(keys))
	}

	// Delete key.
	err = store.DeleteSSHKey(ctx, key.ID)
	if err != nil {
		t.Fatalf("failed to delete key: %v", err)
	}

	_, err = store.GetSSHKey(ctx, key.ID)
	if err == nil {
		t.Error("expected error after delete")
	}
}

func TestSQLiteStore_TokenOperations(t *testing.T) {
	store := createTestStore(t)
	defer store.Close()
	ctx := context.Background()

	// Create a user first.
	user := &User{Username: "tokenuser"}
	_ = store.CreateUser(ctx, user)

	// Create token.
	token := &Token{
		UserID:    user.ID,
		TokenHash: "hash123",
		TokenType: "session",
		ExpiresAt: time.Now().Add(time.Hour),
	}

	err := store.CreateToken(ctx, token)
	if err != nil {
		t.Fatalf("failed to create token: %v", err)
	}

	// Get token by hash.
	retrieved, err := store.GetTokenByHash(ctx, "hash123")
	if err != nil {
		t.Fatalf("failed to get token: %v", err)
	}
	if retrieved.UserID != user.ID {
		t.Errorf("expected user ID %s, got %s", user.ID, retrieved.UserID)
	}

	// Delete token.
	err = store.DeleteToken(ctx, token.ID)
	if err != nil {
		t.Fatalf("failed to delete token: %v", err)
	}

	_, err = store.GetTokenByHash(ctx, "hash123")
	if err == nil {
		t.Error("expected error after delete")
	}
}

func TestSQLiteStore_Settings(t *testing.T) {
	store := createTestStore(t)
	defer store.Close()
	ctx := context.Background()

	// Set setting.
	err := store.SetSetting(ctx, "test_key", "test_value")
	if err != nil {
		t.Fatalf("failed to set setting: %v", err)
	}

	// Get setting.
	value, err := store.GetSetting(ctx, "test_key")
	if err != nil {
		t.Fatalf("failed to get setting: %v", err)
	}
	if value != "test_value" {
		t.Errorf("expected test_value, got %s", value)
	}

	// Update setting.
	err = store.SetSetting(ctx, "test_key", "new_value")
	if err != nil {
		t.Fatalf("failed to update setting: %v", err)
	}

	value, _ = store.GetSetting(ctx, "test_key")
	if value != "new_value" {
		t.Errorf("expected new_value, got %s", value)
	}

	// Get non-existent setting.
	_, err = store.GetSetting(ctx, "nonexistent")
	if err == nil {
		t.Error("expected error for non-existent setting")
	}
}

func TestSQLiteStore_UserWithPassword(t *testing.T) {
	store := createTestStore(t)
	defer store.Close()
	ctx := context.Background()

	// Create user with password.
	user := &UserWithPassword{
		User: User{
			Username: "pwduser",
			Groups:   []string{"users"},
		},
		PasswordHash: "$2a$10$...",
		IsActive:     true,
	}

	err := store.CreateUserWithPassword(ctx, user)
	if err != nil {
		t.Fatalf("failed to create user with password: %v", err)
	}

	// Get user with password.
	retrieved, err := store.GetUserWithPassword(ctx, "pwduser")
	if err != nil {
		t.Fatalf("failed to get user with password: %v", err)
	}
	if retrieved.PasswordHash != "$2a$10$..." {
		t.Error("expected password hash to match")
	}
	if !retrieved.IsActive {
		t.Error("expected user to be active")
	}

	// Update password.
	err = store.UpdateUserPassword(ctx, user.ID, "$2a$10$new...")
	if err != nil {
		t.Fatalf("failed to update password: %v", err)
	}

	retrieved, _ = store.GetUserWithPassword(ctx, "pwduser")
	if retrieved.PasswordHash != "$2a$10$new..." {
		t.Error("expected password to be updated")
	}

	// Update last login.
	err = store.UpdateUserLastLogin(ctx, user.ID)
	if err != nil {
		t.Fatalf("failed to update last login: %v", err)
	}
}

func TestSQLiteStore_UserAllowedHosts(t *testing.T) {
	store := createTestStore(t)
	defer store.Close()
	ctx := context.Background()

	// Create user with allowed_hosts.
	user := &User{
		Username:     "restricted",
		Groups:       []string{"users"},
		AllowedHosts: []string{"host1", "host2"},
		Source:       UserSourceLocal,
	}

	err := store.CreateUser(ctx, user)
	if err != nil {
		t.Fatalf("failed to create user: %v", err)
	}

	// Retrieve and verify allowed_hosts.
	retrieved, err := store.GetUser(ctx, user.ID)
	if err != nil {
		t.Fatalf("failed to get user: %v", err)
	}
	if len(retrieved.AllowedHosts) != 2 {
		t.Errorf("expected 2 allowed hosts, got %d", len(retrieved.AllowedHosts))
	}
	if retrieved.AllowedHosts[0] != "host1" || retrieved.AllowedHosts[1] != "host2" {
		t.Errorf("expected [host1, host2], got %v", retrieved.AllowedHosts)
	}

	// Get by username.
	retrieved, _ = store.GetUserByUsername(ctx, "restricted")
	if len(retrieved.AllowedHosts) != 2 {
		t.Errorf("expected 2 allowed hosts from GetUserByUsername, got %d", len(retrieved.AllowedHosts))
	}

	// List users.
	users, _ := store.ListUsers(ctx)
	if len(users[0].AllowedHosts) != 2 {
		t.Errorf("expected 2 allowed hosts from ListUsers, got %d", len(users[0].AllowedHosts))
	}

	// Update allowed_hosts.
	user.AllowedHosts = []string{"*"}
	err = store.UpdateUser(ctx, user)
	if err != nil {
		t.Fatalf("failed to update user: %v", err)
	}

	retrieved, _ = store.GetUser(ctx, user.ID)
	if len(retrieved.AllowedHosts) != 1 || retrieved.AllowedHosts[0] != "*" {
		t.Errorf("expected [*], got %v", retrieved.AllowedHosts)
	}
}

func TestSQLiteStore_UserNullAllowedHosts(t *testing.T) {
	store := createTestStore(t)
	defer store.Close()
	ctx := context.Background()

	// Create user without allowed_hosts (nil).
	user := &User{
		Username: "nohost",
		Groups:   []string{"users"},
		Source:   UserSourceSSH,
	}

	err := store.CreateUser(ctx, user)
	if err != nil {
		t.Fatalf("failed to create user: %v", err)
	}

	// Retrieve and verify allowed_hosts is nil/empty.
	retrieved, err := store.GetUser(ctx, user.ID)
	if err != nil {
		t.Fatalf("failed to get user: %v", err)
	}
	if len(retrieved.AllowedHosts) > 0 {
		t.Errorf("expected nil/empty allowed hosts, got %v", retrieved.AllowedHosts)
	}

	// Verify listing works with null allowed_hosts.
	users, err := store.ListUsers(ctx)
	if err != nil {
		t.Fatalf("failed to list users: %v", err)
	}
	if len(users) != 1 {
		t.Errorf("expected 1 user, got %d", len(users))
	}
}

func createTestStore(t *testing.T) *SQLiteStore {
	t.Helper()
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "test.db")

	cfg := config.StorageConfig{
		Type:   "sqlite",
		DBPath: dbPath,
	}

	store, err := NewSQLiteStore(cfg)
	if err != nil {
		t.Fatalf("failed to create test store: %v", err)
	}

	return store
}

func TestSQLiteStore_AuditLogCreate(t *testing.T) {
	store := createTestStore(t)
	defer store.Close()
	ctx := context.Background()

	log1 := &AuditLog{
		Timestamp:  time.Now(),
		EventType:  "login",
		Username:   "testuser",
		SourceIP:   "192.168.1.100",
		TargetHost: "",
		Action:     "user login",
		Result:     "success",
		Details:    map[string]interface{}{"method": "password"},
	}

	err := store.CreateAuditLog(ctx, log1)
	if err != nil {
		t.Fatalf("failed to create audit log: %v", err)
	}

	if log1.ID == "" {
		t.Error("expected ID to be set after create")
	}
}

func TestSQLiteStore_AuditLogFilter(t *testing.T) {
	store := createTestStore(t)
	defer store.Close()
	ctx := context.Background()

	// Create test data.
	testLogs := []*AuditLog{
		{Timestamp: time.Now(), EventType: "login", Username: "testuser", SourceIP: "192.168.1.100", Action: "user login", Result: "success"},
		{Timestamp: time.Now(), EventType: "connect", Username: "testuser", SourceIP: "192.168.1.100", TargetHost: "server1.example.com", Action: "connect to host", Result: "success"},
		{Timestamp: time.Now(), EventType: "login", Username: "admin", SourceIP: "10.0.0.50", Action: "user login", Result: "failure"},
	}
	for _, log := range testLogs {
		if err := store.CreateAuditLog(ctx, log); err != nil {
			t.Fatalf("failed to create audit log: %v", err)
		}
	}

	// Filter by username.
	logs, err := store.ListAuditLogs(ctx, "testuser", "", time.Time{}, time.Time{}, 100, 0)
	if err != nil {
		t.Fatalf("failed to list audit logs by username: %v", err)
	}
	if len(logs) != 2 {
		t.Errorf("expected 2 logs for testuser, got %d", len(logs))
	}

	// Filter by event type.
	logs, err = store.ListAuditLogs(ctx, "", "login", time.Time{}, time.Time{}, 100, 0)
	if err != nil {
		t.Fatalf("failed to list audit logs by event type: %v", err)
	}
	if len(logs) != 2 {
		t.Errorf("expected 2 login logs, got %d", len(logs))
	}

	// Filter by event type - connect.
	logs, err = store.ListAuditLogs(ctx, "", "connect", time.Time{}, time.Time{}, 100, 0)
	if err != nil {
		t.Fatalf("failed to list audit logs by connect type: %v", err)
	}
	if len(logs) != 1 {
		t.Errorf("expected 1 connect log, got %d", len(logs))
	}
}

func TestSQLiteStore_AuditLogPagination(t *testing.T) {
	store := createTestStore(t)
	defer store.Close()
	ctx := context.Background()

	// Create 5 test logs.
	for i := 0; i < 5; i++ {
		log := &AuditLog{Timestamp: time.Now(), EventType: "login", Username: "user", Action: "test", Result: "success"}
		if err := store.CreateAuditLog(ctx, log); err != nil {
			t.Fatalf("failed to create audit log: %v", err)
		}
	}

	// Test limit.
	logs, err := store.ListAuditLogs(ctx, "", "", time.Time{}, time.Time{}, 2, 0)
	if err != nil {
		t.Fatalf("failed to list audit logs with limit: %v", err)
	}
	if len(logs) != 2 {
		t.Errorf("expected 2 logs with limit, got %d", len(logs))
	}

	// Test offset.
	logs, err = store.ListAuditLogs(ctx, "", "", time.Time{}, time.Time{}, 100, 3)
	if err != nil {
		t.Fatalf("failed to list audit logs with offset: %v", err)
	}
	if len(logs) != 2 {
		t.Errorf("expected 2 logs with offset 3, got %d", len(logs))
	}
}

// Cleanup test files.
func TestMain(m *testing.M) {
	code := m.Run()
	os.Exit(code)
}
