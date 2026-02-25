//go:build integration

// Package integration provides end-to-end integration tests for vc-jump.
// These tests verify complete user workflows across multiple components.
package integration

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/Veritas-Calculus/vc-jump/internal/auth"
	"github.com/Veritas-Calculus/vc-jump/internal/config"
	"github.com/Veritas-Calculus/vc-jump/internal/otp"
	"github.com/Veritas-Calculus/vc-jump/internal/storage"
)

// testEnv holds the shared test environment.
type testEnv struct {
	store   *storage.SQLiteStore
	auth    *auth.Authenticator
	ctx     context.Context
	cleanup func()
}

// setupTestEnv creates a complete test environment with database.
func setupTestEnv(t *testing.T) *testEnv {
	t.Helper()

	ctx := context.Background()

	// Use temp directory or environment variable for DB path.
	dbPath := os.Getenv("TEST_DB_PATH")
	if dbPath == "" {
		dbPath = filepath.Join(t.TempDir(), "test-vc-jump.db")
	} else {
		// Ensure unique DB per test to avoid conflicts.
		dbPath = filepath.Join(filepath.Dir(dbPath), t.Name()+".db")
	}

	// Create storage.
	storeCfg := config.StorageConfig{
		DBPath: dbPath,
	}
	store, err := storage.NewSQLiteStore(storeCfg)
	if err != nil {
		t.Fatalf("Failed to create store: %v", err)
	}

	// Create authenticator.
	authCfg := config.AuthConfig{
		CacheDuration: 5 * time.Minute,
	}
	authenticator, err := auth.NewWithStore(authCfg, store)
	if err != nil {
		store.Close()
		t.Fatalf("Failed to create authenticator: %v", err)
	}

	// Initialize default roles.
	if err := store.InitDefaultRoles(ctx); err != nil {
		store.Close()
		t.Fatalf("Failed to init default roles: %v", err)
	}

	return &testEnv{
		store:   store,
		auth:    authenticator,
		ctx:     ctx,
		cleanup: func() {
			store.Close()
			os.Remove(dbPath)
		},
	}
}

// =============================================================================
// Scenario 1: Complete User Registration and Login Flow
// =============================================================================

func TestScenario_UserRegistrationAndLogin(t *testing.T) {
	env := setupTestEnv(t)
	defer env.cleanup()

	t.Run("CreateUser_Login_Success", func(t *testing.T) {
		// Step 1: Create a new user with password.
		passwordHash, err := auth.HashPassword("SecureP@ssw0rd!")
		if err != nil {
			t.Fatalf("Failed to hash password: %v", err)
		}

		user := &storage.UserWithPassword{
			User: storage.User{
				Username:     "alice",
				Groups:       []string{"developers"},
				AllowedHosts: []string{"server-1", "server-2"},
				Source:       "local",
			},
			PasswordHash: passwordHash,
			IsActive:     true,
		}

		if err := env.store.CreateUserWithPassword(env.ctx, user); err != nil {
			t.Fatalf("Failed to create user: %v", err)
		}

		// Step 2: Login with correct password.
		authUser, err := env.auth.AuthenticatePassword(env.ctx, "alice", "SecureP@ssw0rd!")
		if err != nil {
			t.Fatalf("Authentication should succeed: %v", err)
		}

		if authUser.Username != "alice" {
			t.Errorf("Username = %s, want alice", authUser.Username)
		}
		if len(authUser.Groups) != 1 || authUser.Groups[0] != "developers" {
			t.Errorf("Groups = %v, want [developers]", authUser.Groups)
		}
	})

	t.Run("Login_WrongPassword_Fail", func(t *testing.T) {
		_, err := env.auth.AuthenticatePassword(env.ctx, "alice", "WrongPassword")
		if err == nil {
			t.Error("Authentication should fail with wrong password")
		}
	})

	t.Run("Login_NonexistentUser_Fail", func(t *testing.T) {
		_, err := env.auth.AuthenticatePassword(env.ctx, "nonexistent", "password")
		if err == nil {
			t.Error("Authentication should fail for nonexistent user")
		}
	})

	t.Run("Login_DisabledUser_Fail", func(t *testing.T) {
		// Create disabled user.
		passwordHash, _ := auth.HashPassword("password123")
		user := &storage.UserWithPassword{
			User:         storage.User{Username: "disabled_user"},
			PasswordHash: passwordHash,
			IsActive:     false,
		}
		env.store.CreateUserWithPassword(env.ctx, user)

		_, err := env.auth.AuthenticatePassword(env.ctx, "disabled_user", "password123")
		if err == nil {
			t.Error("Authentication should fail for disabled user")
		}
	})
}

// =============================================================================
// Scenario 2: OTP (Two-Factor Authentication) Flow
// =============================================================================

func TestScenario_OTPSetupAndVerification(t *testing.T) {
	env := setupTestEnv(t)
	defer env.cleanup()

	t.Run("CompleteOTPFlow", func(t *testing.T) {
		// Step 1: Create user.
		passwordHash, _ := auth.HashPassword("password")
		user := &storage.UserWithPassword{
			User:         storage.User{Username: "bob"},
			PasswordHash: passwordHash,
			IsActive:     true,
		}
		if err := env.store.CreateUserWithPassword(env.ctx, user); err != nil {
			t.Fatalf("Failed to create user: %v", err)
		}

		// Get user to have ID.
		dbUser, _ := env.store.GetUserByUsername(env.ctx, "bob")

		// Step 2: Generate OTP secret.
		otpKey, err := otp.GenerateSecret("bob", "VC-Jump-Test")
		if err != nil {
			t.Fatalf("Failed to generate OTP secret: %v", err)
		}

		secret := otpKey.Secret()
		if secret == "" {
			t.Fatal("OTP secret should not be empty")
		}

		// Step 3: Generate QR code.
		qrCode, err := otp.GenerateQRCode(otpKey, 200, 200)
		if err != nil {
			t.Fatalf("Failed to generate QR code: %v", err)
		}
		if len(qrCode) == 0 {
			t.Error("QR code should not be empty")
		}

		// Step 4: Store OTP secret for user.
		if err := env.store.SetUserOTPSecret(env.ctx, dbUser.ID, secret); err != nil {
			t.Fatalf("Failed to store OTP secret: %v", err)
		}

		// Step 5: Generate and validate OTP code.
		code, err := otp.GenerateCode(secret)
		if err != nil {
			t.Fatalf("Failed to generate OTP code: %v", err)
		}

		if !otp.Validate(code, secret) {
			t.Error("Valid OTP code should pass validation")
		}

		// Step 6: Enable OTP for user.
		if err := env.store.EnableUserOTP(env.ctx, dbUser.ID); err != nil {
			t.Fatalf("Failed to enable OTP: %v", err)
		}

		// Step 7: Verify OTP is enabled.
		updatedUser, _ := env.store.GetUserByUsername(env.ctx, "bob")
		if !updatedUser.OTPEnabled {
			t.Error("OTP should be enabled")
		}
	})

	t.Run("InvalidOTPCode", func(t *testing.T) {
		key, _ := otp.GenerateSecret("test", "")
		secret := key.Secret()

		// Invalid codes should fail.
		invalidCodes := []string{"000000", "123456", "abcdef", "", "12345", "1234567"}
		for _, code := range invalidCodes {
			if otp.Validate(code, secret) {
				t.Errorf("Invalid code %q should not pass validation", code)
			}
		}
	})

	t.Run("OTPWithTimeSkew", func(t *testing.T) {
		key, _ := otp.GenerateSecret("test", "")
		secret := key.Secret()
		now := time.Now()

		// Generate code for current time.
		code, _ := otp.GenerateCode(secret)

		// Should be valid with slight time skew (within 1 period = 30s).
		valid, err := otp.ValidateWithTime(code, secret, now.Add(15*time.Second))
		if err != nil {
			t.Fatalf("ValidateWithTime failed: %v", err)
		}
		if !valid {
			t.Error("Code should be valid with 15s skew")
		}

		// Should be invalid with large time skew.
		valid, _ = otp.ValidateWithTime(code, secret, now.Add(2*time.Minute))
		if valid {
			t.Error("Code should be invalid with 2min skew")
		}
	})
}

// =============================================================================
// Scenario 3: RBAC (Role-Based Access Control) Flow
// =============================================================================

func TestScenario_RBACPermissions(t *testing.T) {
	env := setupTestEnv(t)
	defer env.cleanup()

	// Role name constants (matching rbac package).
	const (
		RoleAdmin     = "admin"
		RoleDeveloper = "developer"
	)

	t.Run("AdminRoleAssignment", func(t *testing.T) {
		// Create admin user.
		passwordHash, _ := auth.HashPassword("admin123")
		adminUser := &storage.UserWithPassword{
			User:         storage.User{Username: "admin_user"},
			PasswordHash: passwordHash,
			IsActive:     true,
		}
		env.store.CreateUserWithPassword(env.ctx, adminUser)
		dbUser, _ := env.store.GetUserByUsername(env.ctx, "admin_user")

		// Get admin role.
		adminRole, err := env.store.GetRoleByName(env.ctx, RoleAdmin)
		if err != nil {
			t.Fatalf("Failed to get admin role: %v", err)
		}

		// Assign admin role.
		if err := env.store.AssignRole(env.ctx, dbUser.ID, adminRole.ID); err != nil {
			t.Fatalf("Failed to assign admin role: %v", err)
		}

		// Verify role was assigned.
		roles, err := env.store.GetUserRoles(env.ctx, dbUser.ID)
		if err != nil {
			t.Fatalf("Failed to get user roles: %v", err)
		}

		found := false
		for _, role := range roles {
			if role.Name == RoleAdmin {
				found = true
				break
			}
		}
		if !found {
			t.Error("Admin role should be assigned to user")
		}
	})

	t.Run("DeveloperRoleAssignment", func(t *testing.T) {
		// Create developer user.
		passwordHash, _ := auth.HashPassword("dev123")
		devUser := &storage.UserWithPassword{
			User:         storage.User{Username: "developer"},
			PasswordHash: passwordHash,
			IsActive:     true,
		}
		env.store.CreateUserWithPassword(env.ctx, devUser)
		dbUser, _ := env.store.GetUserByUsername(env.ctx, "developer")

		// Get developer role.
		devRole, err := env.store.GetRoleByName(env.ctx, RoleDeveloper)
		if err != nil {
			t.Fatalf("Failed to get developer role: %v", err)
		}

		// Assign developer role.
		env.store.AssignRole(env.ctx, dbUser.ID, devRole.ID)

		// Verify permissions on role.
		if len(devRole.Permissions) == 0 {
			t.Error("Developer role should have permissions")
		}
	})

	t.Run("HostAccessControl", func(t *testing.T) {
		// Create user.
		passwordHash, _ := auth.HashPassword("test")
		user := &storage.UserWithPassword{
			User:         storage.User{Username: "host_test_user"},
			PasswordHash: passwordHash,
			IsActive:     true,
		}
		env.store.CreateUserWithPassword(env.ctx, user)
		dbUser, _ := env.store.GetUserByUsername(env.ctx, "host_test_user")

		// Create host.
		host := &storage.Host{
			Name: "test-server",
			Addr: "192.168.1.100",
			Port: 22,
			User: "root",
		}
		env.store.CreateHost(env.ctx, host)

		// Grant host access.
		hostPerm := &storage.HostPermission{
			UserID: dbUser.ID,
			HostID: host.ID,
		}
		if err := env.store.GrantHostAccess(env.ctx, hostPerm); err != nil {
			t.Fatalf("Failed to grant host access: %v", err)
		}

		// Verify permission exists.
		perm, err := env.store.GetHostPermission(env.ctx, dbUser.ID, host.ID)
		if err != nil {
			t.Fatalf("Failed to get host permission: %v", err)
		}
		if perm.HostID != host.ID {
			t.Error("Host permission should exist")
		}

		// Revoke access.
		env.store.RevokeHostAccess(env.ctx, dbUser.ID, host.ID)
		_, err = env.store.GetHostPermission(env.ctx, dbUser.ID, host.ID)
		if err == nil {
			t.Error("Host permission should be revoked")
		}
	})
}

// =============================================================================
// Scenario 4: Session Management Flow
// =============================================================================

func TestScenario_SessionManagement(t *testing.T) {
	env := setupTestEnv(t)
	defer env.cleanup()

	t.Run("CreateAndTrackSession", func(t *testing.T) {
		// Create session.
		session := &storage.Session{
			Username:   "session_user",
			SourceIP:   "192.168.1.50",
			TargetHost: "server-1",
			StartTime:  time.Now(),
		}

		if err := env.store.CreateSession(env.ctx, session); err != nil {
			t.Fatalf("Failed to create session: %v", err)
		}

		if session.ID == "" {
			t.Error("Session ID should be set")
		}

		// Get session.
		retrieved, err := env.store.GetSession(env.ctx, session.ID)
		if err != nil {
			t.Fatalf("Failed to get session: %v", err)
		}

		if retrieved.Username != "session_user" {
			t.Errorf("Username = %s, want session_user", retrieved.Username)
		}
		if retrieved.TargetHost != "server-1" {
			t.Errorf("TargetHost = %s, want server-1", retrieved.TargetHost)
		}
	})

	t.Run("ListSessions", func(t *testing.T) {
		// Create multiple sessions.
		for i := 0; i < 3; i++ {
			session := &storage.Session{
				Username:   "multi_session_user",
				SourceIP:   "192.168.1.60",
				TargetHost: "server-multi",
				StartTime:  time.Now(),
			}
			env.store.CreateSession(env.ctx, session)
		}

		// List sessions for user.
		sessions, err := env.store.ListSessions(env.ctx, "multi_session_user", 10)
		if err != nil {
			t.Fatalf("Failed to list sessions: %v", err)
		}

		if len(sessions) < 3 {
			t.Errorf("Expected at least 3 sessions, got %d", len(sessions))
		}
	})

	t.Run("UpdateSession", func(t *testing.T) {
		session := &storage.Session{
			Username:   "update_user",
			SourceIP:   "192.168.1.70",
			TargetHost: "server-update",
			StartTime:  time.Now(),
		}
		env.store.CreateSession(env.ctx, session)

		// Update session with end time.
		session.EndTime = time.Now()
		session.Recording = "recording-123.cast"
		if err := env.store.UpdateSession(env.ctx, session); err != nil {
			t.Fatalf("Failed to update session: %v", err)
		}

		// Verify session updated.
		retrieved, _ := env.store.GetSession(env.ctx, session.ID)
		if retrieved.Recording != "recording-123.cast" {
			t.Error("Session recording should be updated")
		}
	})
}

// =============================================================================
// Scenario 5: Host Management Flow
// =============================================================================

func TestScenario_HostManagement(t *testing.T) {
	env := setupTestEnv(t)
	defer env.cleanup()

	t.Run("CreateAndManageHost", func(t *testing.T) {
		// Create folder.
		folder := storage.Folder{
			Name:        "Production",
			Path:        "/production",
			Description: "Production servers",
		}
		if err := env.store.CreateFolder(env.ctx, folder); err != nil {
			t.Fatalf("Failed to create folder: %v", err)
		}

		// Create host in folder.
		host := &storage.Host{
			Name:     "prod-web-01",
			Addr:     "10.0.1.10",
			Port:     22,
			User:     "deploy",
			Users:    []string{"deploy", "admin"},
			Groups:   []string{"web", "production"},
			FolderID: folder.ID,
		}

		if err := env.store.CreateHost(env.ctx, host); err != nil {
			t.Fatalf("Failed to create host: %v", err)
		}

		// Get host.
		retrieved, err := env.store.GetHost(env.ctx, host.ID)
		if err != nil {
			t.Fatalf("Failed to get host: %v", err)
		}

		if retrieved.Name != "prod-web-01" {
			t.Errorf("Name = %s, want prod-web-01", retrieved.Name)
		}
		if retrieved.Addr != "10.0.1.10" {
			t.Errorf("Addr = %s, want 10.0.1.10", retrieved.Addr)
		}

		// Update host.
		retrieved.Port = 2222
		if err := env.store.UpdateHost(env.ctx, retrieved); err != nil {
			t.Fatalf("Failed to update host: %v", err)
		}

		updated, _ := env.store.GetHost(env.ctx, host.ID)
		if updated.Port != 2222 {
			t.Errorf("Port = %d, want 2222", updated.Port)
		}
	})

	t.Run("ListHostsInFolder", func(t *testing.T) {
		folder := storage.Folder{
			Name: "Staging",
			Path: "/staging",
		}
		env.store.CreateFolder(env.ctx, folder)

		for i := 1; i <= 5; i++ {
			host := &storage.Host{
				Name:     "staging-server-" + string(rune('0'+i)),
				Addr:     "10.0.2." + string(rune('0'+i)),
				Port:     22,
				FolderID: folder.ID,
			}
			env.store.CreateHost(env.ctx, host)
		}

		hosts, err := env.store.ListHostsByFolder(env.ctx, folder.ID)
		if err != nil {
			t.Fatalf("Failed to list hosts: %v", err)
		}

		if len(hosts) != 5 {
			t.Errorf("Expected 5 hosts, got %d", len(hosts))
		}
	})
}

// =============================================================================
// Scenario 6: SSH Key Management Flow
// =============================================================================

func TestScenario_SSHKeyManagement(t *testing.T) {
	env := setupTestEnv(t)
	defer env.cleanup()

	t.Run("CreateAndManageSSHKey", func(t *testing.T) {
		// Create SSH key (using test data, not real key generation).
		key := &storage.SSHKey{
			Name:        "deploy-key",
			PrivateKey:  "-----BEGIN RSA PRIVATE KEY-----\ntest-private-key-content\n-----END RSA PRIVATE KEY-----",
			PublicKey:   "ssh-rsa AAAA... deploy@example.com",
			Fingerprint: "SHA256:testfingerprint123",
			KeyType:     "rsa",
		}

		if err := env.store.CreateSSHKey(env.ctx, key); err != nil {
			t.Fatalf("Failed to create SSH key: %v", err)
		}

		// Get key.
		retrieved, err := env.store.GetSSHKey(env.ctx, key.ID)
		if err != nil {
			t.Fatalf("Failed to get SSH key: %v", err)
		}

		if retrieved.Name != "deploy-key" {
			t.Errorf("Name = %s, want deploy-key", retrieved.Name)
		}

		// List keys.
		keys, err := env.store.ListSSHKeys(env.ctx)
		if err != nil {
			t.Fatalf("Failed to list SSH keys: %v", err)
		}

		if len(keys) == 0 {
			t.Error("Expected at least 1 SSH key")
		}
	})
}

// =============================================================================
// Scenario 7: Concurrent Access (Stress Test)
// =============================================================================

func TestScenario_ConcurrentAccess(t *testing.T) {
	env := setupTestEnv(t)
	defer env.cleanup()

	t.Run("ConcurrentUserCreation", func(t *testing.T) {
		const numGoroutines = 10
		errChan := make(chan error, numGoroutines)

		for i := 0; i < numGoroutines; i++ {
			go func(idx int) {
				passwordHash, _ := auth.HashPassword("password")
				user := &storage.UserWithPassword{
					User: storage.User{
						Username: "concurrent_user_" + string(rune('a'+idx)),
					},
					PasswordHash: passwordHash,
					IsActive:     true,
				}
				errChan <- env.store.CreateUserWithPassword(env.ctx, user)
			}(i)
		}

		// Wait for all goroutines.
		for i := 0; i < numGoroutines; i++ {
			if err := <-errChan; err != nil {
				t.Errorf("Concurrent user creation failed: %v", err)
			}
		}
	})

	t.Run("ConcurrentSessionCreation", func(t *testing.T) {
		const numGoroutines = 20
		errChan := make(chan error, numGoroutines)

		for i := 0; i < numGoroutines; i++ {
			go func(idx int) {
				session := &storage.Session{
					Username:   "concurrent_session_user",
					SourceIP:   "192.168.1.100",
					TargetHost: "server-concurrent",
					StartTime:  time.Now(),
				}
				errChan <- env.store.CreateSession(env.ctx, session)
			}(i)
		}

		for i := 0; i < numGoroutines; i++ {
			if err := <-errChan; err != nil {
				t.Errorf("Concurrent session creation failed: %v", err)
			}
		}
	})

	t.Run("ConcurrentAuthentication", func(t *testing.T) {
		// Create user for concurrent auth testing.
		passwordHash, _ := auth.HashPassword("concurrent_password")
		user := &storage.UserWithPassword{
			User:         storage.User{Username: "concurrent_auth_user"},
			PasswordHash: passwordHash,
			IsActive:     true,
		}
		env.store.CreateUserWithPassword(env.ctx, user)

		const numGoroutines = 20
		successChan := make(chan bool, numGoroutines)

		for i := 0; i < numGoroutines; i++ {
			go func() {
				_, err := env.auth.AuthenticatePassword(env.ctx, "concurrent_auth_user", "concurrent_password")
				successChan <- (err == nil)
			}()
		}

		successCount := 0
		for i := 0; i < numGoroutines; i++ {
			if <-successChan {
				successCount++
			}
		}

		if successCount != numGoroutines {
			t.Errorf("Expected %d successful authentications, got %d", numGoroutines, successCount)
		}
	})
}

// =============================================================================
// Scenario 8: Security Edge Cases
// =============================================================================

func TestScenario_SecurityEdgeCases(t *testing.T) {
	env := setupTestEnv(t)
	defer env.cleanup()

	t.Run("SQLInjectionAttempts", func(t *testing.T) {
		// These should not cause SQL injection.
		maliciousUsernames := []string{
			"user'; DROP TABLE users; --",
			"user\" OR \"1\"=\"1",
			"user\\",
			"user\x00",
			"<script>alert('xss')</script>",
		}

		for _, username := range maliciousUsernames {
			passwordHash, _ := auth.HashPassword("password")
			user := &storage.UserWithPassword{
				User:         storage.User{Username: username},
				PasswordHash: passwordHash,
				IsActive:     true,
			}
			// Should either create or fail gracefully, not cause SQL injection.
			_ = env.store.CreateUserWithPassword(env.ctx, user)
		}

		// Verify database is still functional.
		_, err := env.store.ListUsers(env.ctx)
		if err != nil {
			t.Errorf("Database should still be functional: %v", err)
		}
	})

	t.Run("EmptyAndNullInputs", func(t *testing.T) {
		// Empty username should fail.
		_, err := env.auth.AuthenticatePassword(env.ctx, "", "password")
		if err == nil {
			t.Error("Empty username should fail")
		}

		// Empty password should fail.
		_, err = env.auth.AuthenticatePassword(env.ctx, "user", "")
		if err == nil {
			t.Error("Empty password should fail")
		}
	})

	t.Run("PasswordSecurityRequirements", func(t *testing.T) {
		// Test password hashing produces different results.
		hash1, _ := auth.HashPassword("samepassword")
		hash2, _ := auth.HashPassword("samepassword")

		if hash1 == hash2 {
			t.Error("Password hashes should be different (bcrypt uses salt)")
		}

		// Verify both hashes work.
		if !auth.VerifyPassword("samepassword", hash1) {
			t.Error("Hash1 should verify")
		}
		if !auth.VerifyPassword("samepassword", hash2) {
			t.Error("Hash2 should verify")
		}
	})

	t.Run("TokenGeneration", func(t *testing.T) {
		// Generate multiple tokens - should all be unique.
		tokens := make(map[string]bool)
		for i := 0; i < 100; i++ {
			token, err := auth.GenerateToken()
			if err != nil {
				t.Fatalf("Token generation failed: %v", err)
			}
			if tokens[token] {
				t.Error("Duplicate token generated")
			}
			tokens[token] = true
		}
	})
}
