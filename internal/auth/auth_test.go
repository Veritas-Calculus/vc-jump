package auth

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/Veritas-Calculus/vc-jump/internal/config"
	"github.com/Veritas-Calculus/vc-jump/internal/storage"
)

func TestNew(t *testing.T) {
	cfg := config.AuthConfig{
		CacheDuration: 24 * time.Hour,
		CachePath:     t.TempDir(),
	}

	auth, err := New(cfg)
	if err != nil {
		t.Fatalf("failed to create authenticator: %v", err)
	}

	if auth == nil {
		t.Error("expected authenticator to be non-nil")
	}
}

func TestNewWithStore(t *testing.T) {
	store := createTestStore(t)
	defer store.Close()

	cfg := config.AuthConfig{
		CacheDuration: 24 * time.Hour,
	}

	auth, err := NewWithStore(cfg, store)
	if err != nil {
		t.Fatalf("failed to create authenticator with store: %v", err)
	}

	if auth == nil {
		t.Error("expected authenticator to be non-nil")
	}
}

func TestAuthenticatePassword_EmptyUsername(t *testing.T) {
	cfg := config.AuthConfig{CacheDuration: time.Hour}
	auth, _ := New(cfg)
	ctx := context.Background()

	_, err := auth.AuthenticatePassword(ctx, "", "password")
	if err == nil {
		t.Error("expected error for empty username")
	}
}

func TestAuthenticatePassword_EmptyPassword(t *testing.T) {
	cfg := config.AuthConfig{CacheDuration: time.Hour}
	auth, _ := New(cfg)
	ctx := context.Background()

	_, err := auth.AuthenticatePassword(ctx, "user", "")
	if err == nil {
		t.Error("expected error for empty password")
	}
}

func TestAuthenticatePassword_NoStore(t *testing.T) {
	cfg := config.AuthConfig{CacheDuration: time.Hour}
	auth, _ := New(cfg)
	ctx := context.Background()

	// Without store, authentication should fail (secure mode).
	_, err := auth.AuthenticatePassword(ctx, "testuser", "testpass")
	if err == nil {
		t.Fatal("expected authentication to fail without store")
	}
}

func TestAuthenticatePassword_FromStore(t *testing.T) {
	store := createTestStore(t)
	defer store.Close()
	ctx := context.Background()

	// Create user with password.
	passwordHash, _ := HashPassword("correctpassword")
	user := &storage.UserWithPassword{
		User: storage.User{
			Username: "storeuser",
			Groups:   []string{"admin"},
		},
		PasswordHash: passwordHash,
		IsActive:     true,
	}
	store.CreateUserWithPassword(ctx, user)

	cfg := config.AuthConfig{CacheDuration: time.Hour}
	auth, _ := NewWithStore(cfg, store)

	// Correct password.
	authedUser, err := auth.AuthenticatePassword(ctx, "storeuser", "correctpassword")
	if err != nil {
		t.Fatalf("failed to authenticate with correct password: %v", err)
	}
	if authedUser.Username != "storeuser" {
		t.Error("expected username to match")
	}

	// Wrong password.
	_, err = auth.AuthenticatePassword(ctx, "storeuser", "wrongpassword")
	if err == nil {
		t.Error("expected error for wrong password")
	}
}

func TestAuthenticatePassword_InactiveUser(t *testing.T) {
	store := createTestStore(t)
	defer store.Close()
	ctx := context.Background()

	passwordHash, _ := HashPassword("password")
	user := &storage.UserWithPassword{
		User: storage.User{
			Username: "inactiveuser",
		},
		PasswordHash: passwordHash,
		IsActive:     false,
	}
	store.CreateUserWithPassword(ctx, user)

	cfg := config.AuthConfig{CacheDuration: time.Hour}
	auth, _ := NewWithStore(cfg, store)

	_, err := auth.AuthenticatePassword(ctx, "inactiveuser", "password")
	if err == nil {
		t.Error("expected error for inactive user")
	}
}

func TestAuthenticatePassword_Caching(t *testing.T) {
	store := createTestStore(t)
	defer store.Close()
	ctx := context.Background()

	passwordHash, _ := HashPassword("password")
	user := &storage.UserWithPassword{
		User:         storage.User{Username: "cacheduser"},
		PasswordHash: passwordHash,
		IsActive:     true,
	}
	store.CreateUserWithPassword(ctx, user)

	cfg := config.AuthConfig{CacheDuration: time.Hour}
	auth, _ := NewWithStore(cfg, store)

	// First auth.
	user1, _ := auth.AuthenticatePassword(ctx, "cacheduser", "password")

	// Second auth should use cache.
	user2, _ := auth.AuthenticatePassword(ctx, "cacheduser", "password")

	if user1.Username != user2.Username {
		t.Error("expected cached user to match")
	}
}

func TestHashPassword(t *testing.T) {
	password := "testpassword123"

	hash, err := HashPassword(password)
	if err != nil {
		t.Fatalf("failed to hash password: %v", err)
	}

	if hash == "" {
		t.Error("expected non-empty hash")
	}
	if hash == password {
		t.Error("hash should not equal plaintext password")
	}
}

func TestVerifyPassword(t *testing.T) {
	password := "testpassword123"
	hash, _ := HashPassword(password)

	// Correct password.
	if !VerifyPassword(password, hash) {
		t.Error("expected verification to succeed")
	}

	// Wrong password.
	if VerifyPassword("wrongpassword", hash) {
		t.Error("expected verification to fail")
	}
}

func TestGenerateToken(t *testing.T) {
	token1, err := GenerateToken()
	if err != nil {
		t.Fatalf("failed to generate token: %v", err)
	}

	token2, err := GenerateToken()
	if err != nil {
		t.Fatalf("failed to generate second token: %v", err)
	}

	if token1 == "" {
		t.Error("expected non-empty token")
	}
	if token1 == token2 {
		t.Error("tokens should be unique")
	}
}

func TestHashToken(t *testing.T) {
	token := "test-token-123"

	hash1 := HashToken(token)
	hash2 := HashToken(token)

	if hash1 == "" {
		t.Error("expected non-empty hash")
	}
	if hash1 != hash2 {
		t.Error("same token should produce same hash")
	}
	if hash1 == token {
		t.Error("hash should not equal token")
	}
}

func TestVerifyToken(t *testing.T) {
	token := "test-token-123"
	hash := HashToken(token)

	if !VerifyToken(token, hash) {
		t.Error("expected verification to succeed")
	}

	if VerifyToken("wrong-token", hash) {
		t.Error("expected verification to fail")
	}
}

func TestSessionManager(t *testing.T) {
	store := createTestStore(t)
	defer store.Close()
	ctx := context.Background()

	// Create a user first.
	user := &storage.User{Username: "sessionuser"}
	store.CreateUser(ctx, user)

	sm := NewSessionManager(store, time.Hour)

	// Create session.
	token, err := sm.CreateSession(ctx, user.ID)
	if err != nil {
		t.Fatalf("failed to create session: %v", err)
	}
	if token == "" {
		t.Error("expected non-empty token")
	}

	// Validate session.
	userID, err := sm.ValidateSession(ctx, token)
	if err != nil {
		t.Fatalf("failed to validate session: %v", err)
	}
	if userID != user.ID {
		t.Error("expected user ID to match")
	}

	// Invalidate session.
	err = sm.InvalidateSession(ctx, token)
	if err != nil {
		t.Fatalf("failed to invalidate session: %v", err)
	}

	// Session should no longer be valid.
	_, err = sm.ValidateSession(ctx, token)
	if err == nil {
		t.Error("expected error for invalidated session")
	}
}

func TestSessionManager_InvalidToken(t *testing.T) {
	store := createTestStore(t)
	defer store.Close()
	ctx := context.Background()

	sm := NewSessionManager(store, time.Hour)

	_, err := sm.ValidateSession(ctx, "invalid-token")
	if err == nil {
		t.Error("expected error for invalid token")
	}
}

func TestSessionManager_InvalidateAllSessions(t *testing.T) {
	store := createTestStore(t)
	defer store.Close()
	ctx := context.Background()

	user := &storage.User{Username: "multiuser"}
	store.CreateUser(ctx, user)

	sm := NewSessionManager(store, time.Hour)

	// Create multiple sessions.
	token1, _ := sm.CreateSession(ctx, user.ID)
	token2, _ := sm.CreateSession(ctx, user.ID)

	// Invalidate all.
	err := sm.InvalidateAllSessions(ctx, user.ID)
	if err != nil {
		t.Fatalf("failed to invalidate all sessions: %v", err)
	}

	// Both should be invalid.
	_, err1 := sm.ValidateSession(ctx, token1)
	_, err2 := sm.ValidateSession(ctx, token2)

	if err1 == nil || err2 == nil {
		t.Error("expected all sessions to be invalidated")
	}
}

func TestTOTPManager(t *testing.T) {
	tm := NewTOTPManager("vc-jump")

	secret, err := tm.GenerateSecret()
	if err != nil {
		t.Fatalf("failed to generate secret: %v", err)
	}

	if secret == "" {
		t.Error("expected non-empty secret")
	}

	uri := tm.GetProvisioningURI("testuser", secret)
	if uri == "" {
		t.Error("expected non-empty URI")
	}
	if !contains(uri, "otpauth://totp/") {
		t.Error("expected valid TOTP URI format")
	}
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > 0 && containsHelper(s, substr))
}

func containsHelper(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

func createTestStore(t *testing.T) *storage.SQLiteStore {
	t.Helper()
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "test.db")

	cfg := config.StorageConfig{
		Type:   "sqlite",
		DBPath: dbPath,
	}

	store, err := storage.NewSQLiteStore(cfg)
	if err != nil {
		t.Fatalf("failed to create test store: %v", err)
	}

	return store
}
