package storage

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/Veritas-Calculus/vc-jump/internal/config"
	"github.com/google/uuid"
)

func newTestSQLiteStore(t *testing.T) *SQLiteStore {
	t.Helper()
	store, err := NewSQLiteStore(config.StorageConfig{
		Type:   "sqlite",
		DBPath: t.TempDir() + "/test.db",
	})
	if err != nil {
		t.Fatalf("failed to create test store: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })
	return store
}

// createTestUser creates a user in the DB and returns the user ID.
func createTestUser(t *testing.T, store *SQLiteStore, username string) string {
	t.Helper()
	userID := uuid.New().String()
	user := &User{
		ID:       userID,
		Username: username,
		Source:   UserSourceLocal,
		IsActive: true,
	}
	if err := store.CreateUser(context.Background(), user); err != nil {
		t.Fatalf("failed to create test user: %v", err)
	}
	return userID
}

func TestApiKey_CreateAndGet(t *testing.T) {
	store := newTestSQLiteStore(t)
	ctx := context.Background()
	userID := createTestUser(t, store, "testuser1")

	key := &ApiKey{
		UserID:      userID,
		Name:        "test-key",
		Description: "A test API key",
		TokenPrefix: "vcj_abcd1234",
		TokenHash:   "sha256hash123",
		Scopes:      []string{"host:view", "host:connect"},
	}

	// Create.
	err := store.CreateApiKey(ctx, key)
	if err != nil {
		t.Fatalf("CreateApiKey failed: %v", err)
	}
	if key.ID == "" {
		t.Fatal("expected ID to be set")
	}
	if !key.IsActive {
		t.Fatal("expected IsActive to be true")
	}

	// Get by ID.
	got, err := store.GetApiKey(ctx, key.ID)
	if err != nil {
		t.Fatalf("GetApiKey failed: %v", err)
	}
	if got.Name != "test-key" {
		t.Errorf("expected name 'test-key', got '%s'", got.Name)
	}
	if got.Description != "A test API key" {
		t.Errorf("expected description 'A test API key', got '%s'", got.Description)
	}
	if got.TokenPrefix != "vcj_abcd1234" {
		t.Errorf("expected token prefix 'vcj_abcd1234', got '%s'", got.TokenPrefix)
	}
	if len(got.Scopes) != 2 {
		t.Errorf("expected 2 scopes, got %d", len(got.Scopes))
	}
	if !got.IsActive {
		t.Error("expected IsActive to be true")
	}
}

func TestApiKey_GetByTokenHash(t *testing.T) {
	store := newTestSQLiteStore(t)
	ctx := context.Background()
	userID := createTestUser(t, store, "testuser2")

	key := &ApiKey{
		UserID:      userID,
		Name:        "hash-lookup-key",
		TokenPrefix: "vcj_00001111",
		TokenHash:   "unique_hash_value",
		Scopes:      []string{},
	}
	if err := store.CreateApiKey(ctx, key); err != nil {
		t.Fatalf("CreateApiKey failed: %v", err)
	}

	// Lookup by hash.
	got, err := store.GetApiKeyByTokenHash(ctx, "unique_hash_value")
	if err != nil {
		t.Fatalf("GetApiKeyByTokenHash failed: %v", err)
	}
	if got.ID != key.ID {
		t.Errorf("expected ID '%s', got '%s'", key.ID, got.ID)
	}

	// Lookup with wrong hash should fail.
	_, err = store.GetApiKeyByTokenHash(ctx, "wrong_hash")
	if err == nil {
		t.Fatal("expected error for non-existent hash")
	}
}

func TestApiKey_GetByTokenHash_InactiveKey(t *testing.T) {
	store := newTestSQLiteStore(t)
	ctx := context.Background()
	userID := createTestUser(t, store, "testuser3")

	key := &ApiKey{
		UserID:      userID,
		Name:        "inactive-key",
		TokenPrefix: "vcj_inactive",
		TokenHash:   "inactive_hash",
		Scopes:      []string{},
	}
	if err := store.CreateApiKey(ctx, key); err != nil {
		t.Fatalf("CreateApiKey failed: %v", err)
	}

	// Deactivate.
	if err := store.DeactivateApiKey(ctx, key.ID); err != nil {
		t.Fatalf("DeactivateApiKey failed: %v", err)
	}

	// Lookup by hash should fail for inactive key.
	_, err := store.GetApiKeyByTokenHash(ctx, "inactive_hash")
	if err == nil {
		t.Fatal("expected error for inactive key hash lookup")
	}
}

func TestApiKey_ListByUser(t *testing.T) {
	store := newTestSQLiteStore(t)
	ctx := context.Background()
	userA := createTestUser(t, store, "user-a")
	userB := createTestUser(t, store, "user-b")

	// Create 2 keys for user-a, 1 for user-b.
	userIDs := []string{userA, userA, userB}
	for i, uid := range userIDs {
		key := &ApiKey{
			UserID:      uid,
			Name:        fmt.Sprintf("key-%d", i),
			TokenPrefix: fmt.Sprintf("vcj_list%04d", i),
			TokenHash:   fmt.Sprintf("hash_list_%d", i),
			Scopes:      []string{},
		}
		if err := store.CreateApiKey(ctx, key); err != nil {
			t.Fatalf("CreateApiKey failed: %v", err)
		}
	}

	// List for user-a.
	keys, err := store.ListApiKeysByUser(ctx, userA)
	if err != nil {
		t.Fatalf("ListApiKeysByUser failed: %v", err)
	}
	if len(keys) != 2 {
		t.Errorf("expected 2 keys for user-a, got %d", len(keys))
	}

	// List for user-b.
	keys, err = store.ListApiKeysByUser(ctx, userB)
	if err != nil {
		t.Fatalf("ListApiKeysByUser failed: %v", err)
	}
	if len(keys) != 1 {
		t.Errorf("expected 1 key for user-b, got %d", len(keys))
	}

	// List for non-existent user.
	keys, err = store.ListApiKeysByUser(ctx, "user-z")
	if err != nil {
		t.Fatalf("ListApiKeysByUser failed: %v", err)
	}
	if len(keys) != 0 {
		t.Errorf("expected 0 keys for user-z, got %d", len(keys))
	}
}

func TestApiKey_UpdateLastUsed(t *testing.T) {
	store := newTestSQLiteStore(t)
	ctx := context.Background()
	userID := createTestUser(t, store, "testuser5")

	key := &ApiKey{
		UserID:      userID,
		Name:        "last-used-key",
		TokenPrefix: "vcj_lastused",
		TokenHash:   "hash_last_used",
		Scopes:      []string{},
	}
	if err := store.CreateApiKey(ctx, key); err != nil {
		t.Fatalf("CreateApiKey failed: %v", err)
	}

	// Initially last_used_at should be nil.
	got, _ := store.GetApiKey(ctx, key.ID)
	if got.LastUsedAt != nil {
		t.Error("expected LastUsedAt to be nil initially")
	}

	// Update.
	if err := store.UpdateApiKeyLastUsed(ctx, key.ID); err != nil {
		t.Fatalf("UpdateApiKeyLastUsed failed: %v", err)
	}

	// Should now have a timestamp.
	got, _ = store.GetApiKey(ctx, key.ID)
	if got.LastUsedAt == nil {
		t.Error("expected LastUsedAt to be set after update")
	}
}

func TestApiKey_Deactivate(t *testing.T) {
	store := newTestSQLiteStore(t)
	ctx := context.Background()
	userID := createTestUser(t, store, "testuser6")

	key := &ApiKey{
		UserID:      userID,
		Name:        "deactivate-key",
		TokenPrefix: "vcj_deactiv8",
		TokenHash:   "hash_deactivate",
		Scopes:      []string{},
	}
	if err := store.CreateApiKey(ctx, key); err != nil {
		t.Fatalf("CreateApiKey failed: %v", err)
	}

	// Deactivate.
	if err := store.DeactivateApiKey(ctx, key.ID); err != nil {
		t.Fatalf("DeactivateApiKey failed: %v", err)
	}

	// Verify.
	got, _ := store.GetApiKey(ctx, key.ID)
	if got.IsActive {
		t.Error("expected IsActive to be false after deactivation")
	}

	// Deactivating a non-existent key should error.
	err := store.DeactivateApiKey(ctx, "non-existent")
	if err == nil {
		t.Error("expected error for deactivating non-existent key")
	}
}

func TestApiKey_Delete(t *testing.T) {
	store := newTestSQLiteStore(t)
	ctx := context.Background()
	userID := createTestUser(t, store, "testuser7")

	key := &ApiKey{
		UserID:      userID,
		Name:        "delete-key",
		TokenPrefix: "vcj_delete00",
		TokenHash:   "hash_delete",
		Scopes:      []string{},
	}
	if err := store.CreateApiKey(ctx, key); err != nil {
		t.Fatalf("CreateApiKey failed: %v", err)
	}

	// Delete.
	if err := store.DeleteApiKey(ctx, key.ID); err != nil {
		t.Fatalf("DeleteApiKey failed: %v", err)
	}

	// Should not be found anymore.
	_, err := store.GetApiKey(ctx, key.ID)
	if err == nil {
		t.Error("expected error after deletion")
	}

	// Deleting again should error.
	err = store.DeleteApiKey(ctx, key.ID)
	if err == nil {
		t.Error("expected error for deleting non-existent key")
	}
}

func TestApiKey_DeleteByUser(t *testing.T) {
	store := newTestSQLiteStore(t)
	ctx := context.Background()
	userID := createTestUser(t, store, "cleanup-user")

	for i := 0; i < 3; i++ {
		key := &ApiKey{
			UserID:      userID,
			Name:        fmt.Sprintf("cleanup-key-%d", i),
			TokenPrefix: fmt.Sprintf("vcj_clean%03d", i),
			TokenHash:   fmt.Sprintf("hash_cleanup_%d", i),
			Scopes:      []string{},
		}
		if err := store.CreateApiKey(ctx, key); err != nil {
			t.Fatalf("CreateApiKey failed: %v", err)
		}
	}

	// Delete all for user.
	if err := store.DeleteApiKeysByUser(ctx, userID); err != nil {
		t.Fatalf("DeleteApiKeysByUser failed: %v", err)
	}

	keys, _ := store.ListApiKeysByUser(ctx, userID)
	if len(keys) != 0 {
		t.Errorf("expected 0 keys after cleanup, got %d", len(keys))
	}
}

func TestApiKey_WithExpiry(t *testing.T) {
	store := newTestSQLiteStore(t)
	ctx := context.Background()
	userID := createTestUser(t, store, "testuser9")

	expires := time.Now().Add(24 * time.Hour)
	key := &ApiKey{
		UserID:      userID,
		Name:        "expiring-key",
		TokenPrefix: "vcj_expiring",
		TokenHash:   "hash_expiring",
		Scopes:      []string{"host:view"},
		ExpiresAt:   &expires,
	}
	if err := store.CreateApiKey(ctx, key); err != nil {
		t.Fatalf("CreateApiKey failed: %v", err)
	}

	got, _ := store.GetApiKey(ctx, key.ID)
	if got.ExpiresAt == nil {
		t.Fatal("expected ExpiresAt to be set")
	}
	if got.ExpiresAt.Before(time.Now()) {
		t.Error("expected ExpiresAt to be in the future")
	}
}

func TestApiKey_NilScopes(t *testing.T) {
	store := newTestSQLiteStore(t)
	ctx := context.Background()
	userID := createTestUser(t, store, "testuser10")

	key := &ApiKey{
		UserID:      userID,
		Name:        "nil-scopes-key",
		TokenPrefix: "vcj_nilscope",
		TokenHash:   "hash_nil_scopes",
		Scopes:      nil,
	}
	if err := store.CreateApiKey(ctx, key); err != nil {
		t.Fatalf("CreateApiKey failed: %v", err)
	}

	got, _ := store.GetApiKey(ctx, key.ID)
	// nil scopes marshalled as "null" should unmarshal to nil.
	if len(got.Scopes) != 0 {
		t.Errorf("expected nil or empty scopes, got %v", got.Scopes)
	}
}
