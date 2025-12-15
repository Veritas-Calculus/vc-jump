package sshkey

import (
	"context"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Veritas-Calculus/vc-jump/internal/config"
	"github.com/Veritas-Calculus/vc-jump/internal/storage"
)

func TestManager_GenerateKey_ED25519(t *testing.T) {
	store := createTestStore(t)
	defer store.Close()

	manager := New(store)
	ctx := context.Background()

	key, err := manager.GenerateKey(ctx, "test-ed25519", KeyTypeED25519)
	if err != nil {
		t.Fatalf("failed to generate ED25519 key: %v", err)
	}

	if key.ID == "" {
		t.Error("expected key ID to be set")
	}
	if key.Name != "test-ed25519" {
		t.Errorf("expected name test-ed25519, got %s", key.Name)
	}
	if !strings.HasPrefix(key.Fingerprint, "SHA256:") {
		t.Error("expected SHA256 fingerprint")
	}
	if !strings.HasPrefix(key.PublicKey, "ssh-ed25519") {
		t.Error("expected ssh-ed25519 public key")
	}
	if !strings.Contains(key.PrivateKey, "PRIVATE KEY") {
		t.Error("expected private key in PEM format")
	}
}

func TestManager_GenerateKey_RSA4096(t *testing.T) {
	store := createTestStore(t)
	defer store.Close()

	manager := New(store)
	ctx := context.Background()

	key, err := manager.GenerateKey(ctx, "test-rsa", KeyTypeRSA4096)
	if err != nil {
		t.Fatalf("failed to generate RSA key: %v", err)
	}

	if key.KeyType != string(KeyTypeRSA4096) {
		t.Errorf("expected key type %s, got %s", KeyTypeRSA4096, key.KeyType)
	}
	if !strings.HasPrefix(key.PublicKey, "ssh-rsa") {
		t.Error("expected ssh-rsa public key")
	}
}

func TestManager_GenerateKey_EmptyName(t *testing.T) {
	store := createTestStore(t)
	defer store.Close()

	manager := New(store)
	ctx := context.Background()

	_, err := manager.GenerateKey(ctx, "", KeyTypeED25519)
	if err == nil {
		t.Error("expected error for empty name")
	}
}

func TestManager_GenerateKey_InvalidType(t *testing.T) {
	store := createTestStore(t)
	defer store.Close()

	manager := New(store)
	ctx := context.Background()

	_, err := manager.GenerateKey(ctx, "test", KeyType("invalid"))
	if err == nil {
		t.Error("expected error for invalid key type")
	}
}

func TestManager_GetKey(t *testing.T) {
	store := createTestStore(t)
	defer store.Close()

	manager := New(store)
	ctx := context.Background()

	created, _ := manager.GenerateKey(ctx, "test-get", KeyTypeED25519)

	retrieved, err := manager.GetKey(ctx, created.ID)
	if err != nil {
		t.Fatalf("failed to get key: %v", err)
	}

	if retrieved.Name != created.Name {
		t.Errorf("expected name %s, got %s", created.Name, retrieved.Name)
	}
}

func TestManager_GetKeyByFingerprint(t *testing.T) {
	store := createTestStore(t)
	defer store.Close()

	manager := New(store)
	ctx := context.Background()

	created, _ := manager.GenerateKey(ctx, "test-fingerprint", KeyTypeED25519)

	retrieved, err := manager.GetKeyByFingerprint(ctx, created.Fingerprint)
	if err != nil {
		t.Fatalf("failed to get key by fingerprint: %v", err)
	}

	if retrieved.ID != created.ID {
		t.Errorf("expected ID %s, got %s", created.ID, retrieved.ID)
	}
}

func TestManager_ListKeys(t *testing.T) {
	store := createTestStore(t)
	defer store.Close()

	manager := New(store)
	ctx := context.Background()

	manager.GenerateKey(ctx, "key1", KeyTypeED25519)
	manager.GenerateKey(ctx, "key2", KeyTypeED25519)

	keys, err := manager.ListKeys(ctx)
	if err != nil {
		t.Fatalf("failed to list keys: %v", err)
	}

	if len(keys) != 2 {
		t.Errorf("expected 2 keys, got %d", len(keys))
	}
}

func TestManager_DeleteKey(t *testing.T) {
	store := createTestStore(t)
	defer store.Close()

	manager := New(store)
	ctx := context.Background()

	key, _ := manager.GenerateKey(ctx, "test-delete", KeyTypeED25519)

	err := manager.DeleteKey(ctx, key.ID)
	if err != nil {
		t.Fatalf("failed to delete key: %v", err)
	}

	_, err = manager.GetKey(ctx, key.ID)
	if err == nil {
		t.Error("expected error after delete")
	}
}

func TestManager_GetSigner(t *testing.T) {
	store := createTestStore(t)
	defer store.Close()

	manager := New(store)
	ctx := context.Background()

	key, _ := manager.GenerateKey(ctx, "test-signer", KeyTypeED25519)

	signer, err := manager.GetSigner(ctx, key.ID)
	if err != nil {
		t.Fatalf("failed to get signer: %v", err)
	}

	if signer == nil {
		t.Error("expected signer to be non-nil")
	}

	// Verify the signer produces valid signatures.
	pubKey := signer.PublicKey()
	if pubKey == nil {
		t.Error("expected public key from signer")
	}
}

func TestManager_ImportKey(t *testing.T) {
	store := createTestStore(t)
	defer store.Close()

	manager := New(store)
	ctx := context.Background()

	// Generate a key first to get a valid private key.
	generated, _ := manager.GenerateKey(ctx, "temp", KeyTypeED25519)
	privateKeyPEM := generated.PrivateKey

	// Delete the temp key.
	manager.DeleteKey(ctx, generated.ID)

	// Import the key.
	imported, err := manager.ImportKey(ctx, "imported-key", privateKeyPEM)
	if err != nil {
		t.Fatalf("failed to import key: %v", err)
	}

	if imported.Name != "imported-key" {
		t.Errorf("expected name imported-key, got %s", imported.Name)
	}
	if imported.Fingerprint != generated.Fingerprint {
		t.Error("expected fingerprints to match")
	}
}

func TestManager_ImportKey_InvalidKey(t *testing.T) {
	store := createTestStore(t)
	defer store.Close()

	manager := New(store)
	ctx := context.Background()

	_, err := manager.ImportKey(ctx, "bad-key", "not a valid key")
	if err == nil {
		t.Error("expected error for invalid key")
	}
}

func TestManager_RotateKey(t *testing.T) {
	store := createTestStore(t)
	defer store.Close()

	manager := New(store)
	ctx := context.Background()

	oldKey, _ := manager.GenerateKey(ctx, "old-key", KeyTypeED25519)

	newKey, err := manager.RotateKey(ctx, oldKey.ID, "new-key", KeyTypeED25519, true)
	if err != nil {
		t.Fatalf("failed to rotate key: %v", err)
	}

	if newKey.Name != "new-key" {
		t.Errorf("expected name new-key, got %s", newKey.Name)
	}

	// Old key should be deleted.
	_, err = manager.GetKey(ctx, oldKey.ID)
	if err == nil {
		t.Error("expected old key to be deleted")
	}
}

func TestManager_GetPublicKey(t *testing.T) {
	store := createTestStore(t)
	defer store.Close()

	manager := New(store)
	ctx := context.Background()

	key, _ := manager.GenerateKey(ctx, "test-pubkey", KeyTypeED25519)

	pubKey, err := manager.GetPublicKey(ctx, key.ID)
	if err != nil {
		t.Fatalf("failed to get public key: %v", err)
	}

	if !strings.HasPrefix(pubKey, "ssh-ed25519") {
		t.Error("expected ssh-ed25519 public key")
	}
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
