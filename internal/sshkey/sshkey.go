// Package sshkey provides SSH key management functionality.
package sshkey

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"time"

	"github.com/Veritas-Calculus/vc-jump/internal/storage"
	"golang.org/x/crypto/ssh"
)

// KeyType represents the type of SSH key.
type KeyType string

const (
	KeyTypeED25519 KeyType = "ed25519"
	KeyTypeRSA4096 KeyType = "rsa-4096"
	KeyTypeRSA2048 KeyType = "rsa-2048"
)

// Manager handles SSH key operations.
type Manager struct {
	store *storage.SQLiteStore
}

// New creates a new SSH key manager.
func New(store *storage.SQLiteStore) *Manager {
	return &Manager{store: store}
}

// GenerateKey generates a new SSH key pair.
func (m *Manager) GenerateKey(ctx context.Context, name string, keyType KeyType) (*storage.SSHKey, error) {
	if name == "" {
		return nil, errors.New("key name cannot be empty")
	}

	var privateKeyPEM, publicKeyStr, fingerprint string
	var err error

	switch keyType {
	case KeyTypeED25519:
		privateKeyPEM, publicKeyStr, fingerprint, err = generateED25519Key()
	case KeyTypeRSA4096:
		privateKeyPEM, publicKeyStr, fingerprint, err = generateRSAKey(4096)
	case KeyTypeRSA2048:
		privateKeyPEM, publicKeyStr, fingerprint, err = generateRSAKey(2048)
	default:
		return nil, fmt.Errorf("unsupported key type: %s", keyType)
	}

	if err != nil {
		return nil, fmt.Errorf("failed to generate key: %w", err)
	}

	key := &storage.SSHKey{
		Name:        name,
		PrivateKey:  privateKeyPEM,
		PublicKey:   publicKeyStr,
		Fingerprint: fingerprint,
		KeyType:     string(keyType),
		CreatedAt:   time.Now(),
	}

	if err := m.store.CreateSSHKey(ctx, key); err != nil {
		return nil, fmt.Errorf("failed to save key: %w", err)
	}

	return key, nil
}

// GetKey retrieves an SSH key by ID.
func (m *Manager) GetKey(ctx context.Context, id string) (*storage.SSHKey, error) {
	return m.store.GetSSHKey(ctx, id)
}

// GetKeyByFingerprint retrieves an SSH key by fingerprint.
func (m *Manager) GetKeyByFingerprint(ctx context.Context, fingerprint string) (*storage.SSHKey, error) {
	return m.store.GetSSHKeyByFingerprint(ctx, fingerprint)
}

// ListKeys returns all SSH keys.
func (m *Manager) ListKeys(ctx context.Context) ([]storage.SSHKey, error) {
	return m.store.ListSSHKeys(ctx)
}

// DeleteKey deletes an SSH key.
func (m *Manager) DeleteKey(ctx context.Context, id string) error {
	return m.store.DeleteSSHKey(ctx, id)
}

// GetSigner returns an SSH signer for the given key.
func (m *Manager) GetSigner(ctx context.Context, keyID string) (ssh.Signer, error) {
	key, err := m.store.GetSSHKey(ctx, keyID)
	if err != nil {
		return nil, err
	}

	signer, err := ssh.ParsePrivateKey([]byte(key.PrivateKey))
	if err != nil {
		return nil, fmt.Errorf("failed to parse private key: %w", err)
	}

	return signer, nil
}

// ImportKey imports an existing SSH key.
func (m *Manager) ImportKey(ctx context.Context, name string, privateKeyPEM string) (*storage.SSHKey, error) {
	if name == "" {
		return nil, errors.New("key name cannot be empty")
	}
	if privateKeyPEM == "" {
		return nil, errors.New("private key cannot be empty")
	}

	// Parse and validate the private key.
	signer, err := ssh.ParsePrivateKey([]byte(privateKeyPEM))
	if err != nil {
		return nil, fmt.Errorf("failed to parse private key: %w", err)
	}

	publicKey := signer.PublicKey()
	publicKeyStr := string(ssh.MarshalAuthorizedKey(publicKey))
	fingerprint := ssh.FingerprintSHA256(publicKey)

	// Determine key type.
	keyType := publicKey.Type()

	key := &storage.SSHKey{
		Name:        name,
		PrivateKey:  privateKeyPEM,
		PublicKey:   publicKeyStr,
		Fingerprint: fingerprint,
		KeyType:     keyType,
		CreatedAt:   time.Now(),
	}

	if err := m.store.CreateSSHKey(ctx, key); err != nil {
		return nil, fmt.Errorf("failed to save key: %w", err)
	}

	return key, nil
}

func generateED25519Key() (privateKeyPEM, publicKeyStr, fingerprint string, err error) {
	pubKey, privKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return "", "", "", err
	}

	pemBlock, err := ssh.MarshalPrivateKey(privKey, "")
	if err != nil {
		return "", "", "", err
	}

	privateKeyPEM = string(pem.EncodeToMemory(pemBlock))

	sshPubKey, err := ssh.NewPublicKey(pubKey)
	if err != nil {
		return "", "", "", err
	}

	publicKeyStr = string(ssh.MarshalAuthorizedKey(sshPubKey))
	fingerprint = ssh.FingerprintSHA256(sshPubKey)

	return privateKeyPEM, publicKeyStr, fingerprint, nil
}

func generateRSAKey(bits int) (privateKeyPEM, publicKeyStr, fingerprint string, err error) {
	privKey, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		return "", "", "", err
	}

	privKeyBytes := x509.MarshalPKCS1PrivateKey(privKey)
	pemBlock := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: privKeyBytes,
	}
	privateKeyPEM = string(pem.EncodeToMemory(pemBlock))

	sshPubKey, err := ssh.NewPublicKey(&privKey.PublicKey)
	if err != nil {
		return "", "", "", err
	}

	publicKeyStr = string(ssh.MarshalAuthorizedKey(sshPubKey))
	fingerprint = ssh.FingerprintSHA256(sshPubKey)

	return privateKeyPEM, publicKeyStr, fingerprint, nil
}

// RotateKey generates a new key and optionally deletes the old one.
func (m *Manager) RotateKey(ctx context.Context, oldKeyID, newName string, keyType KeyType, deleteOld bool) (*storage.SSHKey, error) {
	// Generate new key.
	newKey, err := m.GenerateKey(ctx, newName, keyType)
	if err != nil {
		return nil, err
	}

	// Delete old key if requested.
	if deleteOld && oldKeyID != "" {
		if err := m.DeleteKey(ctx, oldKeyID); err != nil {
			// Log but don't fail - new key was created.
			return newKey, nil
		}
	}

	return newKey, nil
}

// GetPublicKey returns the public key string for a key ID.
func (m *Manager) GetPublicKey(ctx context.Context, keyID string) (string, error) {
	key, err := m.store.GetSSHKey(ctx, keyID)
	if err != nil {
		return "", err
	}
	return key.PublicKey, nil
}
