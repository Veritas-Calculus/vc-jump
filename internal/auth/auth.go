// Package auth provides authentication and authorization for vc-jump.
package auth

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/Veritas-Calculus/vc-jump/internal/config"
	"github.com/Veritas-Calculus/vc-jump/internal/storage"
	"golang.org/x/crypto/bcrypt"
	"golang.org/x/crypto/ssh"
)

// User represents an authenticated user.
type User struct {
	ID           string    `json:"id"`
	Username     string    `json:"username"`
	Groups       []string  `json:"groups"`
	AllowedHosts []string  `json:"allowed_hosts"`
	ExpiresAt    time.Time `json:"expires_at"`
}

// Authenticator handles user authentication.
type Authenticator struct {
	cfg   config.AuthConfig
	store *storage.SQLiteStore
	cache *authCache
}

type authCache struct {
	path    string
	entries map[string]*User
	mu      sync.RWMutex
}

// New creates a new Authenticator with the given configuration (legacy support).
func New(cfg config.AuthConfig) (*Authenticator, error) {
	cache := &authCache{
		path:    cfg.CachePath,
		entries: make(map[string]*User),
	}

	// Ensure cache directory exists.
	if cfg.CachePath != "" {
		if err := os.MkdirAll(cfg.CachePath, 0700); err != nil {
			return nil, fmt.Errorf("failed to create cache directory: %w", err)
		}
	}

	return &Authenticator{
		cfg:   cfg,
		cache: cache,
	}, nil
}

// NewWithStore creates a new Authenticator with database store.
func NewWithStore(cfg config.AuthConfig, store *storage.SQLiteStore) (*Authenticator, error) {
	cache := &authCache{
		entries: make(map[string]*User),
	}

	return &Authenticator{
		cfg:   cfg,
		store: store,
		cache: cache,
	}, nil
}

// AuthenticatePassword authenticates a user with username and password.
func (a *Authenticator) AuthenticatePassword(ctx context.Context, username, password string) (*User, error) {
	if username == "" {
		return nil, errors.New("username cannot be empty")
	}
	if password == "" {
		return nil, errors.New("password cannot be empty")
	}

	cacheKey := a.cacheKey(username, password)

	// If store is available, always verify against database first.
	if a.store != nil {
		user, err := a.authenticateFromStore(ctx, username, password)
		if err == nil {
			user.ExpiresAt = time.Now().Add(a.cfg.CacheDuration)
			a.cache.set(cacheKey, user)
			return user, nil
		}
		// Clear cache on auth failure.
		a.cache.delete(cacheKey)
		// If user exists but password wrong or disabled, return error.
		if !strings.Contains(err.Error(), "not found") {
			return nil, err
		}
	}

	// Fallback to SSO if configured.
	if a.cfg.SSOEndpoint != "" {
		return a.authenticateSSO(ctx, username, password)
	}

	return nil, errors.New("authentication failed: user not found")
}

func (a *Authenticator) authenticateFromStore(ctx context.Context, username, password string) (*User, error) {
	userWithPwd, err := a.store.GetUserWithPassword(ctx, username)
	if err != nil {
		return nil, err
	}

	if !userWithPwd.IsActive {
		return nil, errors.New("user account is disabled")
	}

	// Verify password.
	if err := bcrypt.CompareHashAndPassword([]byte(userWithPwd.PasswordHash), []byte(password)); err != nil {
		return nil, errors.New("invalid password")
	}

	// Update last login.
	_ = a.store.UpdateUserLastLogin(ctx, userWithPwd.ID)

	return &User{
		ID:           userWithPwd.ID,
		Username:     userWithPwd.Username,
		Groups:       userWithPwd.Groups,
		AllowedHosts: userWithPwd.AllowedHosts,
	}, nil
}

// AuthenticatePublicKey authenticates a user with a public key.
// The user must exist in the database and have a matching public key registered.
func (a *Authenticator) AuthenticatePublicKey(ctx context.Context, username string, key ssh.PublicKey) (*User, error) {
	if username == "" {
		return nil, errors.New("username cannot be empty")
	}
	if key == nil {
		return nil, errors.New("public key cannot be nil")
	}

	// Must have a store for public key authentication.
	if a.store == nil {
		return nil, errors.New("public key authentication requires database storage")
	}

	fingerprint := ssh.FingerprintSHA256(key)
	cacheKey := a.cacheKeyPublicKey(username, fingerprint)

	// Always verify user exists and is active in database first.
	dbUser, err := a.store.GetUserByUsername(ctx, username)
	if err != nil {
		// User not found - clear any cached entry and return error.
		a.cache.delete(cacheKey)
		return nil, errors.New("user not found")
	}

	if !dbUser.IsActive {
		a.cache.delete(cacheKey)
		return nil, errors.New("user account is disabled")
	}

	// User exists - verify the public key matches.
	if !a.verifyUserPublicKey(dbUser, fingerprint) {
		return nil, errors.New("public key not authorized for this user")
	}

	// Check cache for this user+key combo.
	if user := a.cache.get(cacheKey); user != nil {
		if time.Now().Before(user.ExpiresAt) {
			return user, nil
		}
		a.cache.delete(cacheKey)
	}

	// Update last login.
	_ = a.store.UpdateUserLastLogin(ctx, dbUser.ID)

	user := &User{
		ID:           dbUser.ID,
		Username:     dbUser.Username,
		Groups:       dbUser.Groups,
		AllowedHosts: dbUser.AllowedHosts,
		ExpiresAt:    time.Now().Add(a.cfg.CacheDuration),
	}
	a.cache.set(cacheKey, user)
	return user, nil
}

// verifyUserPublicKey checks if the provided key matches any of the user's registered keys.
func (a *Authenticator) verifyUserPublicKey(user *storage.User, fingerprint string) bool {
	// Check if user has any registered public keys.
	for _, storedKey := range user.PublicKeys {
		// Parse stored key to compare.
		storedPubKey, _, _, _, err := ssh.ParseAuthorizedKey([]byte(storedKey))
		if err != nil {
			continue
		}
		storedFingerprint := ssh.FingerprintSHA256(storedPubKey)
		if storedFingerprint == fingerprint {
			return true
		}
	}

	return false
}

// cacheKeyHMACSecret is used for HMAC-based cache key generation.
// This is a fixed key used only for cache indexing, not for security.
var cacheKeyHMACSecret = []byte("vc-jump-cache-key-v1")

func (a *Authenticator) cacheKey(username, password string) string {
	h := hmac.New(sha256.New, cacheKeyHMACSecret)
	h.Write([]byte(username))
	h.Write([]byte(":"))
	h.Write([]byte(password))
	return hex.EncodeToString(h.Sum(nil))
}

func (a *Authenticator) cacheKeyPublicKey(username, fingerprint string) string {
	h := hmac.New(sha256.New, cacheKeyHMACSecret)
	h.Write([]byte(username))
	h.Write([]byte(":"))
	h.Write([]byte(fingerprint))
	return hex.EncodeToString(h.Sum(nil))
}

func (a *Authenticator) authenticateSSO(_ context.Context, username, password string) (*User, error) {
	if a.cfg.SSOEndpoint == "" {
		return nil, errors.New("SSO endpoint not configured")
	}

	// TODO: Implement actual SSO authentication.
	_ = username
	_ = password
	return nil, errors.New("SSO authentication not implemented")
}

func (c *authCache) get(key string) *User {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.entries[key]
}

func (c *authCache) set(key string, user *User) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.entries[key] = user
}

func (c *authCache) delete(key string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.entries, key)
}

// HashPassword creates a bcrypt hash of the password.
func HashPassword(password string) (string, error) {
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return "", err
	}
	return string(hash), nil
}

// VerifyPassword verifies a password against a hash.
func VerifyPassword(password, hash string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	return err == nil
}

// GenerateToken generates a secure random token.
func GenerateToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(b), nil
}

// HashToken creates a SHA256 hash of a token.
func HashToken(token string) string {
	h := sha256.Sum256([]byte(token))
	return hex.EncodeToString(h[:])
}

// VerifyToken compares a token with its hash.
func VerifyToken(token, hash string) bool {
	tokenHash := HashToken(token)
	return subtle.ConstantTimeCompare([]byte(tokenHash), []byte(hash)) == 1
}

// SessionManager manages user sessions.
type SessionManager struct {
	store           *storage.SQLiteStore
	sessionDuration time.Duration
}

// NewSessionManager creates a new session manager.
func NewSessionManager(store *storage.SQLiteStore, duration time.Duration) *SessionManager {
	return &SessionManager{
		store:           store,
		sessionDuration: duration,
	}
}

// CreateSession creates a new session for a user.
func (sm *SessionManager) CreateSession(ctx context.Context, userID string) (string, error) {
	token, err := GenerateToken()
	if err != nil {
		return "", err
	}

	tokenHash := HashToken(token)
	sessionToken := &storage.Token{
		UserID:    userID,
		TokenHash: tokenHash,
		TokenType: "session",
		ExpiresAt: time.Now().Add(sm.sessionDuration),
	}

	if err := sm.store.CreateToken(ctx, sessionToken); err != nil {
		return "", err
	}

	return token, nil
}

// ValidateSession validates a session token and returns the user ID.
func (sm *SessionManager) ValidateSession(ctx context.Context, token string) (string, error) {
	tokenHash := HashToken(token)

	storedToken, err := sm.store.GetTokenByHash(ctx, tokenHash)
	if err != nil {
		return "", errors.New("invalid session")
	}

	if time.Now().After(storedToken.ExpiresAt) {
		_ = sm.store.DeleteToken(ctx, storedToken.ID)
		return "", errors.New("session expired")
	}

	return storedToken.UserID, nil
}

// InvalidateSession invalidates a session token.
func (sm *SessionManager) InvalidateSession(ctx context.Context, token string) error {
	tokenHash := HashToken(token)
	storedToken, err := sm.store.GetTokenByHash(ctx, tokenHash)
	if err != nil {
		return nil // Already invalid.
	}
	return sm.store.DeleteToken(ctx, storedToken.ID)
}

// InvalidateAllSessions invalidates all sessions for a user.
func (sm *SessionManager) InvalidateAllSessions(ctx context.Context, userID string) error {
	return sm.store.DeleteUserTokens(ctx, userID)
}

// CleanupExpiredSessions removes expired sessions.
func (sm *SessionManager) CleanupExpiredSessions(ctx context.Context) error {
	return sm.store.DeleteExpiredTokens(ctx)
}

// TOTPManager handles TOTP (Time-based One-Time Password) operations.
type TOTPManager struct {
	issuer string
}

// NewTOTPManager creates a new TOTP manager.
func NewTOTPManager(issuer string) *TOTPManager {
	return &TOTPManager{issuer: issuer}
}

// GenerateSecret generates a new TOTP secret.
func (tm *TOTPManager) GenerateSecret() (string, error) {
	secret := make([]byte, 20)
	if _, err := rand.Read(secret); err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(secret), nil
}

// GetProvisioningURI generates a provisioning URI for authenticator apps.
func (tm *TOTPManager) GetProvisioningURI(username, secret string) string {
	return fmt.Sprintf("otpauth://totp/%s:%s?secret=%s&issuer=%s",
		tm.issuer, username, secret, tm.issuer)
}

// Unused variable to prevent import error.
var _ = filepath.Join
