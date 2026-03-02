// Package storage provides data persistence for vc-jump.
package storage

import (
	"context"
	"fmt"
	"time"

	"github.com/Veritas-Calculus/vc-jump/internal/config"
)

// Folder represents a folder for organizing hosts in a tree structure.
type Folder struct {
	ID          string    `json:"id"`
	Name        string    `json:"name"`
	ParentID    string    `json:"parent_id,omitempty"` // Empty for root folders.
	Path        string    `json:"path"`                // Full path like "/prod/web-servers".
	Description string    `json:"description,omitempty"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

// Host represents a host record in storage.
type Host struct {
	ID                    string    `json:"id"`
	Name                  string    `json:"name"`
	Addr                  string    `json:"addr"`
	Port                  int       `json:"port"`
	User                  string    `json:"user"`  // SSH username for target host.
	Users                 []string  `json:"users"` // Deprecated: use User field.
	Groups                []string  `json:"groups"`
	FolderID              string    `json:"folder_id,omitempty"` // Folder this host belongs to.
	KeyID                 string    `json:"key_id,omitempty"`    // Reference to SSH key in database.
	KeyPath               string    `json:"key_path,omitempty"`  // File path for backward compatibility.
	InsecureIgnoreHostKey bool      `json:"insecure_ignore_host_key,omitempty"`
	CreatedAt             time.Time `json:"created_at"`
	UpdatedAt             time.Time `json:"updated_at"`
}

// UserSource represents the authentication source of a user.
type UserSource string

const (
	UserSourceLocal UserSource = "local" // Created via Dashboard.
	UserSourceSSH   UserSource = "ssh"   // Created via SSH public key auth.
	UserSourceOIDC  UserSource = "oidc"  // Created via OIDC/SSO.
)

// User represents a user record in storage.
type User struct {
	ID           string     `json:"id"`
	Username     string     `json:"username"`
	PasswordHash string     `json:"password_hash,omitempty"`
	Groups       []string   `json:"groups"`
	PublicKeys   []string   `json:"public_keys"`
	AllowedHosts []string   `json:"allowed_hosts"` // Host IDs user can access.
	Source       UserSource `json:"source"`        // local, ssh, oidc.
	IsActive     bool       `json:"is_active"`
	// OTP fields.
	OTPSecret   string `json:"otp_secret,omitempty"` // TOTP secret key.
	OTPEnabled  bool   `json:"otp_enabled"`          // User has enabled OTP.
	OTPVerified bool   `json:"otp_verified"`         // User has verified OTP setup.
	// Timestamps.
	LastLoginAt time.Time `json:"last_login_at,omitempty"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

// Session represents a session record in storage.
type Session struct {
	ID         string    `json:"id"`
	Username   string    `json:"username"`
	SourceIP   string    `json:"source_ip"`
	TargetHost string    `json:"target_host"`
	StartTime  time.Time `json:"start_time"`
	EndTime    time.Time `json:"end_time,omitempty"`
	Recording  string    `json:"recording,omitempty"`
}

// AuditLog represents an audit log entry.
type AuditLog struct {
	ID         string                 `json:"id"`
	Timestamp  time.Time              `json:"timestamp"`
	EventType  string                 `json:"event_type"`
	Username   string                 `json:"username"`
	SourceIP   string                 `json:"source_ip,omitempty"`
	TargetHost string                 `json:"target_host,omitempty"`
	Action     string                 `json:"action"`
	Result     string                 `json:"result"`
	Details    map[string]interface{} `json:"details,omitempty"`
	CreatedAt  time.Time              `json:"created_at"`
}

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

// RecordingStorageType represents where the recording is stored.
type RecordingStorageType string

const (
	RecordingStorageLocal RecordingStorageType = "local"
	RecordingStorageS3    RecordingStorageType = "s3"
)

// Recording represents a session recording metadata in storage.
type Recording struct {
	ID          string               `json:"id"`
	SessionID   string               `json:"session_id"`          // Reference to session.
	Username    string               `json:"username"`            // User who created the recording.
	HostName    string               `json:"hostname"`            // Target host name.
	Filename    string               `json:"filename"`            // Recording filename.
	StorageType RecordingStorageType `json:"storage_type"`        // local or s3.
	StoragePath string               `json:"storage_path"`        // Local path or S3 bucket/key.
	S3Bucket    string               `json:"s3_bucket,omitempty"` // S3 bucket name.
	S3Key       string               `json:"s3_key,omitempty"`    // S3 object key.
	FileSize    int64                `json:"file_size"`           // Size in bytes.
	Duration    int64                `json:"duration"`            // Duration in seconds.
	StartTime   time.Time            `json:"start_time"`          // Recording start time.
	EndTime     time.Time            `json:"end_time,omitempty"`  // Recording end time.
	Checksum    string               `json:"checksum,omitempty"`  // SHA256 checksum for integrity.
	IsComplete  bool                 `json:"is_complete"`         // Whether recording finished normally.
	CreatedAt   time.Time            `json:"created_at"`
	UpdatedAt   time.Time            `json:"updated_at"`
}

// HostStore defines host operations.
type HostStore interface {
	GetHost(ctx context.Context, id string) (*Host, error)
	GetHostByName(ctx context.Context, name string) (*Host, error)
	ListHosts(ctx context.Context) ([]Host, error)
	CreateHost(ctx context.Context, host *Host) error
	UpdateHost(ctx context.Context, host *Host) error
	DeleteHost(ctx context.Context, id string) error
	ListHostsByFolder(ctx context.Context, folderID string) ([]Host, error)
}

// UserStore defines user operations.
type UserStore interface {
	GetUser(ctx context.Context, id string) (*User, error)
	GetUserByUsername(ctx context.Context, username string) (*User, error)
	ListUsers(ctx context.Context) ([]User, error)
	CreateUser(ctx context.Context, user *User) error
	UpdateUser(ctx context.Context, user *User) error
	DeleteUser(ctx context.Context, id string) error
	GetUserWithPassword(ctx context.Context, username string) (*UserWithPassword, error)
	CreateUserWithPassword(ctx context.Context, user *UserWithPassword) error
	UpdateUserPassword(ctx context.Context, userID, passwordHash string) error
	UpdateUserLastLogin(ctx context.Context, userID string) error
}

// SessionStore defines session operations.
type SessionStore interface {
	GetSession(ctx context.Context, id string) (*Session, error)
	ListSessions(ctx context.Context, username string, limit int) ([]Session, error)
	CreateSession(ctx context.Context, session *Session) error
	UpdateSession(ctx context.Context, session *Session) error
	ListActiveSessions(ctx context.Context) ([]Session, error)
	CleanupStaleSessions(ctx context.Context) (int64, error)
}

// RoleStore defines role operations.
type RoleStore interface {
	GetRole(ctx context.Context, id string) (*Role, error)
	GetRoleByName(ctx context.Context, name string) (*Role, error)
	ListRoles(ctx context.Context) ([]Role, error)
	CreateRole(ctx context.Context, role *Role) error
	UpdateRole(ctx context.Context, role *Role) error
	DeleteRole(ctx context.Context, id string) error
	InitDefaultRoles(ctx context.Context) error
}

// IAMStore defines IAM and RBAC operations.
type IAMStore interface {
	RoleStore
	GetUserRoles(ctx context.Context, userID string) ([]Role, error)
	AssignRole(ctx context.Context, userID, roleID string) error
	RevokeRole(ctx context.Context, userID, roleID string) error
	SetUserRoles(ctx context.Context, userID string, roleIDs []string) (*RoleDiff, error)

	GetHostPermissions(ctx context.Context, userID string) ([]HostPermission, error)
	ListAllHostPermissions(ctx context.Context) ([]HostPermission, error)
	GetHostPermission(ctx context.Context, userID, hostID string) (*HostPermission, error)
	GrantHostAccess(ctx context.Context, perm *HostPermission) error
	RevokeHostAccess(ctx context.Context, userID, hostID string) error
	RevokeHostAccessByID(ctx context.Context, id string) error
	ListUsersWithHostAccess(ctx context.Context, hostID string) ([]HostPermission, error)
	SetUserHostPermissions(ctx context.Context, userID string, perms []HostPermission) (*HostPermissionDiff, error)
}

// OTPStore defines OTP operations.
type OTPStore interface {
	SetUserOTPSecret(ctx context.Context, userID, secret string) error
	EnableUserOTP(ctx context.Context, userID string) error
	DisableUserOTP(ctx context.Context, userID string) error
}

// SettingsStore defines setting operations.
type SettingsStore interface {
	GetSetting(ctx context.Context, key string) (string, error)
	SetSetting(ctx context.Context, key, value string) error
	GetAllSettings(ctx context.Context) (map[string]string, error)
}

// ApiKeyStore defines API key operations.
type ApiKeyStore interface {
	CreateApiKey(ctx context.Context, key *ApiKey) error
	GetApiKey(ctx context.Context, id string) (*ApiKey, error)
	GetApiKeyByTokenHash(ctx context.Context, tokenHash string) (*ApiKey, error)
	ListApiKeysByUser(ctx context.Context, userID string) ([]ApiKey, error)
	UpdateApiKeyLastUsed(ctx context.Context, id string) error
	DeactivateApiKey(ctx context.Context, id string) error
	DeleteApiKey(ctx context.Context, id string) error
	DeleteApiKeysByUser(ctx context.Context, userID string) error
}

// TokenStore defines generic token operations.
type TokenStore interface {
	CreateToken(ctx context.Context, token *Token) error
	GetTokenByHash(ctx context.Context, tokenHash string) (*Token, error)
	DeleteToken(ctx context.Context, id string) error
	DeleteExpiredTokens(ctx context.Context) error
	DeleteUserTokens(ctx context.Context, userID string) error
}

// FolderStore defines folder operations.
type FolderStore interface {
	CreateFolder(ctx context.Context, folder Folder) error
	GetFolder(ctx context.Context, id string) (*Folder, error)
	ListFolders(ctx context.Context) ([]Folder, error)
	ListSubfolders(ctx context.Context, parentID string) ([]Folder, error)
	UpdateFolder(ctx context.Context, folder Folder) error
	DeleteFolder(ctx context.Context, id string) error
}

// SSHKeyStore defines SSH key operations.
type SSHKeyStore interface {
	GetSSHKey(ctx context.Context, id string) (*SSHKey, error)
	GetSSHKeyByFingerprint(ctx context.Context, fingerprint string) (*SSHKey, error)
	ListSSHKeys(ctx context.Context) ([]SSHKey, error)
	CreateSSHKey(ctx context.Context, key *SSHKey) error
	DeleteSSHKey(ctx context.Context, id string) error
}

// AuditStore defines audit log operations.
type AuditStore interface {
	CreateAuditLog(ctx context.Context, log *AuditLog) error
	ListAuditLogs(ctx context.Context, username, eventType string, startTime, endTime time.Time, limit, offset int) ([]AuditLog, error)
	CleanupAuditLogs(ctx context.Context, before time.Time) (int64, error)
}

// RecordingStore defines recording metadata operations.
type RecordingStore interface {
	GetRecording(ctx context.Context, id string) (*Recording, error)
	GetRecordingBySessionID(ctx context.Context, sessionID string) (*Recording, error)
	ListRecordings(ctx context.Context, username string, limit, offset int) ([]Recording, error)
	CreateRecording(ctx context.Context, recording *Recording) error
	UpdateRecording(ctx context.Context, recording *Recording) error
	DeleteRecording(ctx context.Context, id string) error
	CleanupRecordings(ctx context.Context, before time.Time) (int64, error)
}

// Store defines the interface for data persistence by combining all capabilities.
type Store interface {
	HostStore
	UserStore
	SessionStore
	IAMStore
	OTPStore
	SettingsStore
	ApiKeyStore
	TokenStore
	FolderStore
	SSHKeyStore
	AuditStore
	RecordingStore

	// Lifecycle.
	Close() error
}

// FileStore has been deprecated and removed. Only SQLiteStore is fully supported.

func generateID() string {
	return fmt.Sprintf("%d", time.Now().UnixNano())
}

// New creates a new Store based on configuration.
func New(cfg config.StorageConfig) (Store, error) {
	switch cfg.Type {
	case "sqlite":
		return NewSQLiteStore(cfg)
	default:
		// Fallback to sqlite if file or unknown is used.
		return NewSQLiteStore(cfg)
	}
}
