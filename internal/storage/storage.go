// Package storage provides data persistence for vc-jump.
package storage

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
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

// Store defines the interface for data persistence.
type Store interface {
	// Host operations.
	GetHost(ctx context.Context, id string) (*Host, error)
	GetHostByName(ctx context.Context, name string) (*Host, error)
	ListHosts(ctx context.Context) ([]Host, error)
	CreateHost(ctx context.Context, host *Host) error
	UpdateHost(ctx context.Context, host *Host) error
	DeleteHost(ctx context.Context, id string) error

	// User operations.
	GetUser(ctx context.Context, id string) (*User, error)
	GetUserByUsername(ctx context.Context, username string) (*User, error)
	ListUsers(ctx context.Context) ([]User, error)
	CreateUser(ctx context.Context, user *User) error
	UpdateUser(ctx context.Context, user *User) error
	DeleteUser(ctx context.Context, id string) error

	// Session operations.
	GetSession(ctx context.Context, id string) (*Session, error)
	ListSessions(ctx context.Context, username string, limit int) ([]Session, error)
	CreateSession(ctx context.Context, session *Session) error
	UpdateSession(ctx context.Context, session *Session) error

	// Recording operations.
	GetRecording(ctx context.Context, id string) (*Recording, error)
	GetRecordingBySessionID(ctx context.Context, sessionID string) (*Recording, error)
	ListRecordings(ctx context.Context, username string, limit, offset int) ([]Recording, error)
	CreateRecording(ctx context.Context, recording *Recording) error
	UpdateRecording(ctx context.Context, recording *Recording) error
	DeleteRecording(ctx context.Context, id string) error

	// Audit log operations.
	CreateAuditLog(ctx context.Context, log *AuditLog) error
	ListAuditLogs(ctx context.Context, username, eventType string, startTime, endTime time.Time, limit, offset int) ([]AuditLog, error)

	// Lifecycle.
	Close() error
}

// FileStore implements Store using JSON files.
type FileStore struct {
	basePath string
	hosts    map[string]*Host
	users    map[string]*User
	sessions map[string]*Session
	mu       sync.RWMutex
}

// NewFileStore creates a new FileStore instance.
func NewFileStore(cfg config.StorageConfig) (*FileStore, error) {
	if cfg.FilePath == "" {
		return nil, errors.New("file_path cannot be empty")
	}

	if err := os.MkdirAll(cfg.FilePath, 0700); err != nil {
		return nil, fmt.Errorf("failed to create storage directory: %w", err)
	}

	store := &FileStore{
		basePath: cfg.FilePath,
		hosts:    make(map[string]*Host),
		users:    make(map[string]*User),
		sessions: make(map[string]*Session),
	}

	// Load existing data.
	if err := store.load(); err != nil {
		return nil, fmt.Errorf("failed to load data: %w", err)
	}

	return store, nil
}

func (s *FileStore) load() error {
	if err := s.loadHosts(); err != nil && !os.IsNotExist(err) {
		return err
	}
	if err := s.loadUsers(); err != nil && !os.IsNotExist(err) {
		return err
	}
	if err := s.loadSessions(); err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}

func (s *FileStore) loadHosts() error {
	data, err := os.ReadFile(filepath.Join(s.basePath, "hosts.json"))
	if err != nil {
		return err
	}
	var hosts []Host
	if err := json.Unmarshal(data, &hosts); err != nil {
		return err
	}
	for i := range hosts {
		s.hosts[hosts[i].ID] = &hosts[i]
	}
	return nil
}

func (s *FileStore) loadUsers() error {
	data, err := os.ReadFile(filepath.Join(s.basePath, "users.json"))
	if err != nil {
		return err
	}
	var users []User
	if err := json.Unmarshal(data, &users); err != nil {
		return err
	}
	for i := range users {
		s.users[users[i].ID] = &users[i]
	}
	return nil
}

func (s *FileStore) loadSessions() error {
	data, err := os.ReadFile(filepath.Join(s.basePath, "sessions.json"))
	if err != nil {
		return err
	}
	var sessions []Session
	if err := json.Unmarshal(data, &sessions); err != nil {
		return err
	}
	for i := range sessions {
		s.sessions[sessions[i].ID] = &sessions[i]
	}
	return nil
}

func (s *FileStore) saveHosts() error {
	hosts := make([]Host, 0, len(s.hosts))
	for _, h := range s.hosts {
		hosts = append(hosts, *h)
	}
	data, err := json.MarshalIndent(hosts, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(s.basePath, "hosts.json"), data, 0600)
}

func (s *FileStore) saveUsers() error {
	users := make([]User, 0, len(s.users))
	for _, u := range s.users {
		users = append(users, *u)
	}
	data, err := json.MarshalIndent(users, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(s.basePath, "users.json"), data, 0600)
}

func (s *FileStore) saveSessions() error {
	sessions := make([]Session, 0, len(s.sessions))
	for _, sess := range s.sessions {
		sessions = append(sessions, *sess)
	}
	data, err := json.MarshalIndent(sessions, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(s.basePath, "sessions.json"), data, 0600)
}

// Host operations.

func (s *FileStore) GetHost(ctx context.Context, id string) (*Host, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	host, ok := s.hosts[id]
	if !ok {
		return nil, errors.New("host not found")
	}
	return host, nil
}

func (s *FileStore) GetHostByName(ctx context.Context, name string) (*Host, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, host := range s.hosts {
		if host.Name == name {
			return host, nil
		}
	}
	return nil, errors.New("host not found")
}

func (s *FileStore) ListHosts(ctx context.Context) ([]Host, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	hosts := make([]Host, 0, len(s.hosts))
	for _, h := range s.hosts {
		hosts = append(hosts, *h)
	}
	return hosts, nil
}

func (s *FileStore) CreateHost(ctx context.Context, host *Host) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if host.ID == "" {
		host.ID = generateID()
	}
	host.CreatedAt = time.Now()
	host.UpdatedAt = time.Now()
	s.hosts[host.ID] = host
	return s.saveHosts()
}

func (s *FileStore) UpdateHost(ctx context.Context, host *Host) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.hosts[host.ID]; !ok {
		return errors.New("host not found")
	}
	host.UpdatedAt = time.Now()
	s.hosts[host.ID] = host
	return s.saveHosts()
}

func (s *FileStore) DeleteHost(ctx context.Context, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.hosts[id]; !ok {
		return errors.New("host not found")
	}
	delete(s.hosts, id)
	return s.saveHosts()
}

// User operations.

func (s *FileStore) GetUser(ctx context.Context, id string) (*User, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	user, ok := s.users[id]
	if !ok {
		return nil, errors.New("user not found")
	}
	return user, nil
}

func (s *FileStore) GetUserByUsername(ctx context.Context, username string) (*User, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, user := range s.users {
		if user.Username == username {
			return user, nil
		}
	}
	return nil, errors.New("user not found")
}

func (s *FileStore) ListUsers(ctx context.Context) ([]User, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	users := make([]User, 0, len(s.users))
	for _, u := range s.users {
		users = append(users, *u)
	}
	return users, nil
}

func (s *FileStore) CreateUser(ctx context.Context, user *User) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if user.ID == "" {
		user.ID = generateID()
	}
	user.CreatedAt = time.Now()
	user.UpdatedAt = time.Now()
	s.users[user.ID] = user
	return s.saveUsers()
}

func (s *FileStore) UpdateUser(ctx context.Context, user *User) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.users[user.ID]; !ok {
		return errors.New("user not found")
	}
	user.UpdatedAt = time.Now()
	s.users[user.ID] = user
	return s.saveUsers()
}

func (s *FileStore) DeleteUser(ctx context.Context, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.users[id]; !ok {
		return errors.New("user not found")
	}
	delete(s.users, id)
	return s.saveUsers()
}

// Session operations.

func (s *FileStore) GetSession(ctx context.Context, id string) (*Session, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	session, ok := s.sessions[id]
	if !ok {
		return nil, errors.New("session not found")
	}
	return session, nil
}

func (s *FileStore) ListSessions(ctx context.Context, username string, limit int) ([]Session, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var sessions []Session
	for _, sess := range s.sessions {
		if username == "" || sess.Username == username {
			sessions = append(sessions, *sess)
		}
	}
	if limit > 0 && limit < len(sessions) {
		sessions = sessions[:limit]
	}
	return sessions, nil
}

func (s *FileStore) CreateSession(ctx context.Context, session *Session) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if session.ID == "" {
		session.ID = generateID()
	}
	s.sessions[session.ID] = session
	return s.saveSessions()
}

func (s *FileStore) UpdateSession(ctx context.Context, session *Session) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.sessions[session.ID]; !ok {
		return errors.New("session not found")
	}
	s.sessions[session.ID] = session
	return s.saveSessions()
}

// CreateAuditLog is a no-op for FileStore (audit logs not supported in file storage).
func (s *FileStore) CreateAuditLog(ctx context.Context, log *AuditLog) error {
	// File-based storage does not support audit logs.
	return nil
}

// ListAuditLogs returns empty for FileStore (audit logs not supported in file storage).
func (s *FileStore) ListAuditLogs(ctx context.Context, username, eventType string, startTime, endTime time.Time, limit, offset int) ([]AuditLog, error) {
	// File-based storage does not support audit logs.
	return []AuditLog{}, nil
}

// GetRecording is a no-op for FileStore (recordings not supported in file storage).
func (s *FileStore) GetRecording(ctx context.Context, id string) (*Recording, error) {
	return nil, errors.New("recordings not supported in file storage")
}

// GetRecordingBySessionID is a no-op for FileStore (recordings not supported in file storage).
func (s *FileStore) GetRecordingBySessionID(ctx context.Context, sessionID string) (*Recording, error) {
	return nil, errors.New("recordings not supported in file storage")
}

// ListRecordings is a no-op for FileStore (recordings not supported in file storage).
func (s *FileStore) ListRecordings(ctx context.Context, username string, limit, offset int) ([]Recording, error) {
	return []Recording{}, nil
}

// CreateRecording is a no-op for FileStore (recordings not supported in file storage).
func (s *FileStore) CreateRecording(ctx context.Context, recording *Recording) error {
	return errors.New("recordings not supported in file storage")
}

// UpdateRecording is a no-op for FileStore (recordings not supported in file storage).
func (s *FileStore) UpdateRecording(ctx context.Context, recording *Recording) error {
	return errors.New("recordings not supported in file storage")
}

// DeleteRecording is a no-op for FileStore (recordings not supported in file storage).
func (s *FileStore) DeleteRecording(ctx context.Context, id string) error {
	return errors.New("recordings not supported in file storage")
}

func (s *FileStore) Close() error {
	return nil
}

func generateID() string {
	return fmt.Sprintf("%d", time.Now().UnixNano())
}

// New creates a new Store based on configuration.
func New(cfg config.StorageConfig) (Store, error) {
	switch cfg.Type {
	case "file":
		return NewFileStore(cfg)
	case "sqlite":
		return NewSQLiteStore(cfg)
	default:
		return nil, fmt.Errorf("unsupported storage type: %s", cfg.Type)
	}
}
