// Package storage provides data persistence for vc-jump.
package storage

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/Veritas-Calculus/vc-jump/internal/config"
	"github.com/Veritas-Calculus/vc-jump/internal/rbac"
	"github.com/google/uuid"
	_ "modernc.org/sqlite"
)

// SQLiteStore implements Store using SQLite database.
type SQLiteStore struct {
	db *sql.DB
	mu sync.RWMutex
}

// NewSQLiteStore creates a new SQLiteStore instance.
func NewSQLiteStore(cfg config.StorageConfig) (*SQLiteStore, error) {
	if cfg.DBPath == "" {
		return nil, errors.New("db_path cannot be empty")
	}

	// Ensure directory exists.
	if err := os.MkdirAll(filepath.Dir(cfg.DBPath), 0700); err != nil {
		return nil, fmt.Errorf("failed to create database directory: %w", err)
	}

	db, err := sql.Open("sqlite", cfg.DBPath)
	if err != nil {
		return nil, fmt.Errorf("failed to open database: %w", err)
	}

	// Enable WAL mode for better concurrency.
	if _, err := db.Exec("PRAGMA journal_mode=WAL"); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("failed to enable WAL mode: %w", err)
	}

	// Enable foreign keys.
	if _, err := db.Exec("PRAGMA foreign_keys=ON"); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("failed to enable foreign keys: %w", err)
	}

	store := &SQLiteStore{db: db}

	// Initialize schema.
	if err := store.initSchema(); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("failed to initialize schema: %w", err)
	}

	return store, nil
}

func (s *SQLiteStore) initSchema() error {
	schema := `
	CREATE TABLE IF NOT EXISTS folders (
		id TEXT PRIMARY KEY,
		name TEXT NOT NULL,
		parent_id TEXT,
		path TEXT NOT NULL,
		description TEXT,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		FOREIGN KEY (parent_id) REFERENCES folders(id) ON DELETE CASCADE
	);

	CREATE INDEX IF NOT EXISTS idx_folders_parent ON folders(parent_id);
	CREATE INDEX IF NOT EXISTS idx_folders_path ON folders(path);

	CREATE TABLE IF NOT EXISTS hosts (
		id TEXT PRIMARY KEY,
		name TEXT UNIQUE NOT NULL,
		addr TEXT NOT NULL,
		port INTEGER NOT NULL DEFAULT 22,
		user TEXT DEFAULT 'root',
		users TEXT DEFAULT '[]',
		groups TEXT DEFAULT '[]',
		folder_id TEXT,
		key_id TEXT,
		insecure_ignore_host_key INTEGER DEFAULT 0,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		FOREIGN KEY (folder_id) REFERENCES folders(id) ON DELETE SET NULL
	);

	CREATE INDEX IF NOT EXISTS idx_hosts_folder ON hosts(folder_id);

	CREATE TABLE IF NOT EXISTS users (
		id TEXT PRIMARY KEY,
		username TEXT UNIQUE NOT NULL,
		password_hash TEXT,
		groups TEXT DEFAULT '[]',
		public_keys TEXT DEFAULT '[]',
		allowed_hosts TEXT DEFAULT '[]',
		source TEXT DEFAULT 'local',
		totp_secret TEXT,
		otp_enabled INTEGER DEFAULT 0,
		otp_verified INTEGER DEFAULT 0,
		is_active INTEGER DEFAULT 1,
		last_login_at DATETIME,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
	);

	CREATE TABLE IF NOT EXISTS sessions (
		id TEXT PRIMARY KEY,
		username TEXT NOT NULL,
		source_ip TEXT NOT NULL,
		target_host TEXT NOT NULL,
		start_time DATETIME NOT NULL,
		end_time DATETIME,
		recording TEXT,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP
	);

	CREATE TABLE IF NOT EXISTS ssh_keys (
		id TEXT PRIMARY KEY,
		name TEXT NOT NULL,
		private_key TEXT NOT NULL,
		public_key TEXT NOT NULL,
		fingerprint TEXT UNIQUE NOT NULL,
		key_type TEXT NOT NULL,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		expires_at DATETIME
	);

	CREATE TABLE IF NOT EXISTS user_public_keys (
		id TEXT PRIMARY KEY,
		user_id TEXT NOT NULL,
		name TEXT NOT NULL,
		public_key TEXT NOT NULL,
		fingerprint TEXT NOT NULL,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		last_used_at DATETIME,
		FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
	);

	CREATE TABLE IF NOT EXISTS tokens (
		id TEXT PRIMARY KEY,
		user_id TEXT NOT NULL,
		token_hash TEXT UNIQUE NOT NULL,
		token_type TEXT NOT NULL,
		expires_at DATETIME NOT NULL,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
	);

	CREATE TABLE IF NOT EXISTS settings (
		key TEXT PRIMARY KEY,
		value TEXT NOT NULL,
		updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
	);

	CREATE INDEX IF NOT EXISTS idx_hosts_name ON hosts(name);
	CREATE INDEX IF NOT EXISTS idx_users_username ON users(username);
	CREATE INDEX IF NOT EXISTS idx_sessions_username ON sessions(username);
	CREATE INDEX IF NOT EXISTS idx_sessions_start_time ON sessions(start_time);
	CREATE INDEX IF NOT EXISTS idx_ssh_keys_fingerprint ON ssh_keys(fingerprint);
	CREATE INDEX IF NOT EXISTS idx_user_public_keys_user_id ON user_public_keys(user_id);
	CREATE INDEX IF NOT EXISTS idx_tokens_user_id ON tokens(user_id);
	CREATE INDEX IF NOT EXISTS idx_tokens_expires_at ON tokens(expires_at);

	-- RBAC tables
	CREATE TABLE IF NOT EXISTS roles (
		id TEXT PRIMARY KEY,
		name TEXT UNIQUE NOT NULL,
		display_name TEXT NOT NULL,
		description TEXT,
		permissions TEXT DEFAULT '[]',
		is_system INTEGER DEFAULT 0,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
	);

	CREATE TABLE IF NOT EXISTS user_roles (
		id TEXT PRIMARY KEY,
		user_id TEXT NOT NULL,
		role_id TEXT NOT NULL,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
		FOREIGN KEY (role_id) REFERENCES roles(id) ON DELETE CASCADE,
		UNIQUE(user_id, role_id)
	);

	CREATE TABLE IF NOT EXISTS host_permissions (
		id TEXT PRIMARY KEY,
		user_id TEXT NOT NULL,
		host_id TEXT NOT NULL,
		can_sudo INTEGER DEFAULT 0,
		expires_at DATETIME,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
		FOREIGN KEY (host_id) REFERENCES hosts(id) ON DELETE CASCADE,
		UNIQUE(user_id, host_id)
	);

	CREATE TABLE IF NOT EXISTS settings (
		key TEXT PRIMARY KEY,
		value TEXT NOT NULL,
		updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
	);

	CREATE TABLE IF NOT EXISTS audit_logs (
		id TEXT PRIMARY KEY,
		timestamp DATETIME NOT NULL,
		event_type TEXT NOT NULL,
		username TEXT NOT NULL,
		source_ip TEXT,
		target_host TEXT,
		action TEXT NOT NULL,
		result TEXT NOT NULL,
		details TEXT,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP
	);

	CREATE INDEX IF NOT EXISTS idx_roles_name ON roles(name);
	CREATE INDEX IF NOT EXISTS idx_user_roles_user_id ON user_roles(user_id);
	CREATE INDEX IF NOT EXISTS idx_user_roles_role_id ON user_roles(role_id);
	CREATE INDEX IF NOT EXISTS idx_host_permissions_user_id ON host_permissions(user_id);
	CREATE INDEX IF NOT EXISTS idx_host_permissions_host_id ON host_permissions(host_id);
	CREATE INDEX IF NOT EXISTS idx_audit_logs_timestamp ON audit_logs(timestamp);
	CREATE INDEX IF NOT EXISTS idx_audit_logs_username ON audit_logs(username);
	CREATE INDEX IF NOT EXISTS idx_audit_logs_event_type ON audit_logs(event_type);
	`

	_, err := s.db.Exec(schema)
	if err != nil {
		return err
	}

	// Run migrations for existing databases.
	return s.runMigrations()
}

// runMigrations applies any necessary schema migrations.
func (s *SQLiteStore) runMigrations() error {
	// Add 'user' column to hosts if it doesn't exist.
	_, err := s.db.Exec("ALTER TABLE hosts ADD COLUMN user TEXT DEFAULT 'root'")
	if err != nil {
		// Ignore error if column already exists.
		if !strings.Contains(err.Error(), "duplicate column name") && !strings.Contains(err.Error(), "duplicate column") {
			return err
		}
	}

	// Add 'insecure_ignore_host_key' column to hosts if it doesn't exist.
	_, err = s.db.Exec("ALTER TABLE hosts ADD COLUMN insecure_ignore_host_key INTEGER DEFAULT 0")
	if err != nil {
		// Ignore error if column already exists.
		if !strings.Contains(err.Error(), "duplicate column name") && !strings.Contains(err.Error(), "duplicate column") {
			return err
		}
	}

	// Add 'otp_enabled' column to users if it doesn't exist.
	_, err = s.db.Exec("ALTER TABLE users ADD COLUMN otp_enabled INTEGER DEFAULT 0")
	if err != nil {
		if !strings.Contains(err.Error(), "duplicate column name") && !strings.Contains(err.Error(), "duplicate column") {
			return err
		}
	}

	// Add 'otp_verified' column to users if it doesn't exist.
	_, err = s.db.Exec("ALTER TABLE users ADD COLUMN otp_verified INTEGER DEFAULT 0")
	if err != nil {
		if !strings.Contains(err.Error(), "duplicate column name") && !strings.Contains(err.Error(), "duplicate column") {
			return err
		}
	}

	// Initialize default RBAC roles if they don't exist.
	if err := s.initDefaultRoles(); err != nil {
		return fmt.Errorf("failed to initialize default roles: %w", err)
	}

	return nil
}

// initDefaultRoles creates the default system roles if they don't exist.
func (s *SQLiteStore) initDefaultRoles() error {
	defaultRoles := rbac.DefaultRoles()

	for _, role := range defaultRoles {
		// Check if role already exists by name.
		var count int
		err := s.db.QueryRow("SELECT COUNT(*) FROM roles WHERE name = ?", role.Name).Scan(&count)
		if err != nil {
			return fmt.Errorf("failed to check role existence: %w", err)
		}

		if count > 0 {
			// Role already exists, skip.
			continue
		}

		// Create the role.
		permsJSON, err := json.Marshal(role.Permissions)
		if err != nil {
			return fmt.Errorf("failed to marshal permissions: %w", err)
		}

		roleID := uuid.New().String()
		now := time.Now()

		_, err = s.db.Exec(
			`INSERT INTO roles (id, name, display_name, description, permissions, is_system, created_at, updated_at)
			 VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
			roleID, role.Name, role.DisplayName, role.Description, string(permsJSON), role.IsSystem, now, now,
		)
		if err != nil {
			return fmt.Errorf("failed to create role %s: %w", role.Name, err)
		}
	}

	return nil
}

// Host operations.

// GetHost retrieves a host by ID.
func (s *SQLiteStore) GetHost(ctx context.Context, id string) (*Host, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var host Host
	var usersJSON, groupsJSON string
	var keyID, user, folderID sql.NullString
	var insecureIgnoreHostKey sql.NullBool
	err := s.db.QueryRowContext(ctx,
		"SELECT id, name, addr, port, user, users, groups, folder_id, key_id, insecure_ignore_host_key, created_at, updated_at FROM hosts WHERE id = ?",
		id,
	).Scan(&host.ID, &host.Name, &host.Addr, &host.Port, &user, &usersJSON, &groupsJSON, &folderID, &keyID, &insecureIgnoreHostKey, &host.CreatedAt, &host.UpdatedAt)

	if err == sql.ErrNoRows {
		return nil, errors.New("host not found")
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get host: %w", err)
	}

	if keyID.Valid {
		host.KeyID = keyID.String
	}
	if folderID.Valid {
		host.FolderID = folderID.String
	}
	if user.Valid {
		host.User = user.String
	} else {
		host.User = "root"
	}
	if insecureIgnoreHostKey.Valid {
		host.InsecureIgnoreHostKey = insecureIgnoreHostKey.Bool
	}
	if err := json.Unmarshal([]byte(usersJSON), &host.Users); err != nil {
		host.Users = nil
	}
	if err := json.Unmarshal([]byte(groupsJSON), &host.Groups); err != nil {
		host.Groups = nil
	}

	return &host, nil
}

// GetHostByName retrieves a host by name.
func (s *SQLiteStore) GetHostByName(ctx context.Context, name string) (*Host, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var host Host
	var usersJSON, groupsJSON string
	var keyID, user, folderID sql.NullString
	var insecureIgnoreHostKey sql.NullBool
	err := s.db.QueryRowContext(ctx,
		"SELECT id, name, addr, port, user, users, groups, folder_id, key_id, insecure_ignore_host_key, created_at, updated_at FROM hosts WHERE name = ?",
		name,
	).Scan(&host.ID, &host.Name, &host.Addr, &host.Port, &user, &usersJSON, &groupsJSON, &folderID, &keyID, &insecureIgnoreHostKey, &host.CreatedAt, &host.UpdatedAt)

	if err == sql.ErrNoRows {
		return nil, errors.New("host not found")
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get host: %w", err)
	}

	if keyID.Valid {
		host.KeyID = keyID.String
	}
	if folderID.Valid {
		host.FolderID = folderID.String
	}
	if user.Valid {
		host.User = user.String
	} else {
		host.User = "root"
	}
	if insecureIgnoreHostKey.Valid {
		host.InsecureIgnoreHostKey = insecureIgnoreHostKey.Bool
	}
	if err := json.Unmarshal([]byte(usersJSON), &host.Users); err != nil {
		host.Users = nil
	}
	if err := json.Unmarshal([]byte(groupsJSON), &host.Groups); err != nil {
		host.Groups = nil
	}

	return &host, nil
}

// ListHosts returns all hosts.
func (s *SQLiteStore) ListHosts(ctx context.Context) ([]Host, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	rows, err := s.db.QueryContext(ctx,
		"SELECT id, name, addr, port, user, users, groups, folder_id, key_id, insecure_ignore_host_key, created_at, updated_at FROM hosts ORDER BY name",
	)
	if err != nil {
		return nil, fmt.Errorf("failed to list hosts: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var hosts []Host
	for rows.Next() {
		var host Host
		var usersJSON, groupsJSON string
		var keyID, user, folderID sql.NullString
		var insecureIgnoreHostKey sql.NullBool
		if err := rows.Scan(&host.ID, &host.Name, &host.Addr, &host.Port, &user, &usersJSON, &groupsJSON, &folderID, &keyID, &insecureIgnoreHostKey, &host.CreatedAt, &host.UpdatedAt); err != nil {
			return nil, fmt.Errorf("failed to scan host: %w", err)
		}

		if keyID.Valid {
			host.KeyID = keyID.String
		}
		if folderID.Valid {
			host.FolderID = folderID.String
		}
		if user.Valid {
			host.User = user.String
		} else {
			host.User = "root"
		}
		if insecureIgnoreHostKey.Valid {
			host.InsecureIgnoreHostKey = insecureIgnoreHostKey.Bool
		}
		if err := json.Unmarshal([]byte(usersJSON), &host.Users); err != nil {
			host.Users = nil
		}
		if err := json.Unmarshal([]byte(groupsJSON), &host.Groups); err != nil {
			host.Groups = nil
		}

		hosts = append(hosts, host)
	}

	return hosts, nil
}

// CreateHost creates a new host.
func (s *SQLiteStore) CreateHost(ctx context.Context, host *Host) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if host.ID == "" {
		host.ID = generateID()
	}
	host.CreatedAt = time.Now()
	host.UpdatedAt = time.Now()
	if host.User == "" {
		host.User = "root"
	}

	usersJSON, _ := json.Marshal(host.Users)
	groupsJSON, _ := json.Marshal(host.Groups)

	var keyID interface{}
	if host.KeyID != "" {
		keyID = host.KeyID
	}

	var folderID interface{}
	if host.FolderID != "" {
		folderID = host.FolderID
	}

	insecureVal := 0
	if host.InsecureIgnoreHostKey {
		insecureVal = 1
	}

	_, err := s.db.ExecContext(ctx,
		"INSERT INTO hosts (id, name, addr, port, user, users, groups, folder_id, key_id, insecure_ignore_host_key, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
		host.ID, host.Name, host.Addr, host.Port, host.User, string(usersJSON), string(groupsJSON), folderID, keyID, insecureVal, host.CreatedAt, host.UpdatedAt,
	)
	if err != nil {
		return fmt.Errorf("failed to create host: %w", err)
	}

	return nil
}

// UpdateHost updates an existing host.
func (s *SQLiteStore) UpdateHost(ctx context.Context, host *Host) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	host.UpdatedAt = time.Now()
	if host.User == "" {
		host.User = "root"
	}

	usersJSON, _ := json.Marshal(host.Users)
	groupsJSON, _ := json.Marshal(host.Groups)

	var keyID interface{}
	if host.KeyID != "" {
		keyID = host.KeyID
	}

	var folderID interface{}
	if host.FolderID != "" {
		folderID = host.FolderID
	}

	insecureVal := 0
	if host.InsecureIgnoreHostKey {
		insecureVal = 1
	}

	result, err := s.db.ExecContext(ctx,
		"UPDATE hosts SET name = ?, addr = ?, port = ?, user = ?, users = ?, groups = ?, folder_id = ?, key_id = ?, insecure_ignore_host_key = ?, updated_at = ? WHERE id = ?",
		host.Name, host.Addr, host.Port, host.User, string(usersJSON), string(groupsJSON), folderID, keyID, insecureVal, host.UpdatedAt, host.ID,
	)
	if err != nil {
		return fmt.Errorf("failed to update host: %w", err)
	}

	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		return errors.New("host not found")
	}

	return nil
}

// DeleteHost deletes a host.
func (s *SQLiteStore) DeleteHost(ctx context.Context, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	result, err := s.db.ExecContext(ctx, "DELETE FROM hosts WHERE id = ?", id)
	if err != nil {
		return fmt.Errorf("failed to delete host: %w", err)
	}

	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		return errors.New("host not found")
	}

	return nil
}

// User operations.

// GetUser retrieves a user by ID.
func (s *SQLiteStore) GetUser(ctx context.Context, id string) (*User, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var user User
	var groupsJSON, publicKeysJSON string
	var allowedHostsJSON, passwordHash, source, otpSecret sql.NullString
	var lastLoginAt sql.NullTime
	err := s.db.QueryRowContext(ctx,
		"SELECT id, username, password_hash, groups, public_keys, allowed_hosts, source, totp_secret, otp_enabled, otp_verified, is_active, last_login_at, created_at, updated_at FROM users WHERE id = ?",
		id,
	).Scan(&user.ID, &user.Username, &passwordHash, &groupsJSON, &publicKeysJSON, &allowedHostsJSON, &source, &otpSecret, &user.OTPEnabled, &user.OTPVerified, &user.IsActive, &lastLoginAt, &user.CreatedAt, &user.UpdatedAt)

	if err == sql.ErrNoRows {
		return nil, errors.New("user not found")
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get user: %w", err)
	}

	if passwordHash.Valid {
		user.PasswordHash = passwordHash.String
	}
	if source.Valid {
		user.Source = UserSource(source.String)
	}
	if otpSecret.Valid {
		user.OTPSecret = otpSecret.String
	}
	if lastLoginAt.Valid {
		user.LastLoginAt = lastLoginAt.Time
	}
	if err := json.Unmarshal([]byte(groupsJSON), &user.Groups); err != nil {
		user.Groups = nil
	}
	if err := json.Unmarshal([]byte(publicKeysJSON), &user.PublicKeys); err != nil {
		user.PublicKeys = nil
	}
	if allowedHostsJSON.Valid {
		if err := json.Unmarshal([]byte(allowedHostsJSON.String), &user.AllowedHosts); err != nil {
			user.AllowedHosts = nil
		}
	}

	return &user, nil
}

// GetUserByUsername retrieves a user by username.
func (s *SQLiteStore) GetUserByUsername(ctx context.Context, username string) (*User, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var user User
	var groupsJSON, publicKeysJSON string
	var allowedHostsJSON, passwordHash, source, otpSecret sql.NullString
	var lastLoginAt sql.NullTime
	err := s.db.QueryRowContext(ctx,
		"SELECT id, username, password_hash, groups, public_keys, allowed_hosts, source, totp_secret, otp_enabled, otp_verified, is_active, last_login_at, created_at, updated_at FROM users WHERE username = ?",
		username,
	).Scan(&user.ID, &user.Username, &passwordHash, &groupsJSON, &publicKeysJSON, &allowedHostsJSON, &source, &otpSecret, &user.OTPEnabled, &user.OTPVerified, &user.IsActive, &lastLoginAt, &user.CreatedAt, &user.UpdatedAt)

	if err == sql.ErrNoRows {
		return nil, errors.New("user not found")
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get user: %w", err)
	}

	if passwordHash.Valid {
		user.PasswordHash = passwordHash.String
	}
	if source.Valid {
		user.Source = UserSource(source.String)
	}
	if otpSecret.Valid {
		user.OTPSecret = otpSecret.String
	}
	if lastLoginAt.Valid {
		user.LastLoginAt = lastLoginAt.Time
	}
	if err := json.Unmarshal([]byte(groupsJSON), &user.Groups); err != nil {
		user.Groups = nil
	}
	if err := json.Unmarshal([]byte(publicKeysJSON), &user.PublicKeys); err != nil {
		user.PublicKeys = nil
	}
	if allowedHostsJSON.Valid {
		if err := json.Unmarshal([]byte(allowedHostsJSON.String), &user.AllowedHosts); err != nil {
			user.AllowedHosts = nil
		}
	}

	return &user, nil
}

// ListUsers returns all users.
func (s *SQLiteStore) ListUsers(ctx context.Context) ([]User, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	rows, err := s.db.QueryContext(ctx,
		"SELECT id, username, password_hash, groups, public_keys, allowed_hosts, source, totp_secret, otp_enabled, otp_verified, is_active, last_login_at, created_at, updated_at FROM users ORDER BY username",
	)
	if err != nil {
		return nil, fmt.Errorf("failed to list users: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var users []User
	for rows.Next() {
		var user User
		var groupsJSON, publicKeysJSON string
		var allowedHostsJSON, passwordHash, source, otpSecret sql.NullString
		var lastLoginAt sql.NullTime
		if err := rows.Scan(&user.ID, &user.Username, &passwordHash, &groupsJSON, &publicKeysJSON, &allowedHostsJSON, &source, &otpSecret, &user.OTPEnabled, &user.OTPVerified, &user.IsActive, &lastLoginAt, &user.CreatedAt, &user.UpdatedAt); err != nil {
			return nil, fmt.Errorf("failed to scan user: %w", err)
		}

		if passwordHash.Valid {
			user.PasswordHash = passwordHash.String
		}
		if source.Valid {
			user.Source = UserSource(source.String)
		}
		if otpSecret.Valid {
			user.OTPSecret = otpSecret.String
		}
		if lastLoginAt.Valid {
			user.LastLoginAt = lastLoginAt.Time
		}
		if err := json.Unmarshal([]byte(groupsJSON), &user.Groups); err != nil {
			user.Groups = nil
		}
		if err := json.Unmarshal([]byte(publicKeysJSON), &user.PublicKeys); err != nil {
			user.PublicKeys = nil
		}
		if allowedHostsJSON.Valid {
			if err := json.Unmarshal([]byte(allowedHostsJSON.String), &user.AllowedHosts); err != nil {
				user.AllowedHosts = nil
			}
		}

		users = append(users, user)
	}

	return users, nil
}

// CreateUser creates a new user.
func (s *SQLiteStore) CreateUser(ctx context.Context, user *User) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if user.ID == "" {
		user.ID = generateID()
	}
	if user.Source == "" {
		user.Source = UserSourceLocal
	}
	user.CreatedAt = time.Now()
	user.UpdatedAt = time.Now()

	groupsJSON, _ := json.Marshal(user.Groups)
	publicKeysJSON, _ := json.Marshal(user.PublicKeys)
	allowedHostsJSON, _ := json.Marshal(user.AllowedHosts)

	_, err := s.db.ExecContext(ctx,
		"INSERT INTO users (id, username, password_hash, groups, public_keys, allowed_hosts, source, is_active, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
		user.ID, user.Username, user.PasswordHash, string(groupsJSON), string(publicKeysJSON), string(allowedHostsJSON), string(user.Source), user.IsActive, user.CreatedAt, user.UpdatedAt,
	)
	if err != nil {
		return fmt.Errorf("failed to create user: %w", err)
	}

	return nil
}

// UpdateUser updates an existing user.
func (s *SQLiteStore) UpdateUser(ctx context.Context, user *User) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	user.UpdatedAt = time.Now()

	groupsJSON, _ := json.Marshal(user.Groups)
	publicKeysJSON, _ := json.Marshal(user.PublicKeys)
	allowedHostsJSON, _ := json.Marshal(user.AllowedHosts)

	result, err := s.db.ExecContext(ctx,
		"UPDATE users SET username = ?, groups = ?, public_keys = ?, allowed_hosts = ?, is_active = ?, updated_at = ? WHERE id = ?",
		user.Username, string(groupsJSON), string(publicKeysJSON), string(allowedHostsJSON), user.IsActive, user.UpdatedAt, user.ID,
	)
	if err != nil {
		return fmt.Errorf("failed to update user: %w", err)
	}

	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		return errors.New("user not found")
	}

	return nil
}

// DeleteUser deletes a user.
func (s *SQLiteStore) DeleteUser(ctx context.Context, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	result, err := s.db.ExecContext(ctx, "DELETE FROM users WHERE id = ?", id)
	if err != nil {
		return fmt.Errorf("failed to delete user: %w", err)
	}

	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		return errors.New("user not found")
	}

	return nil
}

// Session operations.

// GetSession retrieves a session by ID.
func (s *SQLiteStore) GetSession(ctx context.Context, id string) (*Session, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var session Session
	var endTime sql.NullTime
	var recording sql.NullString
	err := s.db.QueryRowContext(ctx,
		"SELECT id, username, source_ip, target_host, start_time, end_time, recording FROM sessions WHERE id = ?",
		id,
	).Scan(&session.ID, &session.Username, &session.SourceIP, &session.TargetHost, &session.StartTime, &endTime, &recording)

	if err == sql.ErrNoRows {
		return nil, errors.New("session not found")
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get session: %w", err)
	}

	if endTime.Valid {
		session.EndTime = endTime.Time
	}
	if recording.Valid {
		session.Recording = recording.String
	}

	return &session, nil
}

// ListSessions returns sessions, optionally filtered by username.
func (s *SQLiteStore) ListSessions(ctx context.Context, username string, limit int) ([]Session, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	query := "SELECT id, username, source_ip, target_host, start_time, end_time, recording FROM sessions"
	var args []interface{}

	if username != "" {
		query += " WHERE username = ?"
		args = append(args, username)
	}

	query += " ORDER BY start_time DESC"

	if limit > 0 {
		query += " LIMIT ?"
		args = append(args, limit)
	}

	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("failed to list sessions: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var sessions []Session
	for rows.Next() {
		var session Session
		var endTime sql.NullTime
		var recording sql.NullString
		if err := rows.Scan(&session.ID, &session.Username, &session.SourceIP, &session.TargetHost, &session.StartTime, &endTime, &recording); err != nil {
			return nil, fmt.Errorf("failed to scan session: %w", err)
		}

		if endTime.Valid {
			session.EndTime = endTime.Time
		}
		if recording.Valid {
			session.Recording = recording.String
		}

		sessions = append(sessions, session)
	}

	return sessions, nil
}

// CreateSession creates a new session.
func (s *SQLiteStore) CreateSession(ctx context.Context, session *Session) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if session.ID == "" {
		session.ID = generateID()
	}

	var endTime, recording interface{}
	if !session.EndTime.IsZero() {
		endTime = session.EndTime
	}
	if session.Recording != "" {
		recording = session.Recording
	}

	_, err := s.db.ExecContext(ctx,
		"INSERT INTO sessions (id, username, source_ip, target_host, start_time, end_time, recording) VALUES (?, ?, ?, ?, ?, ?, ?)",
		session.ID, session.Username, session.SourceIP, session.TargetHost, session.StartTime, endTime, recording,
	)
	if err != nil {
		return fmt.Errorf("failed to create session: %w", err)
	}

	return nil
}

// UpdateSession updates an existing session.
func (s *SQLiteStore) UpdateSession(ctx context.Context, session *Session) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	var endTime, recording interface{}
	if !session.EndTime.IsZero() {
		endTime = session.EndTime
	}
	if session.Recording != "" {
		recording = session.Recording
	}

	result, err := s.db.ExecContext(ctx,
		"UPDATE sessions SET username = ?, source_ip = ?, target_host = ?, start_time = ?, end_time = ?, recording = ? WHERE id = ?",
		session.Username, session.SourceIP, session.TargetHost, session.StartTime, endTime, recording, session.ID,
	)
	if err != nil {
		return fmt.Errorf("failed to update session: %w", err)
	}

	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		return errors.New("session not found")
	}

	return nil
}

// ListActiveSessions returns all sessions that have no end time (currently active).
func (s *SQLiteStore) ListActiveSessions(ctx context.Context) ([]Session, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	rows, err := s.db.QueryContext(ctx,
		"SELECT id, username, source_ip, target_host, start_time, end_time, recording FROM sessions WHERE end_time IS NULL ORDER BY start_time DESC",
	)
	if err != nil {
		return nil, fmt.Errorf("failed to list active sessions: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var sessions []Session
	for rows.Next() {
		var session Session
		var endTime sql.NullTime
		var recording sql.NullString
		if err := rows.Scan(&session.ID, &session.Username, &session.SourceIP, &session.TargetHost, &session.StartTime, &endTime, &recording); err != nil {
			return nil, fmt.Errorf("failed to scan session: %w", err)
		}

		if endTime.Valid {
			session.EndTime = endTime.Time
		}
		if recording.Valid {
			session.Recording = recording.String
		}

		sessions = append(sessions, session)
	}

	return sessions, nil
}

// CleanupStaleSessions closes all sessions that have no end time.
// This should be called on startup to clean up sessions that were not properly closed.
func (s *SQLiteStore) CleanupStaleSessions(ctx context.Context) (int64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	result, err := s.db.ExecContext(ctx,
		"UPDATE sessions SET end_time = start_time WHERE end_time IS NULL",
	)
	if err != nil {
		return 0, fmt.Errorf("failed to cleanup stale sessions: %w", err)
	}

	rowsAffected, _ := result.RowsAffected()
	return rowsAffected, nil
}

// Close closes the database connection.
func (s *SQLiteStore) Close() error {
	return s.db.Close()
}

// SSHKey represents an SSH key in storage.
type SSHKey struct {
	ID          string    `json:"id"`
	Name        string    `json:"name"`
	PrivateKey  string    `json:"private_key"`
	PublicKey   string    `json:"public_key"`
	Fingerprint string    `json:"fingerprint"`
	KeyType     string    `json:"key_type"`
	CreatedAt   time.Time `json:"created_at"`
	ExpiresAt   time.Time `json:"expires_at,omitempty"`
}

// SSHKeyStore extends Store with SSH key operations.
type SSHKeyStore interface {
	Store
	// SSH Key operations.
	GetSSHKey(ctx context.Context, id string) (*SSHKey, error)
	GetSSHKeyByFingerprint(ctx context.Context, fingerprint string) (*SSHKey, error)
	ListSSHKeys(ctx context.Context) ([]SSHKey, error)
	CreateSSHKey(ctx context.Context, key *SSHKey) error
	DeleteSSHKey(ctx context.Context, id string) error
}

// GetSSHKey retrieves an SSH key by ID.
func (s *SQLiteStore) GetSSHKey(ctx context.Context, id string) (*SSHKey, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var key SSHKey
	var expiresAt sql.NullTime
	err := s.db.QueryRowContext(ctx,
		"SELECT id, name, private_key, public_key, fingerprint, key_type, created_at, expires_at FROM ssh_keys WHERE id = ?",
		id,
	).Scan(&key.ID, &key.Name, &key.PrivateKey, &key.PublicKey, &key.Fingerprint, &key.KeyType, &key.CreatedAt, &expiresAt)

	if err == sql.ErrNoRows {
		return nil, errors.New("ssh key not found")
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get ssh key: %w", err)
	}

	if expiresAt.Valid {
		key.ExpiresAt = expiresAt.Time
	}

	return &key, nil
}

// GetSSHKeyByFingerprint retrieves an SSH key by fingerprint.
func (s *SQLiteStore) GetSSHKeyByFingerprint(ctx context.Context, fingerprint string) (*SSHKey, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var key SSHKey
	var expiresAt sql.NullTime
	err := s.db.QueryRowContext(ctx,
		"SELECT id, name, private_key, public_key, fingerprint, key_type, created_at, expires_at FROM ssh_keys WHERE fingerprint = ?",
		fingerprint,
	).Scan(&key.ID, &key.Name, &key.PrivateKey, &key.PublicKey, &key.Fingerprint, &key.KeyType, &key.CreatedAt, &expiresAt)

	if err == sql.ErrNoRows {
		return nil, errors.New("ssh key not found")
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get ssh key: %w", err)
	}

	if expiresAt.Valid {
		key.ExpiresAt = expiresAt.Time
	}

	return &key, nil
}

// ListSSHKeys returns all SSH keys.
func (s *SQLiteStore) ListSSHKeys(ctx context.Context) ([]SSHKey, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	rows, err := s.db.QueryContext(ctx,
		"SELECT id, name, private_key, public_key, fingerprint, key_type, created_at, expires_at FROM ssh_keys ORDER BY created_at DESC",
	)
	if err != nil {
		return nil, fmt.Errorf("failed to list ssh keys: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var keys []SSHKey
	for rows.Next() {
		var key SSHKey
		var expiresAt sql.NullTime
		if err := rows.Scan(&key.ID, &key.Name, &key.PrivateKey, &key.PublicKey, &key.Fingerprint, &key.KeyType, &key.CreatedAt, &expiresAt); err != nil {
			return nil, fmt.Errorf("failed to scan ssh key: %w", err)
		}

		if expiresAt.Valid {
			key.ExpiresAt = expiresAt.Time
		}

		keys = append(keys, key)
	}

	return keys, nil
}

// CreateSSHKey creates a new SSH key.
func (s *SQLiteStore) CreateSSHKey(ctx context.Context, key *SSHKey) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if key.ID == "" {
		key.ID = generateID()
	}
	key.CreatedAt = time.Now()

	var expiresAt interface{}
	if !key.ExpiresAt.IsZero() {
		expiresAt = key.ExpiresAt
	}

	_, err := s.db.ExecContext(ctx,
		"INSERT INTO ssh_keys (id, name, private_key, public_key, fingerprint, key_type, created_at, expires_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
		key.ID, key.Name, key.PrivateKey, key.PublicKey, key.Fingerprint, key.KeyType, key.CreatedAt, expiresAt,
	)
	if err != nil {
		return fmt.Errorf("failed to create ssh key: %w", err)
	}

	return nil
}

// DeleteSSHKey deletes an SSH key.
func (s *SQLiteStore) DeleteSSHKey(ctx context.Context, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	result, err := s.db.ExecContext(ctx, "DELETE FROM ssh_keys WHERE id = ?", id)
	if err != nil {
		return fmt.Errorf("failed to delete ssh key: %w", err)
	}

	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		return errors.New("ssh key not found")
	}

	return nil
}

// UserWithPassword extends User with password hash.
type UserWithPassword struct {
	User
	PasswordHash string `json:"password_hash,omitempty"`
	TOTPSecret   string `json:"totp_secret,omitempty"`
	IsActive     bool   `json:"is_active"`
}

// GetUserWithPassword retrieves a user with password hash by username.
func (s *SQLiteStore) GetUserWithPassword(ctx context.Context, username string) (*UserWithPassword, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var user UserWithPassword
	var groupsJSON, publicKeysJSON, allowedHostsJSON string
	var passwordHash, totpSecret sql.NullString
	var lastLoginAt sql.NullTime
	var isActive int
	err := s.db.QueryRowContext(ctx,
		"SELECT id, username, password_hash, groups, public_keys, allowed_hosts, totp_secret, is_active, last_login_at, created_at, updated_at FROM users WHERE username = ?",
		username,
	).Scan(&user.ID, &user.Username, &passwordHash, &groupsJSON, &publicKeysJSON, &allowedHostsJSON, &totpSecret, &isActive, &lastLoginAt, &user.CreatedAt, &user.UpdatedAt)

	if err == sql.ErrNoRows {
		return nil, errors.New("user not found")
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get user: %w", err)
	}

	if passwordHash.Valid {
		user.PasswordHash = passwordHash.String
	}
	if totpSecret.Valid {
		user.TOTPSecret = totpSecret.String
	}
	user.IsActive = isActive == 1
	if lastLoginAt.Valid {
		user.LastLoginAt = lastLoginAt.Time
	}
	if err := json.Unmarshal([]byte(groupsJSON), &user.Groups); err != nil {
		user.Groups = nil
	}
	if err := json.Unmarshal([]byte(publicKeysJSON), &user.PublicKeys); err != nil {
		user.PublicKeys = nil
	}
	if err := json.Unmarshal([]byte(allowedHostsJSON), &user.AllowedHosts); err != nil {
		user.AllowedHosts = nil
	}

	return &user, nil
}

// CreateUserWithPassword creates a new user with password.
func (s *SQLiteStore) CreateUserWithPassword(ctx context.Context, user *UserWithPassword) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if user.ID == "" {
		user.ID = generateID()
	}
	if user.Source == "" {
		user.Source = UserSourceLocal
	}
	user.CreatedAt = time.Now()
	user.UpdatedAt = time.Now()

	groupsJSON, _ := json.Marshal(user.Groups)
	publicKeysJSON, _ := json.Marshal(user.PublicKeys)
	allowedHostsJSON, _ := json.Marshal(user.AllowedHosts)

	var passwordHash, totpSecret interface{}
	if user.PasswordHash != "" {
		passwordHash = user.PasswordHash
	}
	if user.TOTPSecret != "" {
		totpSecret = user.TOTPSecret
	}

	isActive := 0
	if user.IsActive {
		isActive = 1
	}

	_, err := s.db.ExecContext(ctx,
		"INSERT INTO users (id, username, password_hash, groups, public_keys, allowed_hosts, source, totp_secret, is_active, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
		user.ID, user.Username, passwordHash, string(groupsJSON), string(publicKeysJSON), string(allowedHostsJSON), string(user.Source), totpSecret, isActive, user.CreatedAt, user.UpdatedAt,
	)
	if err != nil {
		return fmt.Errorf("failed to create user: %w", err)
	}

	return nil
}

// UpdateUserPassword updates a user's password hash.
func (s *SQLiteStore) UpdateUserPassword(ctx context.Context, userID, passwordHash string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	result, err := s.db.ExecContext(ctx,
		"UPDATE users SET password_hash = ?, updated_at = ? WHERE id = ?",
		passwordHash, time.Now(), userID,
	)
	if err != nil {
		return fmt.Errorf("failed to update password: %w", err)
	}

	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		return errors.New("user not found")
	}

	return nil
}

// UpdateUserLastLogin updates a user's last login time.
func (s *SQLiteStore) UpdateUserLastLogin(ctx context.Context, userID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	result, err := s.db.ExecContext(ctx,
		"UPDATE users SET last_login_at = ? WHERE id = ?",
		time.Now(), userID,
	)
	if err != nil {
		return fmt.Errorf("failed to update last login: %w", err)
	}

	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		return errors.New("user not found")
	}

	return nil
}

// Token operations for session management.

// Token represents an authentication token.
type Token struct {
	ID        string    `json:"id"`
	UserID    string    `json:"user_id"`
	TokenHash string    `json:"token_hash"`
	TokenType string    `json:"token_type"` // "session", "api", "refresh"
	ExpiresAt time.Time `json:"expires_at"`
	CreatedAt time.Time `json:"created_at"`
}

// CreateToken creates a new token.
func (s *SQLiteStore) CreateToken(ctx context.Context, token *Token) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if token.ID == "" {
		token.ID = generateID()
	}
	token.CreatedAt = time.Now()

	_, err := s.db.ExecContext(ctx,
		"INSERT INTO tokens (id, user_id, token_hash, token_type, expires_at, created_at) VALUES (?, ?, ?, ?, ?, ?)",
		token.ID, token.UserID, token.TokenHash, token.TokenType, token.ExpiresAt, token.CreatedAt,
	)
	if err != nil {
		return fmt.Errorf("failed to create token: %w", err)
	}

	return nil
}

// GetTokenByHash retrieves a token by its hash.
func (s *SQLiteStore) GetTokenByHash(ctx context.Context, tokenHash string) (*Token, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var token Token
	err := s.db.QueryRowContext(ctx,
		"SELECT id, user_id, token_hash, token_type, expires_at, created_at FROM tokens WHERE token_hash = ?",
		tokenHash,
	).Scan(&token.ID, &token.UserID, &token.TokenHash, &token.TokenType, &token.ExpiresAt, &token.CreatedAt)

	if err == sql.ErrNoRows {
		return nil, errors.New("token not found")
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get token: %w", err)
	}

	return &token, nil
}

// DeleteToken deletes a token.
func (s *SQLiteStore) DeleteToken(ctx context.Context, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	_, err := s.db.ExecContext(ctx, "DELETE FROM tokens WHERE id = ?", id)
	return err
}

// DeleteExpiredTokens removes expired tokens.
func (s *SQLiteStore) DeleteExpiredTokens(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	_, err := s.db.ExecContext(ctx, "DELETE FROM tokens WHERE expires_at < ?", time.Now())
	return err
}

// DeleteUserTokens removes all tokens for a user.
func (s *SQLiteStore) DeleteUserTokens(ctx context.Context, userID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	_, err := s.db.ExecContext(ctx, "DELETE FROM tokens WHERE user_id = ?", userID)
	return err
}

// Settings operations.

// GetSetting retrieves a setting value.
func (s *SQLiteStore) GetSetting(ctx context.Context, key string) (string, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var value string
	err := s.db.QueryRowContext(ctx, "SELECT value FROM settings WHERE key = ?", key).Scan(&value)
	if err == sql.ErrNoRows {
		return "", errors.New("setting not found")
	}
	if err != nil {
		return "", fmt.Errorf("failed to get setting: %w", err)
	}

	return value, nil
}

// SetSetting sets a setting value.
func (s *SQLiteStore) SetSetting(ctx context.Context, key, value string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	_, err := s.db.ExecContext(ctx,
		"INSERT OR REPLACE INTO settings (key, value, updated_at) VALUES (?, ?, ?)",
		key, value, time.Now(),
	)
	if err != nil {
		return fmt.Errorf("failed to set setting: %w", err)
	}

	return nil
}

// DB returns the underlying database connection for advanced queries.
func (s *SQLiteStore) DB() *sql.DB {
	return s.db
}

// RBAC Role operations.

// GetRole retrieves a role by ID.
func (s *SQLiteStore) GetRole(ctx context.Context, id string) (*Role, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var role Role
	var permissionsJSON string
	var description sql.NullString

	err := s.db.QueryRowContext(ctx,
		"SELECT id, name, display_name, description, permissions, is_system, created_at, updated_at FROM roles WHERE id = ?",
		id,
	).Scan(&role.ID, &role.Name, &role.DisplayName, &description, &permissionsJSON, &role.IsSystem, &role.CreatedAt, &role.UpdatedAt)
	if err == sql.ErrNoRows {
		return nil, errors.New("role not found")
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get role: %w", err)
	}

	if description.Valid {
		role.Description = description.String
	}
	if err := json.Unmarshal([]byte(permissionsJSON), &role.Permissions); err != nil {
		role.Permissions = []string{}
	}

	return &role, nil
}

// GetRoleByName retrieves a role by name.
func (s *SQLiteStore) GetRoleByName(ctx context.Context, name string) (*Role, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var role Role
	var permissionsJSON string
	var description sql.NullString

	err := s.db.QueryRowContext(ctx,
		"SELECT id, name, display_name, description, permissions, is_system, created_at, updated_at FROM roles WHERE name = ?",
		name,
	).Scan(&role.ID, &role.Name, &role.DisplayName, &description, &permissionsJSON, &role.IsSystem, &role.CreatedAt, &role.UpdatedAt)
	if err == sql.ErrNoRows {
		return nil, errors.New("role not found")
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get role: %w", err)
	}

	if description.Valid {
		role.Description = description.String
	}
	if err := json.Unmarshal([]byte(permissionsJSON), &role.Permissions); err != nil {
		role.Permissions = []string{}
	}

	return &role, nil
}

// ListRoles lists all roles.
func (s *SQLiteStore) ListRoles(ctx context.Context) ([]Role, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	rows, err := s.db.QueryContext(ctx,
		"SELECT id, name, display_name, description, permissions, is_system, created_at, updated_at FROM roles ORDER BY name",
	)
	if err != nil {
		return nil, fmt.Errorf("failed to list roles: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var roles []Role
	for rows.Next() {
		var role Role
		var permissionsJSON string
		var description sql.NullString

		if err := rows.Scan(&role.ID, &role.Name, &role.DisplayName, &description, &permissionsJSON, &role.IsSystem, &role.CreatedAt, &role.UpdatedAt); err != nil {
			return nil, fmt.Errorf("failed to scan role: %w", err)
		}

		if description.Valid {
			role.Description = description.String
		}
		if err := json.Unmarshal([]byte(permissionsJSON), &role.Permissions); err != nil {
			role.Permissions = []string{}
		}
		roles = append(roles, role)
	}

	return roles, rows.Err()
}

// CreateRole creates a new role.
func (s *SQLiteStore) CreateRole(ctx context.Context, role *Role) error {
	if role.Name == "" {
		return errors.New("role name is required")
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if role.ID == "" {
		role.ID = generateID()
	}
	role.CreatedAt = time.Now()
	role.UpdatedAt = role.CreatedAt

	permissionsJSON, err := json.Marshal(role.Permissions)
	if err != nil {
		return fmt.Errorf("failed to marshal permissions: %w", err)
	}

	_, err = s.db.ExecContext(ctx,
		`INSERT INTO roles (id, name, display_name, description, permissions, is_system, created_at, updated_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		role.ID, role.Name, role.DisplayName, role.Description, string(permissionsJSON), role.IsSystem, role.CreatedAt, role.UpdatedAt,
	)
	if err != nil {
		if strings.Contains(err.Error(), "UNIQUE constraint failed") {
			return errors.New("role with this name already exists")
		}
		return fmt.Errorf("failed to create role: %w", err)
	}

	return nil
}

// UpdateRole updates an existing role.
func (s *SQLiteStore) UpdateRole(ctx context.Context, role *Role) error {
	if role.ID == "" {
		return errors.New("role ID is required")
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	role.UpdatedAt = time.Now()

	permissionsJSON, err := json.Marshal(role.Permissions)
	if err != nil {
		return fmt.Errorf("failed to marshal permissions: %w", err)
	}

	result, err := s.db.ExecContext(ctx,
		`UPDATE roles SET name = ?, display_name = ?, description = ?, permissions = ?, updated_at = ? WHERE id = ?`,
		role.Name, role.DisplayName, role.Description, string(permissionsJSON), role.UpdatedAt, role.ID,
	)
	if err != nil {
		return fmt.Errorf("failed to update role: %w", err)
	}

	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		return errors.New("role not found")
	}

	return nil
}

// DeleteRole deletes a role by ID.
func (s *SQLiteStore) DeleteRole(ctx context.Context, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Check if it's a system role.
	var isSystem bool
	err := s.db.QueryRowContext(ctx, "SELECT is_system FROM roles WHERE id = ?", id).Scan(&isSystem)
	if err == sql.ErrNoRows {
		return errors.New("role not found")
	}
	if err != nil {
		return fmt.Errorf("failed to check role: %w", err)
	}
	if isSystem {
		return errors.New("cannot delete system role")
	}

	_, err = s.db.ExecContext(ctx, "DELETE FROM roles WHERE id = ?", id)
	if err != nil {
		return fmt.Errorf("failed to delete role: %w", err)
	}

	return nil
}

// User-Role operations.

// GetUserRoles returns all roles assigned to a user.
func (s *SQLiteStore) GetUserRoles(ctx context.Context, userID string) ([]Role, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	rows, err := s.db.QueryContext(ctx,
		`SELECT r.id, r.name, r.display_name, r.description, r.permissions, r.is_system, r.created_at, r.updated_at
		 FROM roles r
		 INNER JOIN user_roles ur ON r.id = ur.role_id
		 WHERE ur.user_id = ?
		 ORDER BY r.name`,
		userID,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to get user roles: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var roles []Role
	for rows.Next() {
		var role Role
		var permissionsJSON string
		var description sql.NullString

		if err := rows.Scan(&role.ID, &role.Name, &role.DisplayName, &description, &permissionsJSON, &role.IsSystem, &role.CreatedAt, &role.UpdatedAt); err != nil {
			return nil, fmt.Errorf("failed to scan role: %w", err)
		}

		if description.Valid {
			role.Description = description.String
		}
		if err := json.Unmarshal([]byte(permissionsJSON), &role.Permissions); err != nil {
			role.Permissions = []string{}
		}
		roles = append(roles, role)
	}

	return roles, rows.Err()
}

// AssignRole assigns a role to a user.
func (s *SQLiteStore) AssignRole(ctx context.Context, userID, roleID string) error {
	if userID == "" || roleID == "" {
		return errors.New("userID and roleID are required")
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	id := generateID()
	_, err := s.db.ExecContext(ctx,
		"INSERT OR IGNORE INTO user_roles (id, user_id, role_id, created_at) VALUES (?, ?, ?, ?)",
		id, userID, roleID, time.Now(),
	)
	if err != nil {
		return fmt.Errorf("failed to assign role: %w", err)
	}

	return nil
}

// RevokeRole removes a role from a user.
func (s *SQLiteStore) RevokeRole(ctx context.Context, userID, roleID string) error {
	if userID == "" || roleID == "" {
		return errors.New("userID and roleID are required")
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	_, err := s.db.ExecContext(ctx,
		"DELETE FROM user_roles WHERE user_id = ? AND role_id = ?",
		userID, roleID,
	)
	if err != nil {
		return fmt.Errorf("failed to revoke role: %w", err)
	}

	return nil
}

// Host Permission operations.

// GetHostPermissions returns all host permissions for a user.
func (s *SQLiteStore) GetHostPermissions(ctx context.Context, userID string) ([]HostPermission, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	rows, err := s.db.QueryContext(ctx,
		`SELECT id, user_id, host_id, can_sudo, expires_at, created_at, updated_at
		 FROM host_permissions WHERE user_id = ?`,
		userID,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to get host permissions: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var perms []HostPermission
	for rows.Next() {
		var perm HostPermission
		var expiresAt sql.NullTime

		if err := rows.Scan(&perm.ID, &perm.UserID, &perm.HostID, &perm.CanSudo, &expiresAt, &perm.CreatedAt, &perm.UpdatedAt); err != nil {
			return nil, fmt.Errorf("failed to scan permission: %w", err)
		}

		if expiresAt.Valid {
			perm.ExpiresAt = expiresAt.Time
		}
		perms = append(perms, perm)
	}

	return perms, rows.Err()
}

// ListAllHostPermissions returns all host permissions in the system.
func (s *SQLiteStore) ListAllHostPermissions(ctx context.Context) ([]HostPermission, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	rows, err := s.db.QueryContext(ctx,
		`SELECT id, user_id, host_id, can_sudo, expires_at, created_at, updated_at
		 FROM host_permissions ORDER BY created_at DESC`,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to list host permissions: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var perms []HostPermission
	for rows.Next() {
		var perm HostPermission
		var expiresAt sql.NullTime

		if err := rows.Scan(&perm.ID, &perm.UserID, &perm.HostID, &perm.CanSudo, &expiresAt, &perm.CreatedAt, &perm.UpdatedAt); err != nil {
			return nil, fmt.Errorf("failed to scan permission: %w", err)
		}

		if expiresAt.Valid {
			perm.ExpiresAt = expiresAt.Time
		}
		perms = append(perms, perm)
	}

	return perms, rows.Err()
}

// GetHostPermission returns a specific host permission.
func (s *SQLiteStore) GetHostPermission(ctx context.Context, userID, hostID string) (*HostPermission, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var perm HostPermission
	var expiresAt sql.NullTime

	err := s.db.QueryRowContext(ctx,
		`SELECT id, user_id, host_id, can_sudo, expires_at, created_at, updated_at
		 FROM host_permissions WHERE user_id = ? AND host_id = ?`,
		userID, hostID,
	).Scan(&perm.ID, &perm.UserID, &perm.HostID, &perm.CanSudo, &expiresAt, &perm.CreatedAt, &perm.UpdatedAt)
	if err == sql.ErrNoRows {
		return nil, errors.New("permission not found")
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get permission: %w", err)
	}

	if expiresAt.Valid {
		perm.ExpiresAt = expiresAt.Time
	}

	return &perm, nil
}

// GrantHostAccess grants a user access to a host.
func (s *SQLiteStore) GrantHostAccess(ctx context.Context, perm *HostPermission) error {
	if perm.UserID == "" || perm.HostID == "" {
		return errors.New("userID and hostID are required")
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if perm.ID == "" {
		perm.ID = generateID()
	}
	perm.CreatedAt = time.Now()
	perm.UpdatedAt = perm.CreatedAt

	var expiresAt interface{}
	if !perm.ExpiresAt.IsZero() {
		expiresAt = perm.ExpiresAt
	}

	_, err := s.db.ExecContext(ctx,
		`INSERT OR REPLACE INTO host_permissions (id, user_id, host_id, can_sudo, expires_at, created_at, updated_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?)`,
		perm.ID, perm.UserID, perm.HostID, perm.CanSudo, expiresAt, perm.CreatedAt, perm.UpdatedAt,
	)
	if err != nil {
		return fmt.Errorf("failed to grant host access: %w", err)
	}

	return nil
}

// RevokeHostAccess removes a user's access to a host.
func (s *SQLiteStore) RevokeHostAccess(ctx context.Context, userID, hostID string) error {
	if userID == "" || hostID == "" {
		return errors.New("userID and hostID are required")
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	_, err := s.db.ExecContext(ctx,
		"DELETE FROM host_permissions WHERE user_id = ? AND host_id = ?",
		userID, hostID,
	)
	if err != nil {
		return fmt.Errorf("failed to revoke host access: %w", err)
	}

	return nil
}

// RevokeHostAccessByID removes a host permission by its ID.
func (s *SQLiteStore) RevokeHostAccessByID(ctx context.Context, id string) error {
	if id == "" {
		return errors.New("id is required")
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	result, err := s.db.ExecContext(ctx,
		"DELETE FROM host_permissions WHERE id = ?",
		id,
	)
	if err != nil {
		return fmt.Errorf("failed to revoke host access: %w", err)
	}

	rows, _ := result.RowsAffected()
	if rows == 0 {
		return errors.New("permission not found")
	}

	return nil
}

// ListUsersWithHostAccess returns all users with access to a specific host.
func (s *SQLiteStore) ListUsersWithHostAccess(ctx context.Context, hostID string) ([]HostPermission, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	rows, err := s.db.QueryContext(ctx,
		`SELECT id, user_id, host_id, can_sudo, expires_at, created_at, updated_at
		 FROM host_permissions WHERE host_id = ?`,
		hostID,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to list users with host access: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var perms []HostPermission
	for rows.Next() {
		var perm HostPermission
		var expiresAt sql.NullTime

		if err := rows.Scan(&perm.ID, &perm.UserID, &perm.HostID, &perm.CanSudo, &expiresAt, &perm.CreatedAt, &perm.UpdatedAt); err != nil {
			return nil, fmt.Errorf("failed to scan permission: %w", err)
		}

		if expiresAt.Valid {
			perm.ExpiresAt = expiresAt.Time
		}
		perms = append(perms, perm)
	}

	return perms, rows.Err()
}

// InitDefaultRoles initializes the default system roles if they don't exist.
func (s *SQLiteStore) InitDefaultRoles(ctx context.Context) error {
	defaultRoles := []struct {
		Name        string
		DisplayName string
		Description string
		Permissions []string
	}{
		{
			Name:        "admin",
			DisplayName: "Administrator",
			Description: "Full system access",
			Permissions: []string{
				"host:connect", "host:view", "host:create", "host:update", "host:delete",
				"user:view", "user:create", "user:update", "user:delete",
				"session:view", "session:watch", "session:terminate",
				"recording:view", "recording:delete",
				"sshkey:view", "sshkey:create", "sshkey:delete",
				"iam:view", "iam:manage",
				"audit:view",
				"settings:view", "settings:update",
			},
		},
		{
			Name:        "developer",
			DisplayName: "Developer",
			Description: "Access to assigned hosts for development",
			Permissions: []string{
				"host:connect", "host:view",
				"session:view",
				"recording:view",
			},
		},
		{
			Name:        "ops",
			DisplayName: "Operations",
			Description: "Access to assigned hosts for operations",
			Permissions: []string{
				"host:connect", "host:view", "host:create", "host:update",
				"user:view",
				"session:view", "session:watch",
				"recording:view",
				"sshkey:view", "sshkey:create",
			},
		},
		{
			Name:        "tester",
			DisplayName: "Tester",
			Description: "Limited access for testing",
			Permissions: []string{
				"host:connect", "host:view",
				"session:view",
			},
		},
		{
			Name:        "auditor",
			DisplayName: "Auditor",
			Description: "Read-only access to logs and sessions",
			Permissions: []string{
				"host:view",
				"user:view",
				"session:view",
				"recording:view",
				"audit:view",
			},
		},
	}

	for _, r := range defaultRoles {
		// Check if role already exists.
		_, err := s.GetRoleByName(ctx, r.Name)
		if err == nil {
			continue // Role exists.
		}

		role := &Role{
			Name:        r.Name,
			DisplayName: r.DisplayName,
			Description: r.Description,
			Permissions: r.Permissions,
			IsSystem:    true,
		}
		if err := s.CreateRole(ctx, role); err != nil {
			return fmt.Errorf("failed to create default role %s: %w", r.Name, err)
		}
	}

	return nil
}

// OTP-related methods.

// SetUserOTPSecret sets the OTP secret for a user.
func (s *SQLiteStore) SetUserOTPSecret(ctx context.Context, userID, secret string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	_, err := s.db.ExecContext(ctx,
		"UPDATE users SET totp_secret = ?, updated_at = ? WHERE id = ?",
		secret, time.Now(), userID,
	)
	if err != nil {
		return fmt.Errorf("failed to set OTP secret: %w", err)
	}
	return nil
}

// EnableUserOTP enables OTP for a user (marks as verified).
func (s *SQLiteStore) EnableUserOTP(ctx context.Context, userID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	_, err := s.db.ExecContext(ctx,
		"UPDATE users SET otp_enabled = 1, otp_verified = 1, updated_at = ? WHERE id = ?",
		time.Now(), userID,
	)
	if err != nil {
		return fmt.Errorf("failed to enable OTP: %w", err)
	}
	return nil
}

// DisableUserOTP disables OTP for a user and clears the secret.
func (s *SQLiteStore) DisableUserOTP(ctx context.Context, userID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	_, err := s.db.ExecContext(ctx,
		"UPDATE users SET otp_enabled = 0, otp_verified = 0, totp_secret = NULL, updated_at = ? WHERE id = ?",
		time.Now(), userID,
	)
	if err != nil {
		return fmt.Errorf("failed to disable OTP: %w", err)
	}
	return nil
}

// GetAllSettings retrieves all settings.
func (s *SQLiteStore) GetAllSettings(ctx context.Context) (map[string]string, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	rows, err := s.db.QueryContext(ctx, "SELECT key, value FROM settings")
	if err != nil {
		return nil, fmt.Errorf("failed to list settings: %w", err)
	}
	defer func() { _ = rows.Close() }()

	settings := make(map[string]string)
	for rows.Next() {
		var key, value string
		if err := rows.Scan(&key, &value); err != nil {
			return nil, fmt.Errorf("failed to scan setting: %w", err)
		}
		settings[key] = value
	}
	return settings, rows.Err()
}

// ============================================================
// Folder CRUD operations
// ============================================================

// CreateFolder creates a new folder.
func (s *SQLiteStore) CreateFolder(ctx context.Context, folder Folder) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now()
	if folder.CreatedAt.IsZero() {
		folder.CreatedAt = now
	}
	folder.UpdatedAt = now

	_, err := s.db.ExecContext(ctx,
		`INSERT INTO folders (id, name, parent_id, path, description, created_at, updated_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?)`,
		folder.ID, folder.Name, folder.ParentID, folder.Path, folder.Description,
		folder.CreatedAt, folder.UpdatedAt,
	)
	if err != nil {
		return fmt.Errorf("failed to create folder: %w", err)
	}
	return nil
}

// GetFolder retrieves a folder by ID.
func (s *SQLiteStore) GetFolder(ctx context.Context, id string) (*Folder, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var folder Folder
	var parentID sql.NullString
	err := s.db.QueryRowContext(ctx,
		`SELECT id, name, parent_id, path, description, created_at, updated_at
		 FROM folders WHERE id = ?`, id,
	).Scan(&folder.ID, &folder.Name, &parentID, &folder.Path, &folder.Description,
		&folder.CreatedAt, &folder.UpdatedAt)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get folder: %w", err)
	}
	folder.ParentID = parentID.String
	return &folder, nil
}

// ListFolders retrieves all folders.
func (s *SQLiteStore) ListFolders(ctx context.Context) ([]Folder, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	rows, err := s.db.QueryContext(ctx,
		`SELECT id, name, parent_id, path, description, created_at, updated_at
		 FROM folders ORDER BY path`)
	if err != nil {
		return nil, fmt.Errorf("failed to list folders: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var folders []Folder
	for rows.Next() {
		var folder Folder
		var parentID sql.NullString
		if err := rows.Scan(&folder.ID, &folder.Name, &parentID, &folder.Path, &folder.Description,
			&folder.CreatedAt, &folder.UpdatedAt); err != nil {
			return nil, fmt.Errorf("failed to scan folder: %w", err)
		}
		folder.ParentID = parentID.String
		folders = append(folders, folder)
	}
	return folders, rows.Err()
}

// ListSubfolders retrieves child folders of a parent folder.
func (s *SQLiteStore) ListSubfolders(ctx context.Context, parentID string) ([]Folder, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var rows *sql.Rows
	var err error
	if parentID == "" {
		rows, err = s.db.QueryContext(ctx,
			`SELECT id, name, parent_id, path, description, created_at, updated_at
			 FROM folders WHERE parent_id IS NULL OR parent_id = '' ORDER BY name`)
	} else {
		rows, err = s.db.QueryContext(ctx,
			`SELECT id, name, parent_id, path, description, created_at, updated_at
			 FROM folders WHERE parent_id = ? ORDER BY name`, parentID)
	}
	if err != nil {
		return nil, fmt.Errorf("failed to list subfolders: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var folders []Folder
	for rows.Next() {
		var folder Folder
		var pid sql.NullString
		if err := rows.Scan(&folder.ID, &folder.Name, &pid, &folder.Path, &folder.Description,
			&folder.CreatedAt, &folder.UpdatedAt); err != nil {
			return nil, fmt.Errorf("failed to scan folder: %w", err)
		}
		folder.ParentID = pid.String
		folders = append(folders, folder)
	}
	return folders, rows.Err()
}

// UpdateFolder updates a folder.
func (s *SQLiteStore) UpdateFolder(ctx context.Context, folder Folder) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	folder.UpdatedAt = time.Now()
	result, err := s.db.ExecContext(ctx,
		`UPDATE folders SET name = ?, parent_id = ?, path = ?, description = ?, updated_at = ?
		 WHERE id = ?`,
		folder.Name, folder.ParentID, folder.Path, folder.Description, folder.UpdatedAt, folder.ID,
	)
	if err != nil {
		return fmt.Errorf("failed to update folder: %w", err)
	}
	rows, _ := result.RowsAffected()
	if rows == 0 {
		return fmt.Errorf("folder not found")
	}
	return nil
}

// DeleteFolder deletes a folder and moves its hosts to the root.
func (s *SQLiteStore) DeleteFolder(ctx context.Context, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	// First move all hosts in this folder to root (no folder)
	_, err := s.db.ExecContext(ctx, `UPDATE hosts SET folder_id = NULL WHERE folder_id = ?`, id)
	if err != nil {
		return fmt.Errorf("failed to update hosts: %w", err)
	}

	// Move subfolders to parent of deleted folder
	var parentID sql.NullString
	_ = s.db.QueryRowContext(ctx, `SELECT parent_id FROM folders WHERE id = ?`, id).Scan(&parentID)

	_, err = s.db.ExecContext(ctx, `UPDATE folders SET parent_id = ? WHERE parent_id = ?`, parentID, id)
	if err != nil {
		return fmt.Errorf("failed to update subfolders: %w", err)
	}

	// Delete the folder
	result, err := s.db.ExecContext(ctx, `DELETE FROM folders WHERE id = ?`, id)
	if err != nil {
		return fmt.Errorf("failed to delete folder: %w", err)
	}
	rows, _ := result.RowsAffected()
	if rows == 0 {
		return fmt.Errorf("folder not found")
	}
	return nil
}

// ListHostsByFolder retrieves hosts in a specific folder.
func (s *SQLiteStore) ListHostsByFolder(ctx context.Context, folderID string) ([]Host, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var rows *sql.Rows
	var err error
	if folderID == "" {
		rows, err = s.db.QueryContext(ctx,
			`SELECT id, name, addr, port, user, users, groups, folder_id, key_id, insecure_ignore_host_key, created_at, updated_at
			 FROM hosts WHERE folder_id IS NULL OR folder_id = '' ORDER BY name`)
	} else {
		rows, err = s.db.QueryContext(ctx,
			`SELECT id, name, addr, port, user, users, groups, folder_id, key_id, insecure_ignore_host_key, created_at, updated_at
			 FROM hosts WHERE folder_id = ? ORDER BY name`, folderID)
	}
	if err != nil {
		return nil, fmt.Errorf("failed to list hosts: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var hosts []Host
	for rows.Next() {
		var h Host
		var usersJSON, groupsJSON string
		var folderID, keyID sql.NullString
		if err := rows.Scan(&h.ID, &h.Name, &h.Addr, &h.Port, &h.User, &usersJSON, &groupsJSON,
			&folderID, &keyID, &h.InsecureIgnoreHostKey, &h.CreatedAt, &h.UpdatedAt); err != nil {
			return nil, fmt.Errorf("failed to scan host: %w", err)
		}
		_ = json.Unmarshal([]byte(usersJSON), &h.Users)
		_ = json.Unmarshal([]byte(groupsJSON), &h.Groups)
		h.FolderID = folderID.String
		h.KeyID = keyID.String
		hosts = append(hosts, h)
	}
	return hosts, rows.Err()
}

// ============================================================
// Audit Log Operations
// ============================================================

// CreateAuditLog creates a new audit log entry.
func (s *SQLiteStore) CreateAuditLog(ctx context.Context, log *AuditLog) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if log.ID == "" {
		log.ID = generateID()
	}
	if log.Timestamp.IsZero() {
		log.Timestamp = time.Now()
	}
	log.CreatedAt = time.Now()

	detailsJSON, _ := json.Marshal(log.Details)

	_, err := s.db.ExecContext(ctx,
		`INSERT INTO audit_logs (id, timestamp, event_type, username, source_ip, target_host, action, result, details, created_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		log.ID, log.Timestamp, log.EventType, log.Username, log.SourceIP, log.TargetHost, log.Action, log.Result, string(detailsJSON), log.CreatedAt,
	)
	if err != nil {
		return fmt.Errorf("failed to create audit log: %w", err)
	}
	return nil
}

// ListAuditLogs returns audit logs with optional filters.
func (s *SQLiteStore) ListAuditLogs(ctx context.Context, username, eventType string, startTime, endTime time.Time, limit, offset int) ([]AuditLog, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	query := `SELECT id, timestamp, event_type, username, source_ip, target_host, action, result, details, created_at
	          FROM audit_logs WHERE 1=1`
	args := []interface{}{}

	if username != "" {
		query += " AND username = ?"
		args = append(args, username)
	}
	if eventType != "" {
		query += " AND event_type = ?"
		args = append(args, eventType)
	}
	if !startTime.IsZero() {
		query += " AND timestamp >= ?"
		args = append(args, startTime)
	}
	if !endTime.IsZero() {
		query += " AND timestamp <= ?"
		args = append(args, endTime)
	}

	query += " ORDER BY timestamp DESC"

	if limit > 0 {
		query += " LIMIT ?"
		args = append(args, limit)
	}
	if offset > 0 {
		query += " OFFSET ?"
		args = append(args, offset)
	}

	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("failed to query audit logs: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var logs []AuditLog
	for rows.Next() {
		var log AuditLog
		var sourceIP, targetHost, detailsJSON sql.NullString
		if err := rows.Scan(&log.ID, &log.Timestamp, &log.EventType, &log.Username, &sourceIP, &targetHost, &log.Action, &log.Result, &detailsJSON, &log.CreatedAt); err != nil {
			return nil, fmt.Errorf("failed to scan audit log: %w", err)
		}
		log.SourceIP = sourceIP.String
		log.TargetHost = targetHost.String
		if detailsJSON.Valid && detailsJSON.String != "" {
			_ = json.Unmarshal([]byte(detailsJSON.String), &log.Details)
		}
		logs = append(logs, log)
	}
	return logs, rows.Err()
}

// CleanupAuditLogs deletes audit logs older than the specified time.
func (s *SQLiteStore) CleanupAuditLogs(ctx context.Context, before time.Time) (int64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	result, err := s.db.ExecContext(ctx, "DELETE FROM audit_logs WHERE timestamp < ?", before)
	if err != nil {
		return 0, fmt.Errorf("failed to cleanup audit logs: %w", err)
	}
	return result.RowsAffected()
}
