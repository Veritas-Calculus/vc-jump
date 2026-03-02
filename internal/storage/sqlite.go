// Package storage provides data persistence for vc-jump.
package storage

import (
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

	CREATE TABLE IF NOT EXISTS recordings (
		id TEXT PRIMARY KEY,
		session_id TEXT,
		username TEXT NOT NULL,
		hostname TEXT NOT NULL,
		filename TEXT NOT NULL,
		storage_type TEXT NOT NULL DEFAULT 'local',
		storage_path TEXT,
		s3_bucket TEXT,
		s3_key TEXT,
		file_size INTEGER DEFAULT 0,
		duration INTEGER DEFAULT 0,
		start_time DATETIME NOT NULL,
		end_time DATETIME,
		checksum TEXT,
		is_complete INTEGER DEFAULT 0,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		FOREIGN KEY (session_id) REFERENCES sessions(id) ON DELETE SET NULL
	);

	CREATE INDEX IF NOT EXISTS idx_roles_name ON roles(name);
	CREATE INDEX IF NOT EXISTS idx_user_roles_user_id ON user_roles(user_id);
	CREATE INDEX IF NOT EXISTS idx_user_roles_role_id ON user_roles(role_id);
	CREATE INDEX IF NOT EXISTS idx_host_permissions_user_id ON host_permissions(user_id);
	CREATE INDEX IF NOT EXISTS idx_host_permissions_host_id ON host_permissions(host_id);
	CREATE INDEX IF NOT EXISTS idx_audit_logs_timestamp ON audit_logs(timestamp);
	CREATE INDEX IF NOT EXISTS idx_audit_logs_username ON audit_logs(username);
	CREATE INDEX IF NOT EXISTS idx_audit_logs_event_type ON audit_logs(event_type);
	CREATE INDEX IF NOT EXISTS idx_recordings_session_id ON recordings(session_id);
	CREATE INDEX IF NOT EXISTS idx_recordings_username ON recordings(username);
	CREATE INDEX IF NOT EXISTS idx_recordings_start_time ON recordings(start_time);
	CREATE INDEX IF NOT EXISTS idx_recordings_storage_type ON recordings(storage_type);

	CREATE TABLE IF NOT EXISTS api_keys (
		id TEXT PRIMARY KEY,
		user_id TEXT NOT NULL,
		name TEXT NOT NULL,
		description TEXT,
		token_prefix TEXT NOT NULL,
		token_hash TEXT UNIQUE NOT NULL,
		scopes TEXT DEFAULT '[]',
		last_used_at DATETIME,
		expires_at DATETIME,
		is_active INTEGER DEFAULT 1,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
	);

	CREATE INDEX IF NOT EXISTS idx_api_keys_user_id ON api_keys(user_id);
	CREATE INDEX IF NOT EXISTS idx_api_keys_token_prefix ON api_keys(token_prefix);
	CREATE INDEX IF NOT EXISTS idx_api_keys_token_hash ON api_keys(token_hash);
	`

	_, err := s.db.Exec(schema)
	if err != nil {
		return err
	}

	// Run migrations for existing databases.
	return s.runMigrations()
}

// runMigrations applies any necessary schema migrations using a versioned system.
func (s *SQLiteStore) runMigrations() error {
	// Ensure migration tracking table exists.
	_, err := s.db.Exec(`
		CREATE TABLE IF NOT EXISTS schema_migrations (
			version INTEGER PRIMARY KEY,
			name TEXT NOT NULL,
			applied_at DATETIME DEFAULT CURRENT_TIMESTAMP
		)
	`)
	if err != nil {
		return fmt.Errorf("failed to create schema_migrations table: %w", err)
	}

	// Define migrations in order. Each runs exactly once.
	migrations := []struct {
		version int
		name    string
		sql     string
	}{
		{1, "add_hosts_user_column", "ALTER TABLE hosts ADD COLUMN user TEXT DEFAULT 'root'"},
		{2, "add_hosts_insecure_flag", "ALTER TABLE hosts ADD COLUMN insecure_ignore_host_key INTEGER DEFAULT 0"},
		{3, "add_users_otp_enabled", "ALTER TABLE users ADD COLUMN otp_enabled INTEGER DEFAULT 0"},
		{4, "add_users_otp_verified", "ALTER TABLE users ADD COLUMN otp_verified INTEGER DEFAULT 0"},
	}

	for _, m := range migrations {
		applied, err := s.isMigrationApplied(m.version)
		if err != nil {
			return fmt.Errorf("migration check failed for v%d (%s): %w", m.version, m.name, err)
		}
		if applied {
			continue
		}

		// Execute the migration SQL.
		_, err = s.db.Exec(m.sql)
		if err != nil {
			// For ALTER TABLE ADD COLUMN, "duplicate column" means it was applied
			// before the migration table existed (legacy system). Mark it applied.
			if strings.Contains(err.Error(), "duplicate column") {
				_ = s.recordMigration(m.version, m.name)
				continue
			}
			return fmt.Errorf("migration v%d (%s) failed: %w", m.version, m.name, err)
		}

		// Record the migration.
		if err := s.recordMigration(m.version, m.name); err != nil {
			return fmt.Errorf("failed to record migration v%d: %w", m.version, err)
		}
	}

	// Initialize default RBAC roles if they don't exist.
	if err := s.initDefaultRoles(); err != nil {
		return fmt.Errorf("failed to initialize default roles: %w", err)
	}

	return nil
}

// isMigrationApplied checks if a migration version has already been applied.
func (s *SQLiteStore) isMigrationApplied(version int) (bool, error) {
	var count int
	err := s.db.QueryRow("SELECT COUNT(*) FROM schema_migrations WHERE version = ?", version).Scan(&count)
	if err != nil {
		return false, err
	}
	return count > 0, nil
}

// recordMigration records a migration as applied.
func (s *SQLiteStore) recordMigration(version int, name string) error {
	_, err := s.db.Exec("INSERT INTO schema_migrations (version, name) VALUES (?, ?)", version, name)
	return err
}

// GetMigrationVersion returns the current schema migration version.
func (s *SQLiteStore) GetMigrationVersion() (int, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var version int
	err := s.db.QueryRow("SELECT COALESCE(MAX(version), 0) FROM schema_migrations").Scan(&version)
	if err != nil {
		return 0, fmt.Errorf("failed to get migration version: %w", err)
	}
	return version, nil
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
