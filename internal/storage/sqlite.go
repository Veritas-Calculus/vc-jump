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
	CREATE TABLE IF NOT EXISTS hosts (
		id TEXT PRIMARY KEY,
		name TEXT UNIQUE NOT NULL,
		addr TEXT NOT NULL,
		port INTEGER NOT NULL DEFAULT 22,
		user TEXT DEFAULT 'root',
		users TEXT DEFAULT '[]',
		groups TEXT DEFAULT '[]',
		key_id TEXT,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
	);

	CREATE TABLE IF NOT EXISTS users (
		id TEXT PRIMARY KEY,
		username TEXT UNIQUE NOT NULL,
		password_hash TEXT,
		groups TEXT DEFAULT '[]',
		public_keys TEXT DEFAULT '[]',
		allowed_hosts TEXT DEFAULT '[]',
		source TEXT DEFAULT 'local',
		totp_secret TEXT,
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
	return nil
}

// Host operations.

// GetHost retrieves a host by ID.
func (s *SQLiteStore) GetHost(ctx context.Context, id string) (*Host, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var host Host
	var usersJSON, groupsJSON string
	var keyID, user sql.NullString
	err := s.db.QueryRowContext(ctx,
		"SELECT id, name, addr, port, user, users, groups, key_id, created_at, updated_at FROM hosts WHERE id = ?",
		id,
	).Scan(&host.ID, &host.Name, &host.Addr, &host.Port, &user, &usersJSON, &groupsJSON, &keyID, &host.CreatedAt, &host.UpdatedAt)

	if err == sql.ErrNoRows {
		return nil, errors.New("host not found")
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get host: %w", err)
	}

	if keyID.Valid {
		host.KeyID = keyID.String
	}
	if user.Valid {
		host.User = user.String
	} else {
		host.User = "root"
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
	var keyID, user sql.NullString
	err := s.db.QueryRowContext(ctx,
		"SELECT id, name, addr, port, user, users, groups, key_id, created_at, updated_at FROM hosts WHERE name = ?",
		name,
	).Scan(&host.ID, &host.Name, &host.Addr, &host.Port, &user, &usersJSON, &groupsJSON, &keyID, &host.CreatedAt, &host.UpdatedAt)

	if err == sql.ErrNoRows {
		return nil, errors.New("host not found")
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get host: %w", err)
	}

	if keyID.Valid {
		host.KeyID = keyID.String
	}
	if user.Valid {
		host.User = user.String
	} else {
		host.User = "root"
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
		"SELECT id, name, addr, port, user, users, groups, key_id, created_at, updated_at FROM hosts ORDER BY name",
	)
	if err != nil {
		return nil, fmt.Errorf("failed to list hosts: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var hosts []Host
	for rows.Next() {
		var host Host
		var usersJSON, groupsJSON string
		var keyID, user sql.NullString
		if err := rows.Scan(&host.ID, &host.Name, &host.Addr, &host.Port, &user, &usersJSON, &groupsJSON, &keyID, &host.CreatedAt, &host.UpdatedAt); err != nil {
			return nil, fmt.Errorf("failed to scan host: %w", err)
		}

		if keyID.Valid {
			host.KeyID = keyID.String
		}
		if user.Valid {
			host.User = user.String
		} else {
			host.User = "root"
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

	_, err := s.db.ExecContext(ctx,
		"INSERT INTO hosts (id, name, addr, port, user, users, groups, key_id, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
		host.ID, host.Name, host.Addr, host.Port, host.User, string(usersJSON), string(groupsJSON), keyID, host.CreatedAt, host.UpdatedAt,
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

	result, err := s.db.ExecContext(ctx,
		"UPDATE hosts SET name = ?, addr = ?, port = ?, user = ?, users = ?, groups = ?, key_id = ?, updated_at = ? WHERE id = ?",
		host.Name, host.Addr, host.Port, host.User, string(usersJSON), string(groupsJSON), keyID, host.UpdatedAt, host.ID,
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
	var allowedHostsJSON, passwordHash, source sql.NullString
	var lastLoginAt sql.NullTime
	err := s.db.QueryRowContext(ctx,
		"SELECT id, username, password_hash, groups, public_keys, allowed_hosts, source, is_active, last_login_at, created_at, updated_at FROM users WHERE id = ?",
		id,
	).Scan(&user.ID, &user.Username, &passwordHash, &groupsJSON, &publicKeysJSON, &allowedHostsJSON, &source, &user.IsActive, &lastLoginAt, &user.CreatedAt, &user.UpdatedAt)

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
	var allowedHostsJSON, passwordHash, source sql.NullString
	var lastLoginAt sql.NullTime
	err := s.db.QueryRowContext(ctx,
		"SELECT id, username, password_hash, groups, public_keys, allowed_hosts, source, is_active, last_login_at, created_at, updated_at FROM users WHERE username = ?",
		username,
	).Scan(&user.ID, &user.Username, &passwordHash, &groupsJSON, &publicKeysJSON, &allowedHostsJSON, &source, &user.IsActive, &lastLoginAt, &user.CreatedAt, &user.UpdatedAt)

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
		"SELECT id, username, password_hash, groups, public_keys, allowed_hosts, source, is_active, last_login_at, created_at, updated_at FROM users ORDER BY username",
	)
	if err != nil {
		return nil, fmt.Errorf("failed to list users: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var users []User
	for rows.Next() {
		var user User
		var groupsJSON, publicKeysJSON string
		var allowedHostsJSON, passwordHash, source sql.NullString
		var lastLoginAt sql.NullTime
		if err := rows.Scan(&user.ID, &user.Username, &passwordHash, &groupsJSON, &publicKeysJSON, &allowedHostsJSON, &source, &user.IsActive, &lastLoginAt, &user.CreatedAt, &user.UpdatedAt); err != nil {
			return nil, fmt.Errorf("failed to scan user: %w", err)
		}

		if passwordHash.Valid {
			user.PasswordHash = passwordHash.String
		}
		if source.Valid {
			user.Source = UserSource(source.String)
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

// GetOrCreateUser retrieves a user by username, creating them if they don't exist.
// Used for SSH/OIDC authentication where users are created on first login.
func (s *SQLiteStore) GetOrCreateUser(ctx context.Context, username string, source UserSource, publicKey string) (*User, error) {
	// Try to get existing user first.
	user, err := s.GetUserByUsername(ctx, username)
	if err == nil {
		// User exists, update public key if provided and not already stored.
		if publicKey != "" {
			keyExists := false
			for _, k := range user.PublicKeys {
				if k == publicKey {
					keyExists = true
					break
				}
			}
			if !keyExists {
				user.PublicKeys = append(user.PublicKeys, publicKey)
				_ = s.UpdateUser(ctx, user)
			}
		}
		return user, nil
	}

	// User doesn't exist, create new one.
	newUser := &User{
		Username:   username,
		Groups:     []string{"users"},
		Source:     source,
		IsActive:   true,
		PublicKeys: []string{},
	}
	if publicKey != "" {
		newUser.PublicKeys = []string{publicKey}
	}

	if err := s.CreateUser(ctx, newUser); err != nil {
		return nil, fmt.Errorf("failed to create user: %w", err)
	}

	return newUser, nil
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
	var groupsJSON, publicKeysJSON string
	var passwordHash, totpSecret sql.NullString
	var lastLoginAt sql.NullTime
	var isActive int
	err := s.db.QueryRowContext(ctx,
		"SELECT id, username, password_hash, groups, public_keys, totp_secret, is_active, last_login_at, created_at, updated_at FROM users WHERE username = ?",
		username,
	).Scan(&user.ID, &user.Username, &passwordHash, &groupsJSON, &publicKeysJSON, &totpSecret, &isActive, &lastLoginAt, &user.CreatedAt, &user.UpdatedAt)

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

	return &user, nil
}

// CreateUserWithPassword creates a new user with password.
func (s *SQLiteStore) CreateUserWithPassword(ctx context.Context, user *UserWithPassword) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if user.ID == "" {
		user.ID = generateID()
	}
	user.CreatedAt = time.Now()
	user.UpdatedAt = time.Now()

	groupsJSON, _ := json.Marshal(user.Groups)
	publicKeysJSON, _ := json.Marshal(user.PublicKeys)

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
		"INSERT INTO users (id, username, password_hash, groups, public_keys, totp_secret, is_active, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
		user.ID, user.Username, passwordHash, string(groupsJSON), string(publicKeysJSON), totpSecret, isActive, user.CreatedAt, user.UpdatedAt,
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
