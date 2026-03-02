package storage

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"
)

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
