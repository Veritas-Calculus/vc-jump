package storage

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"time"
)

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

	// Convert empty ParentID to nil for FK constraint (NULL is valid, "" is not).
	var parentID interface{}
	if folder.ParentID != "" {
		parentID = folder.ParentID
	}

	_, err := s.db.ExecContext(ctx,
		`INSERT INTO folders (id, name, parent_id, path, description, created_at, updated_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?)`,
		folder.ID, folder.Name, parentID, folder.Path, folder.Description,
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

	// Convert empty ParentID to nil for FK constraint.
	var parentID interface{}
	if folder.ParentID != "" {
		parentID = folder.ParentID
	}

	folder.UpdatedAt = time.Now()
	result, err := s.db.ExecContext(ctx,
		`UPDATE folders SET name = ?, parent_id = ?, path = ?, description = ?, updated_at = ?
		 WHERE id = ?`,
		folder.Name, parentID, folder.Path, folder.Description, folder.UpdatedAt, folder.ID,
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
