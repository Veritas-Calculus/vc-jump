// Package dashboard provides a web-based management interface for vc-jump.
package dashboard

import (
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/Veritas-Calculus/vc-jump/internal/storage"
)

// Predefined permissions list for UI.
var allPermissions = []permissionInfo{
	// Host permissions.
	{ID: "host:connect", Name: "Connect to Hosts", Category: "Hosts", Description: "SSH to assigned hosts"},
	{ID: "host:view", Name: "View Hosts", Category: "Hosts", Description: "View host list"},
	{ID: "host:create", Name: "Create Hosts", Category: "Hosts", Description: "Create new hosts"},
	{ID: "host:update", Name: "Update Hosts", Category: "Hosts", Description: "Update host configuration"},
	{ID: "host:delete", Name: "Delete Hosts", Category: "Hosts", Description: "Delete hosts"},

	// User permissions.
	{ID: "user:view", Name: "View Users", Category: "Users", Description: "View user list"},
	{ID: "user:create", Name: "Create Users", Category: "Users", Description: "Create new users"},
	{ID: "user:update", Name: "Update Users", Category: "Users", Description: "Update user information"},
	{ID: "user:delete", Name: "Delete Users", Category: "Users", Description: "Delete users"},

	// Session permissions.
	{ID: "session:view", Name: "View Sessions", Category: "Sessions", Description: "View session history"},
	{ID: "session:watch", Name: "Watch Sessions", Category: "Sessions", Description: "Watch live sessions"},
	{ID: "session:terminate", Name: "Terminate Sessions", Category: "Sessions", Description: "Terminate active sessions"},

	// Recording permissions.
	{ID: "recording:view", Name: "View Recordings", Category: "Recordings", Description: "View session recordings"},
	{ID: "recording:delete", Name: "Delete Recordings", Category: "Recordings", Description: "Delete recordings"},

	// SSH Key permissions.
	{ID: "sshkey:view", Name: "View SSH Keys", Category: "SSH Keys", Description: "View SSH keys"},
	{ID: "sshkey:create", Name: "Create SSH Keys", Category: "SSH Keys", Description: "Create/import SSH keys"},
	{ID: "sshkey:delete", Name: "Delete SSH Keys", Category: "SSH Keys", Description: "Delete SSH keys"},

	// IAM permissions.
	{ID: "iam:view", Name: "View IAM", Category: "IAM", Description: "View IAM settings"},
	{ID: "iam:manage", Name: "Manage IAM", Category: "IAM", Description: "Manage roles and permissions"},

	// Audit permissions.
	{ID: "audit:view", Name: "View Audit Logs", Category: "Audit", Description: "View audit logs"},

	// Settings permissions.
	{ID: "settings:view", Name: "View Settings", Category: "Settings", Description: "View system settings"},
	{ID: "settings:update", Name: "Update Settings", Category: "Settings", Description: "Update system settings"},
}

type permissionInfo struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Category    string `json:"category"`
	Description string `json:"description"`
}

// handlePermissionsList returns all available permissions.
func (s *Server) handlePermissionsList(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		s.jsonError(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	s.jsonResponse(w, allPermissions)
}

// handleRoles handles /api/iam/roles.
func (s *Server) handleRoles(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		s.listRoles(w, r)
	case http.MethodPost:
		s.createRole(w, r)
	default:
		s.jsonError(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *Server) listRoles(w http.ResponseWriter, r *http.Request) {
	roles, err := s.store.ListRoles(r.Context())
	if err != nil {
		s.jsonError(w, "failed to list roles", http.StatusInternalServerError)
		return
	}

	s.jsonResponse(w, roles)
}

func (s *Server) createRole(w http.ResponseWriter, r *http.Request) {
	if !s.hasPermission(r, "iam:manage") {
		s.jsonError(w, "forbidden", http.StatusForbidden)
		return
	}

	var role storage.Role
	if err := json.NewDecoder(r.Body).Decode(&role); err != nil {
		s.jsonError(w, "invalid request body", http.StatusBadRequest)
		return
	}

	if role.Name == "" {
		s.jsonError(w, "role name is required", http.StatusBadRequest)
		return
	}

	if err := s.store.CreateRole(r.Context(), &role); err != nil {
		s.jsonError(w, err.Error(), http.StatusBadRequest)
		return
	}

	s.jsonResponse(w, role)
}

// handleRole handles /api/iam/roles/:id.
func (s *Server) handleRole(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimPrefix(r.URL.Path, "/api/iam/roles/")
	if id == "" {
		s.jsonError(w, "role ID required", http.StatusBadRequest)
		return
	}

	switch r.Method {
	case http.MethodGet:
		s.getRole(w, r, id)
	case http.MethodPut:
		s.updateRole(w, r, id)
	case http.MethodDelete:
		s.deleteRole(w, r, id)
	default:
		s.jsonError(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *Server) getRole(w http.ResponseWriter, r *http.Request, id string) {
	role, err := s.store.GetRole(r.Context(), id)
	if err != nil {
		s.jsonError(w, "role not found", http.StatusNotFound)
		return
	}

	s.jsonResponse(w, role)
}

func (s *Server) updateRole(w http.ResponseWriter, r *http.Request, id string) {
	if !s.hasPermission(r, "iam:manage") {
		s.jsonError(w, "forbidden", http.StatusForbidden)
		return
	}

	existing, err := s.store.GetRole(r.Context(), id)
	if err != nil {
		s.jsonError(w, "role not found", http.StatusNotFound)
		return
	}

	if existing.IsSystem {
		s.jsonError(w, "cannot modify system role", http.StatusForbidden)
		return
	}

	var role storage.Role
	if err := json.NewDecoder(r.Body).Decode(&role); err != nil {
		s.jsonError(w, "invalid request body", http.StatusBadRequest)
		return
	}

	role.ID = id
	if err := s.store.UpdateRole(r.Context(), &role); err != nil {
		s.jsonError(w, err.Error(), http.StatusBadRequest)
		return
	}

	s.jsonResponse(w, role)
}

func (s *Server) deleteRole(w http.ResponseWriter, r *http.Request, id string) {
	if !s.hasPermission(r, "iam:manage") {
		s.jsonError(w, "forbidden", http.StatusForbidden)
		return
	}

	if err := s.store.DeleteRole(r.Context(), id); err != nil {
		s.jsonError(w, err.Error(), http.StatusBadRequest)
		return
	}

	s.jsonResponse(w, map[string]string{"status": "deleted"})
}

// handleUserRoles handles /api/iam/user-roles/:userID.
func (s *Server) handleUserRoles(w http.ResponseWriter, r *http.Request) {
	userID := strings.TrimPrefix(r.URL.Path, "/api/iam/user-roles/")
	if userID == "" {
		s.jsonError(w, "user ID required", http.StatusBadRequest)
		return
	}

	switch r.Method {
	case http.MethodGet:
		s.getUserRoles(w, r, userID)
	case http.MethodPost:
		s.assignUserRole(w, r, userID)
	case http.MethodDelete:
		s.revokeUserRole(w, r, userID)
	default:
		s.jsonError(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *Server) getUserRoles(w http.ResponseWriter, r *http.Request, userID string) {
	roles, err := s.store.GetUserRoles(r.Context(), userID)
	if err != nil {
		s.jsonError(w, "failed to get user roles", http.StatusInternalServerError)
		return
	}

	s.jsonResponse(w, roles)
}

type roleAssignment struct {
	RoleID string `json:"role_id"`
}

func (s *Server) assignUserRole(w http.ResponseWriter, r *http.Request, userID string) {
	if !s.hasPermission(r, "iam:manage") {
		s.jsonError(w, "forbidden", http.StatusForbidden)
		return
	}

	var req roleAssignment
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.jsonError(w, "invalid request body", http.StatusBadRequest)
		return
	}

	if req.RoleID == "" {
		s.jsonError(w, "role_id is required", http.StatusBadRequest)
		return
	}

	if err := s.store.AssignRole(r.Context(), userID, req.RoleID); err != nil {
		s.jsonError(w, err.Error(), http.StatusBadRequest)
		return
	}

	s.jsonResponse(w, map[string]string{"status": "assigned"})
}

func (s *Server) revokeUserRole(w http.ResponseWriter, r *http.Request, userID string) {
	if !s.hasPermission(r, "iam:manage") {
		s.jsonError(w, "forbidden", http.StatusForbidden)
		return
	}

	roleID := r.URL.Query().Get("role_id")
	if roleID == "" {
		s.jsonError(w, "role_id query parameter is required", http.StatusBadRequest)
		return
	}

	// Protect admin user's admin role from being revoked.
	user, err := s.store.GetUser(r.Context(), userID)
	if err != nil {
		s.jsonError(w, "user not found", http.StatusNotFound)
		return
	}
	if user.Username == "admin" {
		role, err := s.store.GetRole(r.Context(), roleID)
		if err == nil && role.Name == "admin" {
			s.jsonError(w, "cannot revoke admin role from admin user", http.StatusForbidden)
			return
		}
	}

	if err := s.store.RevokeRole(r.Context(), userID, roleID); err != nil {
		s.jsonError(w, err.Error(), http.StatusBadRequest)
		return
	}

	s.jsonResponse(w, map[string]string{"status": "revoked"})
}

// handleHostPermissions handles /api/iam/host-permissions.
func (s *Server) handleHostPermissions(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		s.listHostPermissions(w, r)
	case http.MethodPost:
		s.grantHostPermission(w, r)
	default:
		s.jsonError(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *Server) listHostPermissions(w http.ResponseWriter, r *http.Request) {
	userID := r.URL.Query().Get("user_id")
	hostID := r.URL.Query().Get("host_id")

	if userID != "" {
		perms, err := s.store.GetHostPermissions(r.Context(), userID)
		if err != nil {
			s.jsonError(w, "failed to get permissions", http.StatusInternalServerError)
			return
		}
		s.jsonResponse(w, perms)
		return
	}

	if hostID != "" {
		perms, err := s.store.ListUsersWithHostAccess(r.Context(), hostID)
		if err != nil {
			s.jsonError(w, "failed to get permissions", http.StatusInternalServerError)
			return
		}
		s.jsonResponse(w, perms)
		return
	}

	// No filter - return all host permissions.
	perms, err := s.store.ListAllHostPermissions(r.Context())
	if err != nil {
		s.jsonError(w, "failed to list permissions", http.StatusInternalServerError)
		return
	}
	s.jsonResponse(w, perms)
}

type hostPermissionRequest struct {
	UserID    string `json:"user_id"`
	HostID    string `json:"host_id"`
	CanSudo   bool   `json:"can_sudo"`
	ExpiresAt string `json:"expires_at,omitempty"` // RFC3339 format.
}

func (s *Server) grantHostPermission(w http.ResponseWriter, r *http.Request) {
	if !s.hasPermission(r, "iam:manage") {
		s.jsonError(w, "forbidden", http.StatusForbidden)
		return
	}

	var req hostPermissionRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.jsonError(w, "invalid request body", http.StatusBadRequest)
		return
	}

	if req.UserID == "" || req.HostID == "" {
		s.jsonError(w, "user_id and host_id are required", http.StatusBadRequest)
		return
	}

	perm := &storage.HostPermission{
		UserID:  req.UserID,
		HostID:  req.HostID,
		CanSudo: req.CanSudo,
	}

	if req.ExpiresAt != "" {
		t, err := time.Parse(time.RFC3339, req.ExpiresAt)
		if err != nil {
			s.jsonError(w, "invalid expires_at format (use RFC3339)", http.StatusBadRequest)
			return
		}
		perm.ExpiresAt = t
	}

	if err := s.store.GrantHostAccess(r.Context(), perm); err != nil {
		s.jsonError(w, err.Error(), http.StatusBadRequest)
		return
	}

	s.jsonResponse(w, perm)
}

// handleHostPermission handles /api/iam/host-permissions/:id.
func (s *Server) handleHostPermission(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.Path, "/api/iam/host-permissions/")

	switch r.Method {
	case http.MethodDelete:
		s.revokeHostPermission(w, r, path)
	default:
		s.jsonError(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *Server) revokeHostPermission(w http.ResponseWriter, r *http.Request, path string) {
	if !s.hasPermission(r, "iam:manage") {
		s.jsonError(w, "forbidden", http.StatusForbidden)
		return
	}

	// Path can be either:
	// - Single ID (e.g., "abc123") - delete by permission ID
	// - userID/hostID format (e.g., "user1/host1") - delete by user and host
	parts := strings.Split(path, "/")

	if len(parts) == 1 && parts[0] != "" {
		// Delete by permission ID.
		if err := s.store.RevokeHostAccessByID(r.Context(), parts[0]); err != nil {
			s.jsonError(w, err.Error(), http.StatusBadRequest)
			return
		}
		s.jsonResponse(w, map[string]string{"status": "revoked"})
		return
	}

	if len(parts) == 2 {
		// Delete by userID/hostID.
		userID, hostID := parts[0], parts[1]
		if err := s.store.RevokeHostAccess(r.Context(), userID, hostID); err != nil {
			s.jsonError(w, err.Error(), http.StatusBadRequest)
			return
		}
		s.jsonResponse(w, map[string]string{"status": "revoked"})
		return
	}

	s.jsonError(w, "invalid path format", http.StatusBadRequest)
}

// hasPermission checks if the current user has a specific permission.
func (s *Server) hasPermission(r *http.Request, permission string) bool {
	userID, ok := r.Context().Value(contextKeyUserID).(string)
	if !ok || userID == "" {
		return false
	}

	roles, err := s.store.GetUserRoles(r.Context(), userID)
	if err != nil {
		return false
	}

	for _, role := range roles {
		for _, perm := range role.Permissions {
			if perm == permission {
				return true
			}
		}
	}

	return false
}

// isAdmin checks if the current user has admin role.
func (s *Server) isAdmin(r *http.Request) bool {
	userID, ok := r.Context().Value(contextKeyUserID).(string)
	if !ok || userID == "" {
		return false
	}

	roles, err := s.store.GetUserRoles(r.Context(), userID)
	if err != nil {
		return false
	}

	for _, role := range roles {
		if role.Name == "admin" {
			return true
		}
	}

	return false
}
