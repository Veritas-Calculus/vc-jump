package dashboard

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/Veritas-Calculus/vc-jump/internal/auth"
	"github.com/Veritas-Calculus/vc-jump/internal/storage"
)

func (s *Server) handleUsers(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		// List users requires user:view permission.
		if !s.hasPermission(r, "user:view") {
			s.jsonError(w, "permission denied", http.StatusForbidden)
			return
		}

		toSafeUser := func(u storage.User) map[string]interface{} {
			return map[string]interface{}{
				"id":            u.ID,
				"username":      u.Username,
				"groups":        u.Groups,
				"allowed_hosts": u.AllowedHosts,
				"source":        u.Source,
				"otp_enabled":   u.OTPEnabled,
				"created_at":    u.CreatedAt,
			}
		}

		pg := parsePagination(r)
		if pg != nil {
			total, err := s.store.CountUsers(r.Context())
			if err != nil {
				s.jsonError(w, "failed to count users", http.StatusInternalServerError)
				return
			}
			users, err := s.store.ListUsersPaginated(r.Context(), pg.PageSize, pg.Offset)
			if err != nil {
				s.jsonError(w, "failed to list users", http.StatusInternalServerError)
				return
			}
			var safeUsers []map[string]interface{}
			for _, u := range users {
				safeUsers = append(safeUsers, toSafeUser(u))
			}
			s.jsonResponse(w, newPaginatedResponse(safeUsers, total, pg))
		} else {
			users, err := s.store.ListUsers(r.Context())
			if err != nil {
				s.jsonError(w, "failed to list users", http.StatusInternalServerError)
				return
			}
			var safeUsers []map[string]interface{}
			for _, u := range users {
				safeUsers = append(safeUsers, toSafeUser(u))
			}
			s.jsonResponse(w, safeUsers)
		}

	case http.MethodPost:
		if !s.hasPermission(r, "user:create") {
			s.jsonError(w, "permission denied", http.StatusForbidden)
			return
		}

		var req struct {
			Username     string   `json:"username"`
			Password     string   `json:"password"` //nolint:gosec // G117: user creation request field
			Groups       []string `json:"groups"`
			AllowedHosts []string `json:"allowed_hosts"`
			RoleIDs      []string `json:"role_ids"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			s.jsonError(w, "invalid request body", http.StatusBadRequest)
			return
		}

		if req.Username == "" {
			s.jsonError(w, "username is required", http.StatusBadRequest)
			return
		}

		passwordHash := ""
		if req.Password != "" {
			var err error
			passwordHash, err = auth.HashPassword(req.Password)
			if err != nil {
				s.jsonError(w, "failed to hash password", http.StatusInternalServerError)
				return
			}
		}

		user := &storage.UserWithPassword{
			User: storage.User{
				Username:     req.Username,
				Groups:       req.Groups,
				AllowedHosts: req.AllowedHosts,
				Source:       "local",
			},
			PasswordHash: passwordHash,
			IsActive:     true,
		}
		if err := s.store.CreateUserWithPassword(r.Context(), user); err != nil {
			s.jsonError(w, "failed to create user", http.StatusInternalServerError)
			return
		}

		// Assign roles if provided.
		if len(req.RoleIDs) > 0 {
			dbUser, err := s.store.GetUserByUsername(r.Context(), req.Username)
			if err == nil {
				for _, roleID := range req.RoleIDs {
					_ = s.store.AssignRole(r.Context(), dbUser.ID, roleID)
				}
			}
		}

		s.jsonResponse(w, map[string]interface{}{
			"id":       user.ID,
			"username": user.Username,
			"groups":   user.Groups,
			"source":   user.Source,
		})

	default:
		s.jsonError(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *Server) handleUser(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimPrefix(r.URL.Path, "/api/users/")
	if id == "" {
		s.jsonError(w, "user id required", http.StatusBadRequest)
		return
	}

	switch r.Method {
	case http.MethodGet:
		s.getUser(w, r, id)
	case http.MethodPut:
		s.updateUser(w, r, id)
	case http.MethodDelete:
		s.deleteUser(w, r, id)
	default:
		s.jsonError(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *Server) getUser(w http.ResponseWriter, r *http.Request, id string) {
	user, err := s.store.GetUser(r.Context(), id)
	if err != nil {
		s.jsonError(w, "user not found", http.StatusNotFound)
		return
	}

	s.jsonResponse(w, map[string]interface{}{
		"id":            user.ID,
		"username":      user.Username,
		"groups":        user.Groups,
		"allowed_hosts": user.AllowedHosts,
		"source":        user.Source,
		"otp_enabled":   user.OTPEnabled,
		"created_at":    user.CreatedAt,
	})
}

func (s *Server) updateUser(w http.ResponseWriter, r *http.Request, id string) {
	if !s.hasPermission(r, "user:update") {
		s.jsonError(w, "forbidden", http.StatusForbidden)
		return
	}

	var req struct {
		Username     string   `json:"username"`
		Groups       []string `json:"groups"`
		AllowedHosts []string `json:"allowed_hosts"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.jsonError(w, "invalid request body", http.StatusBadRequest)
		return
	}

	existing, err := s.store.GetUser(r.Context(), id)
	if err != nil {
		s.jsonError(w, "user not found", http.StatusNotFound)
		return
	}

	if req.Username != "" {
		existing.Username = req.Username
	}
	if req.Groups != nil {
		existing.Groups = req.Groups
	}
	if req.AllowedHosts != nil {
		existing.AllowedHosts = req.AllowedHosts
	}

	if err := s.store.UpdateUser(r.Context(), existing); err != nil {
		s.jsonError(w, "failed to update user", http.StatusInternalServerError)
		return
	}

	s.jsonResponse(w, existing)
}

func (s *Server) deleteUser(w http.ResponseWriter, r *http.Request, id string) {
	if !s.hasPermission(r, "user:delete") {
		s.jsonError(w, "forbidden", http.StatusForbidden)
		return
	}

	// Get username for audit log.
	user, _ := s.store.GetUser(r.Context(), id)
	username := id
	if user != nil {
		username = user.Username
	}

	if err := s.store.DeleteUser(r.Context(), id); err != nil {
		s.jsonError(w, "failed to delete user", http.StatusInternalServerError)
		return
	}

	sourceIP := r.RemoteAddr
	if fwdIP := r.Header.Get("X-Forwarded-For"); fwdIP != "" {
		sourceIP = fwdIP
	}
	s.logAudit("user_delete", username, sourceIP, "", "delete user", "success", nil)

	s.jsonResponse(w, map[string]string{"status": "deleted"})
}
