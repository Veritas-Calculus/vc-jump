// Package dashboard provides a web-based management interface for vc-jump.
package dashboard

import (
	"context"
	"embed"
	"encoding/json"
	"fmt"
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/Veritas-Calculus/vc-jump/internal/auth"
	"github.com/Veritas-Calculus/vc-jump/internal/config"
	"github.com/Veritas-Calculus/vc-jump/internal/sshkey"
	"github.com/Veritas-Calculus/vc-jump/internal/storage"
	"github.com/gorilla/websocket"
)

//go:embed static/* static/vendor/*
var staticFiles embed.FS

// Server represents the dashboard HTTP server.
type Server struct {
	cfg          DashboardConfig
	store        *storage.SQLiteStore
	auth         *auth.Authenticator
	session      *auth.SessionManager
	keyManager   *sshkey.Manager
	recordingCfg config.RecordingConfig
	recorder     RecorderInterface
	mux          *http.ServeMux
	server       *http.Server
}

// RecorderInterface defines the interface for session recording.
type RecorderInterface interface {
	ListActiveSessions() []ActiveSessionInfo
	GetSession(id string) (SessionInterface, bool)
}

// SessionInterface defines the interface for an active session.
type SessionInterface interface {
	AddWatcher(ch chan []byte)
	RemoveWatcher(ch chan []byte)
}

// ActiveSessionInfo mirrors recording.ActiveSessionInfo.
type ActiveSessionInfo struct {
	ID        string    `json:"id"`
	Username  string    `json:"username"`
	HostName  string    `json:"hostname"`
	StartTime time.Time `json:"start_time"`
}

// DashboardConfig holds dashboard configuration.
type DashboardConfig struct {
	ListenAddr     string
	SessionTimeout time.Duration
	EnableHTTPS    bool
	CertFile       string
	KeyFile        string
}

// New creates a new dashboard server.
func New(cfg DashboardConfig, store *storage.SQLiteStore, authCfg config.AuthConfig) (*Server, error) {
	return NewWithRecording(cfg, store, authCfg, config.RecordingConfig{})
}

// NewWithRecording creates a new dashboard server with recording support.
func NewWithRecording(cfg DashboardConfig, store *storage.SQLiteStore, authCfg config.AuthConfig, recordingCfg config.RecordingConfig) (*Server, error) {
	return NewWithRecorder(cfg, store, authCfg, recordingCfg, nil)
}

// NewWithRecorder creates a new dashboard server with a recorder for live session viewing.
func NewWithRecorder(cfg DashboardConfig, store *storage.SQLiteStore, authCfg config.AuthConfig, recordingCfg config.RecordingConfig, recorder RecorderInterface) (*Server, error) {
	authenticator, err := auth.NewWithStore(authCfg, store)
	if err != nil {
		return nil, fmt.Errorf("failed to create authenticator: %w", err)
	}

	s := &Server{
		cfg:          cfg,
		store:        store,
		auth:         authenticator,
		session:      auth.NewSessionManager(store, cfg.SessionTimeout),
		keyManager:   sshkey.New(store),
		recordingCfg: recordingCfg,
		recorder:     recorder,
		mux:          http.NewServeMux(),
	}

	s.setupRoutes()

	s.server = &http.Server{
		Addr:         cfg.ListenAddr,
		Handler:      s.securityHeaders(s.mux),
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	return s, nil
}

func (s *Server) setupRoutes() {
	// API routes.
	s.mux.HandleFunc("/api/login", s.handleLogin)
	s.mux.HandleFunc("/api/logout", s.requireAuth(s.handleLogout))
	s.mux.HandleFunc("/api/me", s.requireAuth(s.handleMe))

	// Folder management.
	s.mux.HandleFunc("/api/folders", s.requireAuth(s.handleFolders))
	s.mux.HandleFunc("/api/folders/", s.requireAuth(s.handleFolder))

	// Host management.
	s.mux.HandleFunc("/api/hosts", s.requireAuth(s.handleHosts))
	s.mux.HandleFunc("/api/hosts/", s.requireAuth(s.handleHost))

	// User management.
	s.mux.HandleFunc("/api/users", s.requireAuth(s.handleUsers))
	s.mux.HandleFunc("/api/users/", s.requireAuth(s.handleUser))

	// SSH key management.
	s.mux.HandleFunc("/api/keys", s.requireAuth(s.handleKeys))
	s.mux.HandleFunc("/api/keys/", s.requireAuth(s.handleKey))

	// Session management.
	s.mux.HandleFunc("/api/sessions", s.requireAuth(s.handleSessions))
	s.mux.HandleFunc("/api/sessions/active", s.requireAuth(s.handleActiveSessions))
	s.mux.HandleFunc("/api/sessions/live", s.requireAuth(s.handleLiveSessions))
	s.mux.HandleFunc("/api/sessions/watch/", s.requireAuth(s.handleWatchSession))

	// Recording management.
	s.mux.HandleFunc("/api/recordings", s.requireAuth(s.handleRecordings))
	s.mux.HandleFunc("/api/recordings/", s.requireAuth(s.handleRecording))

	// IAM - Role management.
	s.mux.HandleFunc("/api/iam/roles", s.requireAuth(s.handleRoles))
	s.mux.HandleFunc("/api/iam/roles/", s.requireAuth(s.handleRole))

	// IAM - User role assignments.
	s.mux.HandleFunc("/api/iam/user-roles/", s.requireAuth(s.handleUserRoles))

	// IAM - Host permissions.
	s.mux.HandleFunc("/api/iam/host-permissions", s.requireAuth(s.handleHostPermissions))
	s.mux.HandleFunc("/api/iam/host-permissions/", s.requireAuth(s.handleHostPermission))

	// IAM - Permissions list.
	s.mux.HandleFunc("/api/iam/permissions", s.requireAuth(s.handlePermissionsList))

	// OTP management.
	s.mux.HandleFunc("/api/otp/status", s.requireAuth(s.handleOTPStatus))
	s.mux.HandleFunc("/api/otp/setup", s.requireAuth(s.handleOTPSetup))
	s.mux.HandleFunc("/api/otp/verify", s.requireAuth(s.handleOTPVerify))
	s.mux.HandleFunc("/api/otp", s.requireAuth(s.handleOTPDisable))

	// Settings.
	s.mux.HandleFunc("/api/settings/otp", s.requireAuth(s.handleOTPSettings))

	// Dashboard stats.
	s.mux.HandleFunc("/api/stats", s.requireAuth(s.handleStats))

	// Audit logs.
	s.mux.HandleFunc("/api/audit", s.requireAuth(s.handleAuditLogs))
	s.mux.HandleFunc("/api/audit/stats", s.requireAuth(s.handleAuditStats))

	// SEO/crawler control.
	s.mux.HandleFunc("/robots.txt", s.handleRobotsTxt)
	s.mux.HandleFunc("/sitemap.xml", s.handleSitemapXml)

	// Static files.
	staticFS, _ := fs.Sub(staticFiles, "static")
	fileServer := http.FileServer(http.FS(staticFS))
	s.mux.Handle("/static/", http.StripPrefix("/static/", fileServer))
	s.mux.Handle("/", fileServer)
}

// Start begins serving HTTP requests.
func (s *Server) Start() error {
	if s.cfg.EnableHTTPS {
		return s.server.ListenAndServeTLS(s.cfg.CertFile, s.cfg.KeyFile)
	}
	return s.server.ListenAndServe()
}

// Stop gracefully shuts down the server.
func (s *Server) Stop(ctx context.Context) error {
	return s.server.Shutdown(ctx)
}

// Middleware.

// securityHeaders adds security headers to all responses.
func (s *Server) securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Anti-clickjacking
		w.Header().Set("X-Frame-Options", "DENY")

		// Prevent MIME type sniffing
		w.Header().Set("X-Content-Type-Options", "nosniff")

		// XSS Protection (legacy, but still useful)
		w.Header().Set("X-XSS-Protection", "1; mode=block")

		// Content Security Policy
		w.Header().Set("Content-Security-Policy", "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self' ws: wss:; font-src 'self'")

		// Referrer Policy
		w.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")

		// Permissions Policy (formerly Feature-Policy)
		w.Header().Set("Permissions-Policy", "accelerometer=(), camera=(), geolocation=(), gyroscope=(), magnetometer=(), microphone=(), payment=(), usb=()")

		// Spectre/Meltdown mitigations
		w.Header().Set("Cross-Origin-Opener-Policy", "same-origin")
		w.Header().Set("Cross-Origin-Embedder-Policy", "require-corp")
		w.Header().Set("Cross-Origin-Resource-Policy", "same-origin")

		// Cache control for sensitive pages
		if strings.HasPrefix(r.URL.Path, "/api/") {
			w.Header().Set("Cache-Control", "no-store, no-cache, must-revalidate, private")
			w.Header().Set("Pragma", "no-cache")
		}

		next.ServeHTTP(w, r)
	})
}

func (s *Server) requireAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		token := extractToken(r)
		if token == "" {
			s.jsonError(w, "unauthorized", http.StatusUnauthorized)
			return
		}

		userID, err := s.session.ValidateSession(r.Context(), token)
		if err != nil {
			s.jsonError(w, "unauthorized", http.StatusUnauthorized)
			return
		}

		// Add user ID to context.
		ctx := context.WithValue(r.Context(), contextKeyUserID, userID)
		next(w, r.WithContext(ctx))
	}
}

type contextKey string

const contextKeyUserID contextKey = "userID"

func extractToken(r *http.Request) string {
	// Check Authorization header.
	authHeader := r.Header.Get("Authorization")
	if strings.HasPrefix(authHeader, "Bearer ") {
		return strings.TrimPrefix(authHeader, "Bearer ")
	}

	// Check cookie.
	cookie, err := r.Cookie("session")
	if err == nil {
		return cookie.Value
	}

	return ""
}

// Handlers.

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		s.jsonError(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.jsonError(w, "invalid request body", http.StatusBadRequest)
		return
	}

	sourceIP := r.RemoteAddr
	if fwdIP := r.Header.Get("X-Forwarded-For"); fwdIP != "" {
		sourceIP = fwdIP
	}

	user, err := s.auth.AuthenticatePassword(r.Context(), req.Username, req.Password)
	if err != nil {
		s.logAudit("dashboard_login", req.Username, sourceIP, "", "dashboard login failed", "failure", nil)
		s.jsonError(w, "invalid credentials", http.StatusUnauthorized)
		return
	}

	token, err := s.session.CreateSession(r.Context(), user.ID)
	if err != nil {
		s.jsonError(w, "failed to create session", http.StatusInternalServerError)
		return
	}

	// Log successful login.
	s.logAudit("dashboard_login", req.Username, sourceIP, "", "dashboard login", "success", nil)

	// Set session cookie.
	http.SetCookie(w, &http.Cookie{
		Name:     "session",
		Value:    token,
		Path:     "/",
		HttpOnly: true,
		Secure:   s.cfg.EnableHTTPS,
		SameSite: http.SameSiteStrictMode,
		MaxAge:   int(s.cfg.SessionTimeout.Seconds()),
	})

	s.jsonResponse(w, map[string]interface{}{
		"token": token,
		"user": map[string]interface{}{
			"id":       user.ID,
			"username": user.Username,
			"groups":   user.Groups,
		},
	})
}

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		s.jsonError(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	token := extractToken(r)
	if token != "" {
		_ = s.session.InvalidateSession(r.Context(), token)
	}

	// Clear session cookie.
	http.SetCookie(w, &http.Cookie{
		Name:     "session",
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteStrictMode,
		MaxAge:   -1,
	})

	s.jsonResponse(w, map[string]string{"status": "ok"})
}

func (s *Server) handleMe(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		s.jsonError(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	userID := r.Context().Value(contextKeyUserID).(string)
	user, err := s.store.GetUser(r.Context(), userID)
	if err != nil {
		s.jsonError(w, "user not found", http.StatusNotFound)
		return
	}

	// Get user's roles and permissions.
	roles, err := s.store.GetUserRoles(r.Context(), userID)
	if err != nil {
		roles = nil
	}

	// Collect all permissions from all roles.
	permSet := make(map[string]bool)
	var roleNames []string
	for _, role := range roles {
		roleNames = append(roleNames, role.Name)
		for _, perm := range role.Permissions {
			permSet[perm] = true
		}
	}
	var permissions []string
	for perm := range permSet {
		permissions = append(permissions, perm)
	}

	s.jsonResponse(w, map[string]interface{}{
		"id":          user.ID,
		"username":    user.Username,
		"groups":      user.Groups,
		"roles":       roleNames,
		"permissions": permissions,
	})
}

func (s *Server) handleHosts(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		hosts, err := s.store.ListHosts(r.Context())
		if err != nil {
			s.jsonError(w, "failed to list hosts", http.StatusInternalServerError)
			return
		}
		s.jsonResponse(w, hosts)

	case http.MethodPost:
		var host storage.Host
		if err := json.NewDecoder(r.Body).Decode(&host); err != nil {
			s.jsonError(w, "invalid request body", http.StatusBadRequest)
			return
		}
		if err := s.store.CreateHost(r.Context(), &host); err != nil {
			s.jsonError(w, "failed to create host", http.StatusInternalServerError)
			return
		}
		s.jsonResponse(w, host)

	default:
		s.jsonError(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *Server) handleHost(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimPrefix(r.URL.Path, "/api/hosts/")
	if id == "" {
		s.jsonError(w, "host id required", http.StatusBadRequest)
		return
	}

	switch r.Method {
	case http.MethodGet:
		host, err := s.store.GetHost(r.Context(), id)
		if err != nil {
			s.jsonError(w, "host not found", http.StatusNotFound)
			return
		}
		s.jsonResponse(w, host)

	case http.MethodPut:
		var host storage.Host
		if err := json.NewDecoder(r.Body).Decode(&host); err != nil {
			s.jsonError(w, "invalid request body", http.StatusBadRequest)
			return
		}
		host.ID = id
		if err := s.store.UpdateHost(r.Context(), &host); err != nil {
			s.jsonError(w, "failed to update host", http.StatusInternalServerError)
			return
		}
		s.jsonResponse(w, host)

	case http.MethodDelete:
		if err := s.store.DeleteHost(r.Context(), id); err != nil {
			s.jsonError(w, "failed to delete host", http.StatusInternalServerError)
			return
		}
		s.jsonResponse(w, map[string]string{"status": "deleted"})

	default:
		s.jsonError(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *Server) handleUsers(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		// List users requires user:view permission.
		if !s.hasPermission(r, "user:view") {
			s.jsonError(w, "permission denied", http.StatusForbidden)
			return
		}
		users, err := s.store.ListUsers(r.Context())
		if err != nil {
			s.jsonError(w, "failed to list users", http.StatusInternalServerError)
			return
		}
		// Enrich users with their roles
		var usersWithRoles []map[string]interface{}
		for _, u := range users {
			roles, _ := s.store.GetUserRoles(r.Context(), u.ID)
			var roleNames []string
			for _, role := range roles {
				roleNames = append(roleNames, role.Name)
			}
			usersWithRoles = append(usersWithRoles, map[string]interface{}{
				"id":            u.ID,
				"username":      u.Username,
				"groups":        u.Groups,
				"allowed_hosts": u.AllowedHosts,
				"source":        u.Source,
				"is_active":     u.IsActive,
				"last_login_at": u.LastLoginAt,
				"created_at":    u.CreatedAt,
				"roles":         roleNames,
			})
		}
		s.jsonResponse(w, usersWithRoles)

	case http.MethodPost:
		// Create user requires user:create permission.
		if !s.hasPermission(r, "user:create") {
			s.jsonError(w, "permission denied", http.StatusForbidden)
			return
		}
		var req struct {
			Username     string   `json:"username"`
			Password     string   `json:"password"`
			Groups       []string `json:"groups"`
			AllowedHosts []string `json:"allowed_hosts"`
			RoleID       string   `json:"role_id"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			s.jsonError(w, "invalid request body", http.StatusBadRequest)
			return
		}

		passwordHash, err := auth.HashPassword(req.Password)
		if err != nil {
			s.jsonError(w, "failed to hash password", http.StatusInternalServerError)
			return
		}

		user := &storage.UserWithPassword{
			User: storage.User{
				Username:     req.Username,
				Groups:       req.Groups,
				AllowedHosts: req.AllowedHosts,
			},
			PasswordHash: passwordHash,
			IsActive:     true,
		}

		if err := s.store.CreateUserWithPassword(r.Context(), user); err != nil {
			s.jsonError(w, "failed to create user", http.StatusInternalServerError)
			return
		}

		// Assign role to user. Default to "user" role if not specified.
		roleID := req.RoleID
		if roleID == "" {
			// Get default "user" role.
			userRole, err := s.store.GetRoleByName(r.Context(), "user")
			if err == nil {
				roleID = userRole.ID
			}
		}
		if roleID != "" {
			_ = s.store.AssignRole(r.Context(), user.ID, roleID)
		}

		s.jsonResponse(w, user.User)

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
	if !s.hasPermission(r, "user:view") {
		s.jsonError(w, "permission denied", http.StatusForbidden)
		return
	}
	user, err := s.store.GetUser(r.Context(), id)
	if err != nil {
		s.jsonError(w, "user not found", http.StatusNotFound)
		return
	}
	s.jsonResponse(w, user)
}

func (s *Server) updateUser(w http.ResponseWriter, r *http.Request, id string) {
	if !s.hasPermission(r, "user:update") {
		s.jsonError(w, "permission denied", http.StatusForbidden)
		return
	}
	existingUser, err := s.store.GetUser(r.Context(), id)
	if err != nil {
		s.jsonError(w, "user not found", http.StatusNotFound)
		return
	}
	var req struct {
		Groups       []string `json:"groups"`
		AllowedHosts []string `json:"allowed_hosts"`
		IsActive     *bool    `json:"is_active"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.jsonError(w, "invalid request body", http.StatusBadRequest)
		return
	}
	existingUser.Groups = req.Groups
	existingUser.AllowedHosts = req.AllowedHosts
	if req.IsActive != nil {
		existingUser.IsActive = *req.IsActive
	}
	if err := s.store.UpdateUser(r.Context(), existingUser); err != nil {
		s.jsonError(w, "failed to update user", http.StatusInternalServerError)
		return
	}
	s.jsonResponse(w, existingUser)
}

func (s *Server) deleteUser(w http.ResponseWriter, r *http.Request, id string) {
	if !s.hasPermission(r, "user:delete") {
		s.jsonError(w, "permission denied", http.StatusForbidden)
		return
	}
	user, err := s.store.GetUser(r.Context(), id)
	if err != nil {
		s.jsonError(w, "user not found", http.StatusNotFound)
		return
	}
	if user.Username == "admin" {
		s.jsonError(w, "cannot delete admin user", http.StatusForbidden)
		return
	}
	if err := s.store.DeleteUser(r.Context(), id); err != nil {
		s.jsonError(w, "failed to delete user", http.StatusInternalServerError)
		return
	}
	s.jsonResponse(w, map[string]string{"status": "deleted"})
}

func (s *Server) handleKeys(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		keys, err := s.keyManager.ListKeys(r.Context())
		if err != nil {
			s.jsonError(w, "failed to list keys", http.StatusInternalServerError)
			return
		}
		// Return keys without private key content.
		var safeKeys []map[string]interface{}
		for _, k := range keys {
			safeKeys = append(safeKeys, map[string]interface{}{
				"id":          k.ID,
				"name":        k.Name,
				"public_key":  k.PublicKey,
				"fingerprint": k.Fingerprint,
				"key_type":    k.KeyType,
				"created_at":  k.CreatedAt,
			})
		}
		s.jsonResponse(w, safeKeys)

	case http.MethodPost:
		var req struct {
			Name    string `json:"name"`
			KeyType string `json:"key_type"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			s.jsonError(w, "invalid request body", http.StatusBadRequest)
			return
		}

		keyType := sshkey.KeyType(req.KeyType)
		if keyType == "" {
			keyType = sshkey.KeyTypeED25519
		}

		key, err := s.keyManager.GenerateKey(r.Context(), req.Name, keyType)
		if err != nil {
			s.jsonError(w, "failed to generate key", http.StatusInternalServerError)
			return
		}
		s.jsonResponse(w, map[string]interface{}{
			"id":          key.ID,
			"name":        key.Name,
			"public_key":  key.PublicKey,
			"fingerprint": key.Fingerprint,
			"key_type":    key.KeyType,
			"created_at":  key.CreatedAt,
		})

	default:
		s.jsonError(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *Server) handleKey(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimPrefix(r.URL.Path, "/api/keys/")
	if id == "" {
		s.jsonError(w, "key id required", http.StatusBadRequest)
		return
	}

	switch r.Method {
	case http.MethodGet:
		key, err := s.keyManager.GetKey(r.Context(), id)
		if err != nil {
			s.jsonError(w, "key not found", http.StatusNotFound)
			return
		}
		s.jsonResponse(w, map[string]interface{}{
			"id":          key.ID,
			"name":        key.Name,
			"public_key":  key.PublicKey,
			"fingerprint": key.Fingerprint,
			"key_type":    key.KeyType,
			"created_at":  key.CreatedAt,
		})

	case http.MethodDelete:
		if err := s.keyManager.DeleteKey(r.Context(), id); err != nil {
			s.jsonError(w, "failed to delete key", http.StatusInternalServerError)
			return
		}
		s.jsonResponse(w, map[string]string{"status": "deleted"})

	default:
		s.jsonError(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *Server) handleSessions(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		s.jsonError(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Session history requires session:view permission.
	if !s.hasPermission(r, "session:view") {
		s.jsonError(w, "forbidden", http.StatusForbidden)
		return
	}

	limit := 100
	sessions, err := s.store.ListSessions(r.Context(), "", limit)
	if err != nil {
		s.jsonError(w, "failed to list sessions", http.StatusInternalServerError)
		return
	}
	s.jsonResponse(w, sessions)
}

func (s *Server) handleStats(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		s.jsonError(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	hosts, _ := s.store.ListHosts(r.Context())
	users, _ := s.store.ListUsers(r.Context())
	sessions, _ := s.store.ListSessions(r.Context(), "", 0)
	keys, _ := s.keyManager.ListKeys(r.Context())

	// Count active sessions.
	var activeSessions int
	for _, sess := range sessions {
		if sess.EndTime.IsZero() {
			activeSessions++
		}
	}

	s.jsonResponse(w, map[string]interface{}{
		"hosts":           len(hosts),
		"users":           len(users),
		"total_sessions":  len(sessions),
		"active_sessions": activeSessions,
		"ssh_keys":        len(keys),
	})
}

func (s *Server) handleActiveSessions(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		s.jsonError(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Active sessions list requires session:view permission.
	if !s.hasPermission(r, "session:view") {
		s.jsonError(w, "forbidden", http.StatusForbidden)
		return
	}

	// Get active sessions directly using the optimized method.
	activeSessions, err := s.store.ListActiveSessions(r.Context())
	if err != nil {
		s.jsonError(w, "failed to list active sessions", http.StatusInternalServerError)
		return
	}

	if activeSessions == nil {
		activeSessions = []storage.Session{}
	}

	s.jsonResponse(w, activeSessions)
}

// handleLiveSessions returns list of live recording sessions that can be watched.
// Users with session:view permission can see all sessions.
// Users without session:view permission can only see their own sessions.
func (s *Server) handleLiveSessions(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		s.jsonError(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if s.recorder == nil {
		s.jsonResponse(w, []ActiveSessionInfo{})
		return
	}

	sessions := s.recorder.ListActiveSessions()
	if sessions == nil {
		sessions = []ActiveSessionInfo{}
	}

	// If user has session:view permission, return all sessions.
	if s.hasPermission(r, "session:view") {
		s.jsonResponse(w, sessions)
		return
	}

	// Otherwise, filter to only show user's own sessions.
	userID := r.Context().Value(contextKeyUserID).(string)
	user, err := s.store.GetUser(r.Context(), userID)
	if err != nil {
		s.jsonResponse(w, []ActiveSessionInfo{})
		return
	}

	var userSessions []ActiveSessionInfo
	for _, sess := range sessions {
		if sess.Username == user.Username {
			userSessions = append(userSessions, sess)
		}
	}
	if userSessions == nil {
		userSessions = []ActiveSessionInfo{}
	}
	s.jsonResponse(w, userSessions)
}

var wsUpgrader = websocket.Upgrader{
	ReadBufferSize:  1024,
	WriteBufferSize: 1024,
	CheckOrigin: func(r *http.Request) bool {
		return true // Allow all origins for internal use.
	},
}

// handleWatchSession handles WebSocket connections for watching live sessions.
func (s *Server) handleWatchSession(w http.ResponseWriter, r *http.Request) {
	sessionID := strings.TrimPrefix(r.URL.Path, "/api/sessions/watch/")
	if sessionID == "" {
		s.jsonError(w, "session id required", http.StatusBadRequest)
		return
	}

	// For WebSocket, check token from query param as well (since headers don't work with WS).
	tokenStr := r.URL.Query().Get("token")
	if tokenStr != "" {
		// Validate token from query param.
		_, err := s.session.ValidateSession(r.Context(), tokenStr)
		if err != nil {
			s.jsonError(w, "unauthorized", http.StatusUnauthorized)
			return
		}
	}

	if s.recorder == nil {
		s.jsonError(w, "recording not enabled", http.StatusServiceUnavailable)
		return
	}

	session, ok := s.recorder.GetSession(sessionID)
	if !ok {
		s.jsonError(w, "session not found", http.StatusNotFound)
		return
	}

	// Upgrade to WebSocket.
	conn, err := wsUpgrader.Upgrade(w, r, nil)
	if err != nil {
		return
	}
	defer func() { _ = conn.Close() }()

	// Create a channel to receive session output.
	outputChan := make(chan []byte, 100)
	session.AddWatcher(outputChan)
	defer session.RemoveWatcher(outputChan)

	// Send data from session to WebSocket client.
	for data := range outputChan {
		if err := conn.WriteMessage(websocket.BinaryMessage, data); err != nil {
			return
		}
	}
}

func (s *Server) handleRecordings(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		s.handleRecordingsList(w, r)
	case http.MethodDelete:
		s.handleRecordingsBatchDelete(w, r)
	default:
		s.jsonError(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *Server) handleRecordingsList(w http.ResponseWriter, _ *http.Request) {
	if !s.recordingCfg.Enabled || s.recordingCfg.LocalPath == "" {
		s.jsonError(w, "recording not enabled", http.StatusNotFound)
		return
	}

	// List recording files.
	entries, err := os.ReadDir(s.recordingCfg.LocalPath)
	if err != nil {
		s.jsonError(w, "failed to list recordings", http.StatusInternalServerError)
		return
	}

	var recordings []map[string]interface{}
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		info, err := entry.Info()
		if err != nil {
			continue
		}
		recordings = append(recordings, map[string]interface{}{
			"name":     entry.Name(),
			"size":     info.Size(),
			"mod_time": info.ModTime(),
		})
	}

	s.jsonResponse(w, recordings)
}

// BatchDeleteRequest represents the request body for batch delete.
type BatchDeleteRequest struct {
	Filenames []string `json:"filenames"`
}

// BatchDeleteResponse represents the response for batch delete.
type BatchDeleteResponse struct {
	Deleted []string          `json:"deleted"`
	Failed  map[string]string `json:"failed,omitempty"`
}

func (s *Server) handleRecordingsBatchDelete(w http.ResponseWriter, r *http.Request) {
	if !s.recordingCfg.Enabled || s.recordingCfg.LocalPath == "" {
		s.jsonError(w, "recording not enabled", http.StatusNotFound)
		return
	}

	var req BatchDeleteRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.jsonError(w, "invalid request body", http.StatusBadRequest)
		return
	}

	if len(req.Filenames) == 0 {
		s.jsonError(w, "no filenames provided", http.StatusBadRequest)
		return
	}

	// Limit batch size to prevent abuse.
	const maxBatchSize = 100
	if len(req.Filenames) > maxBatchSize {
		s.jsonError(w, fmt.Sprintf("batch size exceeds limit of %d", maxBatchSize), http.StatusBadRequest)
		return
	}

	resp := BatchDeleteResponse{
		Deleted: make([]string, 0),
		Failed:  make(map[string]string),
	}

	for _, filename := range req.Filenames {
		// Security: prevent directory traversal.
		if filename == "" || strings.Contains(filename, "..") || strings.Contains(filename, "/") || strings.Contains(filename, "\\") {
			resp.Failed[filename] = "invalid filename"
			continue
		}

		filePath := filepath.Join(s.recordingCfg.LocalPath, filename)

		// Additional validation: ensure the path is within the expected directory.
		if !isPathWithinBase(s.recordingCfg.LocalPath, filePath) {
			resp.Failed[filename] = "invalid filename"
			continue
		}

		if err := os.Remove(filePath); err != nil {
			if os.IsNotExist(err) {
				resp.Failed[filename] = "file not found"
			} else {
				resp.Failed[filename] = "delete failed"
			}
			continue
		}

		resp.Deleted = append(resp.Deleted, filename)
	}

	s.jsonResponse(w, resp)
}

func (s *Server) handleRecording(w http.ResponseWriter, r *http.Request) {
	filename := strings.TrimPrefix(r.URL.Path, "/api/recordings/")
	if filename == "" {
		s.jsonError(w, "filename required", http.StatusBadRequest)
		return
	}

	// Security: prevent directory traversal.
	if strings.Contains(filename, "..") || strings.Contains(filename, "/") || strings.Contains(filename, "\\") {
		s.jsonError(w, "invalid filename", http.StatusBadRequest)
		return
	}

	if !s.recordingCfg.Enabled || s.recordingCfg.LocalPath == "" {
		s.jsonError(w, "recording not enabled", http.StatusNotFound)
		return
	}

	filePath := filepath.Join(s.recordingCfg.LocalPath, filename)

	// Additional validation: ensure the path is within the expected directory.
	if !isPathWithinBase(s.recordingCfg.LocalPath, filePath) {
		s.jsonError(w, "invalid filename", http.StatusBadRequest)
		return
	}

	switch r.Method {
	case http.MethodGet:
		// Return recording content.
		data, err := os.ReadFile(filePath) // #nosec G304 -- path validated by isPathWithinBase
		if err != nil {
			s.jsonError(w, "recording not found", http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(data)

	case http.MethodDelete:
		if err := os.Remove(filePath); err != nil {
			s.jsonError(w, "failed to delete recording", http.StatusInternalServerError)
			return
		}
		s.jsonResponse(w, map[string]string{"status": "deleted"})

	default:
		s.jsonError(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

// Helper functions.

func (s *Server) jsonResponse(w http.ResponseWriter, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(data)
}

func (s *Server) jsonError(w http.ResponseWriter, message string, code int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": message})
}

// isPathWithinBase validates that the given path is within the base directory.
// This prevents directory traversal attacks.
func isPathWithinBase(basePath, targetPath string) bool {
	// Clean both paths.
	absBase, err := filepath.Abs(basePath)
	if err != nil {
		return false
	}
	absTarget, err := filepath.Abs(targetPath)
	if err != nil {
		return false
	}

	// Ensure the target path starts with the base path.
	relPath, err := filepath.Rel(absBase, absTarget)
	if err != nil {
		return false
	}

	// If the relative path starts with "..", it's outside the base directory.
	return !startsWithDotDot(relPath)
}

// startsWithDotDot checks if a path starts with "..".
func startsWithDotDot(path string) bool {
	if len(path) < 2 {
		return false
	}
	return path[0] == '.' && path[1] == '.' && (len(path) == 2 || path[2] == filepath.Separator)
}

// logAudit logs an audit event to SQLite storage.
func (s *Server) logAudit(eventType, username, sourceIP, targetHost, action, result string, details map[string]interface{}) {
	if s.store == nil {
		return
	}

	log := &storage.AuditLog{
		Timestamp:  time.Now(),
		EventType:  eventType,
		Username:   username,
		SourceIP:   sourceIP,
		TargetHost: targetHost,
		Action:     action,
		Result:     result,
		Details:    details,
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	_ = s.store.CreateAuditLog(ctx, log)
}

// handleRobotsTxt serves robots.txt to control crawler access.
func (s *Server) handleRobotsTxt(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	// Disallow all crawlers - this is an internal admin dashboard
	robotsTxt := `User-agent: *
Disallow: /
`
	w.Write([]byte(robotsTxt))
}

// handleSitemapXml returns an empty sitemap - internal dashboard doesn't need indexing.
func (s *Server) handleSitemapXml(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/xml; charset=utf-8")
	sitemap := `<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
</urlset>
`
	w.Write([]byte(sitemap))
}
