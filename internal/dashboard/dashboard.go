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
	mux          *http.ServeMux
	server       *http.Server
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
		mux:          http.NewServeMux(),
	}

	s.setupRoutes()

	s.server = &http.Server{
		Addr:         cfg.ListenAddr,
		Handler:      s.mux,
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

	// Recording management.
	s.mux.HandleFunc("/api/recordings", s.requireAuth(s.handleRecordings))
	s.mux.HandleFunc("/api/recordings/", s.requireAuth(s.handleRecording))

	// Dashboard stats.
	s.mux.HandleFunc("/api/stats", s.requireAuth(s.handleStats))

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

	user, err := s.auth.AuthenticatePassword(r.Context(), req.Username, req.Password)
	if err != nil {
		s.jsonError(w, "invalid credentials", http.StatusUnauthorized)
		return
	}

	token, err := s.session.CreateSession(r.Context(), user.ID)
	if err != nil {
		s.jsonError(w, "failed to create session", http.StatusInternalServerError)
		return
	}

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

	s.jsonResponse(w, map[string]interface{}{
		"id":       user.ID,
		"username": user.Username,
		"groups":   user.Groups,
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
		users, err := s.store.ListUsers(r.Context())
		if err != nil {
			s.jsonError(w, "failed to list users", http.StatusInternalServerError)
			return
		}
		s.jsonResponse(w, users)

	case http.MethodPost:
		var req struct {
			Username string   `json:"username"`
			Password string   `json:"password"`
			Groups   []string `json:"groups"`
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
				Username: req.Username,
				Groups:   req.Groups,
			},
			PasswordHash: passwordHash,
			IsActive:     true,
		}

		if err := s.store.CreateUserWithPassword(r.Context(), user); err != nil {
			s.jsonError(w, "failed to create user", http.StatusInternalServerError)
			return
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
		user, err := s.store.GetUser(r.Context(), id)
		if err != nil {
			s.jsonError(w, "user not found", http.StatusNotFound)
			return
		}
		s.jsonResponse(w, user)

	case http.MethodPut:
		var user storage.User
		if err := json.NewDecoder(r.Body).Decode(&user); err != nil {
			s.jsonError(w, "invalid request body", http.StatusBadRequest)
			return
		}
		user.ID = id
		if err := s.store.UpdateUser(r.Context(), &user); err != nil {
			s.jsonError(w, "failed to update user", http.StatusInternalServerError)
			return
		}
		s.jsonResponse(w, user)

	case http.MethodDelete:
		// Prevent deleting admin user.
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

	default:
		s.jsonError(w, "method not allowed", http.StatusMethodNotAllowed)
	}
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

func (s *Server) handleRecordings(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		s.jsonError(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

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

func (s *Server) handleRecording(w http.ResponseWriter, r *http.Request) {
	filename := strings.TrimPrefix(r.URL.Path, "/api/recordings/")
	if filename == "" {
		s.jsonError(w, "filename required", http.StatusBadRequest)
		return
	}

	// Security: prevent directory traversal.
	if strings.Contains(filename, "..") || strings.Contains(filename, "/") {
		s.jsonError(w, "invalid filename", http.StatusBadRequest)
		return
	}

	if !s.recordingCfg.Enabled || s.recordingCfg.LocalPath == "" {
		s.jsonError(w, "recording not enabled", http.StatusNotFound)
		return
	}

	filePath := filepath.Join(s.recordingCfg.LocalPath, filename)

	switch r.Method {
	case http.MethodGet:
		// Return recording content.
		data, err := os.ReadFile(filePath) //nolint:gosec // filePath constructed from validated filename
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
