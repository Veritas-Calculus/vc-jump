// Package dashboard provides a web-based management interface for vc-jump.
package dashboard

import (
	"context"
	"embed"
	"encoding/json"
	"fmt"
	"io/fs"
	"net/http"
	"strings"
	"time"

	"github.com/Veritas-Calculus/vc-jump/internal/auth"
	"github.com/Veritas-Calculus/vc-jump/internal/config"
	"github.com/Veritas-Calculus/vc-jump/internal/logger"
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
	recorder     RecorderInterface
	logger       *logger.Logger
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

	l, err := logger.New(config.LoggingConfig{Level: "info", Format: "text", Output: "stdout"})
	if err != nil {
		return nil, fmt.Errorf("failed to create logger: %w", err)
	}

	s := &Server{
		cfg:          cfg,
		store:        store,
		auth:         authenticator,
		session:      auth.NewSessionManager(store, cfg.SessionTimeout),
		keyManager:   sshkey.New(store),
		recordingCfg: recordingCfg,
		recorder:     recorder,
		logger:       l,
		mux:          http.NewServeMux(),
	}

	s.setupRoutes()

	s.server = &http.Server{
		Addr:         cfg.ListenAddr,
		Handler:      s.requestLogger(s.securityHeaders(s.mux)),
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	return s, nil
}

func (s *Server) setupRoutes() {
	// Health check (no auth required).
	s.mux.HandleFunc("/healthz", s.handleHealthz)
	s.mux.HandleFunc("/readyz", s.handleReadyz)

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
	s.mux.HandleFunc("/api/users/", s.requireAuth(s.handleUserSubResource)) // Handles /api/users/:id and /api/users/:id/roles, /api/users/:id/host-permissions

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
	// Normalized alias for roles.
	s.mux.HandleFunc("/api/roles", s.requireAuth(s.handleRoles))
	s.mux.HandleFunc("/api/roles/", s.requireAuth(s.handleRole))

	// IAM - User role assignments (deprecated, use /api/users/:userID/roles).
	s.mux.HandleFunc("/api/iam/user-roles/", s.requireAuth(s.deprecated(s.handleUserRoles, "/api/users/{userID}/roles")))

	// IAM - Host permissions (deprecated for per-user ops, use /api/users/:userID/host-permissions).
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

	// API Key management.
	s.mux.HandleFunc("/api/api-keys", s.requireAuth(s.handleAPIKeys))
	s.mux.HandleFunc("/api/api-keys/", s.requireAuth(s.handleAPIKey))

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

// =============================================================================
// Middleware
// =============================================================================

type responseWriter struct {
	http.ResponseWriter
	status int
}

func (rw *responseWriter) WriteHeader(status int) {
	rw.status = status
	rw.ResponseWriter.WriteHeader(status)
}

// requestLogger logs HTTP requests with latency, status, IP, and User ID.
func (s *Server) requestLogger(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		rw := &responseWriter{ResponseWriter: w, status: http.StatusOK}

		next.ServeHTTP(rw, r)

		duration := time.Since(start)

		userID := rw.Header().Get("X-User-ID")
		if userID == "" {
			userID = "-"
		}

		clientIP := r.RemoteAddr
		if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
			clientIP = strings.Split(xff, ",")[0]
		}

		s.logger.Infof("%s %s %d %s %s [%v]", r.Method, r.URL.Path, rw.status, clientIP, userID, duration)
	})
}

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

		// API Key authentication path: tokens with "vcj_" prefix.
		if strings.HasPrefix(token, apiKeyPrefix) {
			userID, scopes, err := s.validateAPIKey(r, token)
			if err != nil {
				s.jsonError(w, "invalid api key", http.StatusUnauthorized)
				return
			}
			ctx := context.WithValue(r.Context(), contextKeyUserID, userID)
			ctx = context.WithValue(ctx, contextKeyAuthType, "api_key")
			ctx = context.WithValue(ctx, contextKeyScopes, scopes)

			// Set header for logger to extract.
			w.Header().Set("X-User-ID", userID)

			next(w, r.WithContext(ctx))
			return
		}

		// Session token authentication path (existing behavior).
		userID, err := s.session.ValidateSession(r.Context(), token)
		if err != nil {
			s.jsonError(w, "unauthorized", http.StatusUnauthorized)
			return
		}

		// Add user ID to context.
		ctx := context.WithValue(r.Context(), contextKeyUserID, userID)
		ctx = context.WithValue(ctx, contextKeyAuthType, "session")

		// Set header for logger to extract.
		w.Header().Set("X-User-ID", userID)

		next(w, r.WithContext(ctx))
	}
}

type contextKey string

const (
	contextKeyUserID   contextKey = "userID"
	contextKeyAuthType contextKey = "authType"
	contextKeyScopes   contextKey = "scopes"
)

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

// =============================================================================
// Auth Handlers
// =============================================================================

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		s.jsonError(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		Username string `json:"username"`
		Password string `json:"password"` //nolint:gosec // G117: login request field
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

// =============================================================================
// SSH Key Handlers
// =============================================================================

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

// =============================================================================
// Health Check Handlers
// =============================================================================

// handleHealthz returns 200 if the server is alive.
func (s *Server) handleHealthz(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write([]byte(`{"status":"ok"}`))
}

// handleReadyz returns 200 if the server is ready (DB connection is healthy).
func (s *Server) handleReadyz(w http.ResponseWriter, r *http.Request) {
	if s.store == nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusServiceUnavailable)
		_, _ = w.Write([]byte(`{"status":"not ready","reason":"no database"}`))
		return
	}

	// Verify DB is accessible with a quick read.
	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
	defer cancel()
	_, err := s.store.ListUsers(ctx)
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusServiceUnavailable)
		_, _ = w.Write([]byte(`{"status":"not ready","reason":"database unreachable"}`))
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write([]byte(`{"status":"ready"}`))
}
