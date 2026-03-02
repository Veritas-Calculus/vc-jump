// Package dashboard provides a web-based management interface for vc-jump.
package dashboard

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/Veritas-Calculus/vc-jump/internal/auth"
	"github.com/Veritas-Calculus/vc-jump/internal/storage"
)

// API Key token prefix for identification and secret scanning.
const apiKeyPrefix = "vcj_"

// createAPIKeyRequest is the request body for creating a new API key.
type createAPIKeyRequest struct {
	Name        string   `json:"name"`
	Description string   `json:"description,omitempty"`
	Scopes      []string `json:"scopes,omitempty"`
	ExpiresIn   string   `json:"expires_in,omitempty"` // e.g. "90d", "1y", "" for never
}

// createAPIKeyResponse is returned on API key creation (only time plain token is shown).
type createAPIKeyResponse struct {
	ID          string     `json:"id"`
	Name        string     `json:"name"`
	Description string     `json:"description,omitempty"`
	Token       string     `json:"token"`        // Plain text token, shown only once.
	TokenPrefix string     `json:"token_prefix"` // First 8 chars for later identification.
	Scopes      []string   `json:"scopes"`
	ExpiresAt   *time.Time `json:"expires_at,omitempty"`
	CreatedAt   time.Time  `json:"created_at"`
}

// apiKeyInfo is returned when listing/getting API keys (no plain token).
type apiKeyInfo struct {
	ID          string     `json:"id"`
	Name        string     `json:"name"`
	Description string     `json:"description,omitempty"`
	TokenPrefix string     `json:"token_prefix"`
	Scopes      []string   `json:"scopes"`
	LastUsedAt  *time.Time `json:"last_used_at,omitempty"`
	ExpiresAt   *time.Time `json:"expires_at,omitempty"`
	IsActive    bool       `json:"is_active"`
	CreatedAt   time.Time  `json:"created_at"`
}

// handleAPIKeys handles /api/api-keys (GET, POST).
func (s *Server) handleAPIKeys(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		s.listAPIKeys(w, r)
	case http.MethodPost:
		s.createAPIKey(w, r)
	default:
		s.jsonError(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

// handleAPIKey handles /api/api-keys/:id (GET, DELETE).
func (s *Server) handleAPIKey(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimPrefix(r.URL.Path, "/api/api-keys/")
	if id == "" {
		s.jsonError(w, "api key id required", http.StatusBadRequest)
		return
	}

	// Handle rotate sub-route: /api/api-keys/:id/rotate
	if strings.Contains(id, "/") {
		parts := strings.SplitN(id, "/", 2)
		id = parts[0]
		action := parts[1]

		if action == "rotate" && r.Method == http.MethodPost {
			s.rotateAPIKey(w, r, id)
			return
		}
		s.jsonError(w, "not found", http.StatusNotFound)
		return
	}

	switch r.Method {
	case http.MethodGet:
		s.getAPIKey(w, r, id)
	case http.MethodDelete:
		s.deleteAPIKey(w, r, id)
	default:
		s.jsonError(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

// listAPIKeys returns all API keys for the current user (without plain tokens).
func (s *Server) listAPIKeys(w http.ResponseWriter, r *http.Request) {
	if !s.hasPermission(r, "settings:view") {
		s.jsonError(w, "permission denied", http.StatusForbidden)
		return
	}

	userID := r.Context().Value(contextKeyUserID).(string)
	keys, err := s.store.ListApiKeysByUser(r.Context(), userID)
	if err != nil {
		s.jsonError(w, "failed to list api keys", http.StatusInternalServerError)
		return
	}

	result := make([]apiKeyInfo, 0, len(keys))
	for _, k := range keys {
		result = append(result, toAPIKeyInfo(&k))
	}

	s.jsonResponse(w, result)
}

// createAPIKey generates a new API key.
func (s *Server) createAPIKey(w http.ResponseWriter, r *http.Request) {
	if !s.hasPermission(r, "settings:update") {
		s.jsonError(w, "permission denied", http.StatusForbidden)
		return
	}

	var req createAPIKeyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.jsonError(w, "invalid request body", http.StatusBadRequest)
		return
	}

	if req.Name == "" {
		s.jsonError(w, "name is required", http.StatusBadRequest)
		return
	}

	userID := r.Context().Value(contextKeyUserID).(string)

	// Generate the raw token.
	plainToken, err := generateAPIKeyToken()
	if err != nil {
		s.jsonError(w, "failed to generate token", http.StatusInternalServerError)
		return
	}

	// Parse expiry.
	var expiresAt *time.Time
	if req.ExpiresIn != "" {
		t, err := parseDuration(req.ExpiresIn)
		if err != nil {
			s.jsonError(w, fmt.Sprintf("invalid expires_in: %s", err), http.StatusBadRequest)
			return
		}
		exp := time.Now().Add(t)
		expiresAt = &exp
	}

	// Build the storage model.
	apiKey := &storage.ApiKey{
		UserID:      userID,
		Name:        req.Name,
		Description: req.Description,
		TokenPrefix: plainToken[:12], // "vcj_" + 8 chars
		TokenHash:   auth.HashToken(plainToken),
		Scopes:      req.Scopes,
		ExpiresAt:   expiresAt,
	}

	if err := s.store.CreateApiKey(r.Context(), apiKey); err != nil {
		s.jsonError(w, "failed to create api key", http.StatusInternalServerError)
		return
	}

	// Log audit event.
	sourceIP := r.RemoteAddr
	if fwdIP := r.Header.Get("X-Forwarded-For"); fwdIP != "" {
		sourceIP = fwdIP
	}
	user, _ := s.store.GetUser(r.Context(), userID)
	username := userID
	if user != nil {
		username = user.Username
	}
	s.logAudit("api_key_create", username, sourceIP, "", fmt.Sprintf("created api key: %s", req.Name), "success", nil)

	// Return the plain token — shown only this once.
	s.jsonResponse(w, createAPIKeyResponse{
		ID:          apiKey.ID,
		Name:        apiKey.Name,
		Description: apiKey.Description,
		Token:       plainToken,
		TokenPrefix: apiKey.TokenPrefix,
		Scopes:      apiKey.Scopes,
		ExpiresAt:   expiresAt,
		CreatedAt:   apiKey.CreatedAt,
	})
}

// getAPIKey returns a single API key's metadata.
func (s *Server) getAPIKey(w http.ResponseWriter, r *http.Request, id string) {
	if !s.hasPermission(r, "settings:view") {
		s.jsonError(w, "permission denied", http.StatusForbidden)
		return
	}

	userID := r.Context().Value(contextKeyUserID).(string)

	key, err := s.store.GetApiKey(r.Context(), id)
	if err != nil {
		s.jsonError(w, "api key not found", http.StatusNotFound)
		return
	}

	// Users can only see their own API keys.
	if key.UserID != userID {
		s.jsonError(w, "api key not found", http.StatusNotFound)
		return
	}

	s.jsonResponse(w, toAPIKeyInfo(key))
}

// deleteAPIKey permanently removes an API key.
func (s *Server) deleteAPIKey(w http.ResponseWriter, r *http.Request, id string) {
	if !s.hasPermission(r, "settings:update") {
		s.jsonError(w, "permission denied", http.StatusForbidden)
		return
	}

	userID := r.Context().Value(contextKeyUserID).(string)

	// Verify ownership.
	key, err := s.store.GetApiKey(r.Context(), id)
	if err != nil {
		s.jsonError(w, "api key not found", http.StatusNotFound)
		return
	}
	if key.UserID != userID {
		s.jsonError(w, "api key not found", http.StatusNotFound)
		return
	}

	if err := s.store.DeleteApiKey(r.Context(), id); err != nil {
		s.jsonError(w, "failed to delete api key", http.StatusInternalServerError)
		return
	}

	// Log audit event.
	sourceIP := r.RemoteAddr
	if fwdIP := r.Header.Get("X-Forwarded-For"); fwdIP != "" {
		sourceIP = fwdIP
	}
	user, _ := s.store.GetUser(r.Context(), userID)
	username := userID
	if user != nil {
		username = user.Username
	}
	s.logAudit("api_key_delete", username, sourceIP, "", fmt.Sprintf("deleted api key: %s", key.Name), "success", nil)

	s.jsonResponse(w, map[string]string{"status": "deleted"})
}

// rotateAPIKey generates a new token for an existing API key, invalidating the old one.
func (s *Server) rotateAPIKey(w http.ResponseWriter, r *http.Request, id string) {
	if !s.hasPermission(r, "settings:update") {
		s.jsonError(w, "permission denied", http.StatusForbidden)
		return
	}

	userID := r.Context().Value(contextKeyUserID).(string)

	// Verify ownership.
	key, err := s.store.GetApiKey(r.Context(), id)
	if err != nil {
		s.jsonError(w, "api key not found", http.StatusNotFound)
		return
	}
	if key.UserID != userID {
		s.jsonError(w, "api key not found", http.StatusNotFound)
		return
	}

	// Delete the old key and create a new one with the same metadata.
	if err := s.store.DeleteApiKey(r.Context(), id); err != nil {
		s.jsonError(w, "failed to rotate api key", http.StatusInternalServerError)
		return
	}

	// Generate new token.
	plainToken, err := generateAPIKeyToken()
	if err != nil {
		s.jsonError(w, "failed to generate token", http.StatusInternalServerError)
		return
	}

	newKey := &storage.ApiKey{
		UserID:      key.UserID,
		Name:        key.Name,
		Description: key.Description,
		TokenPrefix: plainToken[:12],
		TokenHash:   auth.HashToken(plainToken),
		Scopes:      key.Scopes,
		ExpiresAt:   key.ExpiresAt,
	}

	if err := s.store.CreateApiKey(r.Context(), newKey); err != nil {
		s.jsonError(w, "failed to create rotated api key", http.StatusInternalServerError)
		return
	}

	// Log audit event.
	sourceIP := r.RemoteAddr
	if fwdIP := r.Header.Get("X-Forwarded-For"); fwdIP != "" {
		sourceIP = fwdIP
	}
	user, _ := s.store.GetUser(r.Context(), userID)
	username := userID
	if user != nil {
		username = user.Username
	}
	s.logAudit("api_key_rotate", username, sourceIP, "", fmt.Sprintf("rotated api key: %s", key.Name), "success", nil)

	s.jsonResponse(w, createAPIKeyResponse{
		ID:          newKey.ID,
		Name:        newKey.Name,
		Description: newKey.Description,
		Token:       plainToken,
		TokenPrefix: newKey.TokenPrefix,
		Scopes:      newKey.Scopes,
		ExpiresAt:   newKey.ExpiresAt,
		CreatedAt:   newKey.CreatedAt,
	})
}

// validateAPIKey validates an API key token and returns the user ID and scopes.
func (s *Server) validateAPIKey(r *http.Request, token string) (string, []string, error) {
	tokenHash := auth.HashToken(token)

	key, err := s.store.GetApiKeyByTokenHash(r.Context(), tokenHash)
	if err != nil {
		return "", nil, fmt.Errorf("invalid api key: %w", err)
	}

	// Check if expired.
	if key.ExpiresAt != nil && key.ExpiresAt.Before(time.Now()) {
		return "", nil, fmt.Errorf("api key expired")
	}

	// Check if active.
	if !key.IsActive {
		return "", nil, fmt.Errorf("api key is disabled")
	}

	// Update last used timestamp (fire-and-forget, using detached context
	// since the request context will be cancelled when the handler returns).
	keyID := key.ID
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = s.store.UpdateApiKeyLastUsed(ctx, keyID)
	}()

	return key.UserID, key.Scopes, nil
}

// generateAPIKeyToken creates a new API key token with the vcj_ prefix.
func generateAPIKeyToken() (string, error) {
	b := make([]byte, 24) // 24 bytes = 48 hex chars
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return apiKeyPrefix + hex.EncodeToString(b), nil
}

// parseDuration parses human-friendly duration strings like "30d", "90d", "1y".
func parseDuration(s string) (time.Duration, error) {
	if len(s) < 2 {
		return 0, fmt.Errorf("invalid duration: %s", s)
	}

	unit := s[len(s)-1]
	valueStr := s[:len(s)-1]
	var value int
	if _, err := fmt.Sscanf(valueStr, "%d", &value); err != nil {
		return 0, fmt.Errorf("invalid duration value: %s", s)
	}

	switch unit {
	case 'h':
		return time.Duration(value) * time.Hour, nil
	case 'd':
		return time.Duration(value) * 24 * time.Hour, nil
	case 'w':
		return time.Duration(value) * 7 * 24 * time.Hour, nil
	case 'y':
		return time.Duration(value) * 365 * 24 * time.Hour, nil
	default:
		return 0, fmt.Errorf("unknown duration unit: %c (use h/d/w/y)", unit)
	}
}

// toAPIKeyInfo converts a storage.ApiKey to the safe response format (no token hash).
func toAPIKeyInfo(k *storage.ApiKey) apiKeyInfo {
	return apiKeyInfo{
		ID:          k.ID,
		Name:        k.Name,
		Description: k.Description,
		TokenPrefix: k.TokenPrefix,
		Scopes:      k.Scopes,
		LastUsedAt:  k.LastUsedAt,
		ExpiresAt:   k.ExpiresAt,
		IsActive:    k.IsActive,
		CreatedAt:   k.CreatedAt,
	}
}
