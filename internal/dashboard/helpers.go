package dashboard

import (
	"context"
	"encoding/json"
	"net/http"
	"path/filepath"
	"strings"
	"time"

	"github.com/Veritas-Calculus/vc-jump/internal/storage"
)

// APIError represents a standardized error response.
type APIError struct {
	Code    int    `json:"code"`
	Error   string `json:"error"`
	Details string `json:"details,omitempty"`
}

func (s *Server) jsonResponse(w http.ResponseWriter, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(data)
}

func (s *Server) jsonCreated(w http.ResponseWriter, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(data)
}

func (s *Server) jsonError(w http.ResponseWriter, message string, code int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(APIError{
		Code:  code,
		Error: message,
	})
}

func (s *Server) jsonErrorWithDetails(w http.ResponseWriter, message, details string, code int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(APIError{
		Code:    code,
		Error:   message,
		Details: details,
	})
}

// deprecated wraps a handler to add deprecation headers to the response.
// newRoute is the suggested replacement route.
func (s *Server) deprecated(handler http.HandlerFunc, newRoute string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Deprecation", "true")
		w.Header().Set("Sunset", "2026-12-31T23:59:59Z")
		w.Header().Set("Link", "<"+newRoute+">; rel=\"successor-version\"")
		handler(w, r)
	}
}

// isPathWithinBase validates that the given path is within the base directory.
// This prevents directory traversal attacks.
func isPathWithinBase(basePath, targetPath string) bool {
	absBase, err := filepath.Abs(basePath)
	if err != nil {
		return false
	}

	absTarget, err := filepath.Abs(targetPath)
	if err != nil {
		return false
	}

	rel, err := filepath.Rel(absBase, absTarget)
	if err != nil {
		return false
	}

	// Check if the relative path tries to escape.
	if startsWithDotDot(rel) {
		return false
	}
	return true
}

// startsWithDotDot checks if a path starts with "..".
func startsWithDotDot(path string) bool {
	if path == ".." {
		return true
	}
	return strings.HasPrefix(path, ".."+string(filepath.Separator))
}

// logAudit logs an audit event to SQLite storage.
func (s *Server) logAudit(eventType, username, sourceIP, targetHost, action, result string, details map[string]interface{}) { //nolint:unparam // targetHost reserved for SSH session audit
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
func (s *Server) handleRobotsTxt(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	// Disallow all crawlers - this is an internal admin dashboard
	robotsTxt := `User-agent: *
Disallow: /
`
	_, _ = w.Write([]byte(robotsTxt))
}

// handleSitemapXml returns an empty sitemap - internal dashboard doesn't need indexing.
func (s *Server) handleSitemapXml(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/xml; charset=utf-8")
	sitemap := `<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
</urlset>
`
	_, _ = w.Write([]byte(sitemap))
}
