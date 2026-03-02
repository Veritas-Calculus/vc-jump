// Audit log API handlers for dashboard.
package dashboard

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/Veritas-Calculus/vc-jump/internal/storage"
)

// auditQueryParams holds parsed query parameters for audit log requests.
type auditQueryParams struct {
	username  string
	eventType string
	startTime time.Time
	endTime   time.Time
	limit     int
	offset    int
}

// parseAuditQueryParams parses query parameters for audit log requests.
func parseAuditQueryParams(r *http.Request) auditQueryParams {
	query := r.URL.Query()
	params := auditQueryParams{
		username:  query.Get("username"),
		eventType: query.Get("event_type"),
		limit:     100,
		offset:    0,
	}

	if start := query.Get("start_time"); start != "" {
		if t, err := time.Parse(time.RFC3339, start); err == nil {
			params.startTime = t
		}
	}
	if end := query.Get("end_time"); end != "" {
		if t, err := time.Parse(time.RFC3339, end); err == nil {
			params.endTime = t
		}
	}
	if l := query.Get("limit"); l != "" {
		if n, err := strconv.Atoi(l); err == nil && n > 0 && n <= 1000 {
			params.limit = n
		}
	}
	if o := query.Get("offset"); o != "" {
		if n, err := strconv.Atoi(o); err == nil && n >= 0 {
			params.offset = n
		}
	}

	return params
}

// handleAuditLogs handles GET /api/audit requests.
func (s *Server) handleAuditLogs(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		s.jsonError(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if !s.hasPermission(r, "audit:view") {
		s.jsonError(w, "permission denied", http.StatusForbidden)
		return
	}

	params := parseAuditQueryParams(r)
	logs, err := s.store.ListAuditLogs(r.Context(), params.username, params.eventType, params.startTime, params.endTime, params.limit, params.offset)
	if err != nil {
		s.jsonError(w, "failed to list audit logs", http.StatusInternalServerError)
		return
	}

	if logs == nil {
		logs = []storage.AuditLog{}
	}

	s.jsonResponse(w, logs)
}

// handleAuditStats returns audit statistics.
func (s *Server) handleAuditStats(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		s.jsonError(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if !s.hasPermission(r, "audit:view") {
		s.jsonError(w, "permission denied", http.StatusForbidden)
		return
	}

	// Get counts for last 24 hours.
	since := time.Now().Add(-24 * time.Hour)
	logs, err := s.store.ListAuditLogs(r.Context(), "", "", since, time.Time{}, 10000, 0)
	if err != nil {
		s.jsonError(w, "failed to get audit stats", http.StatusInternalServerError)
		return
	}

	stats := map[string]int{
		"total":      len(logs),
		"logins":     0,
		"connects":   0,
		"failures":   0,
		"dashboards": 0,
	}

	for _, log := range logs {
		switch log.EventType {
		case "login", "ssh_login":
			stats["logins"]++
		case "connect":
			stats["connects"]++
		case "dashboard_login":
			stats["dashboards"]++
		}
		if log.Result == "failure" || log.Result == "failed" {
			stats["failures"]++
		}
	}

	s.jsonResponse(w, stats)
}

// handleAuditExport exports audit logs in CSV or JSON Lines format.
// GET /api/audit/export?format=csv&start_time=...&end_time=...&username=...&event_type=...
func (s *Server) handleAuditExport(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		s.jsonError(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if !s.hasPermission(r, "audit:view") {
		s.jsonError(w, "permission denied", http.StatusForbidden)
		return
	}

	params := parseAuditQueryParams(r)
	// Override limit for export — no cap.
	params.limit = 0
	params.offset = 0

	logs, err := s.store.ListAuditLogs(r.Context(), params.username, params.eventType, params.startTime, params.endTime, params.limit, params.offset)
	if err != nil {
		s.jsonError(w, "failed to list audit logs", http.StatusInternalServerError)
		return
	}
	if logs == nil {
		logs = []storage.AuditLog{}
	}

	format := r.URL.Query().Get("format")
	if format == "" {
		format = "csv"
	}

	switch format {
	case "csv":
		s.exportAuditCSV(w, logs)
	case "jsonl":
		s.exportAuditJSONL(w, logs)
	default:
		s.jsonError(w, "unsupported format, use csv or jsonl", http.StatusBadRequest)
	}
}

func (s *Server) exportAuditCSV(w http.ResponseWriter, logs []storage.AuditLog) {
	w.Header().Set("Content-Type", "text/csv; charset=utf-8")
	w.Header().Set("Content-Disposition", "attachment; filename=audit_logs.csv")

	// Write BOM for Excel compatibility.
	_, _ = w.Write([]byte("\xEF\xBB\xBF"))
	// Header row.
	_, _ = w.Write([]byte("id,timestamp,event_type,username,source_ip,target_host,action,result\n"))

	for _, log := range logs {
		line := fmt.Sprintf("%s,%s,%s,%s,%s,%s,%s,%s\n",
			csvEscape(log.ID),
			log.Timestamp.Format(time.RFC3339),
			csvEscape(log.EventType),
			csvEscape(log.Username),
			csvEscape(log.SourceIP),
			csvEscape(log.TargetHost),
			csvEscape(log.Action),
			csvEscape(log.Result),
		)
		_, _ = w.Write([]byte(line))
	}
}

func (s *Server) exportAuditJSONL(w http.ResponseWriter, logs []storage.AuditLog) {
	w.Header().Set("Content-Type", "application/x-ndjson; charset=utf-8")
	w.Header().Set("Content-Disposition", "attachment; filename=audit_logs.jsonl")

	enc := json.NewEncoder(w)
	for _, log := range logs {
		_ = enc.Encode(log)
	}
}

// csvEscape wraps a value in quotes if it contains commas, quotes, or newlines.
func csvEscape(s string) string {
	needsQuote := false
	for _, c := range s {
		if c == ',' || c == '"' || c == '\n' || c == '\r' {
			needsQuote = true
			break
		}
	}
	if !needsQuote {
		return s
	}
	// Double any quotes and wrap.
	escaped := strings.ReplaceAll(s, "\"", "\"\"")
	return "\"" + escaped + "\""
}
