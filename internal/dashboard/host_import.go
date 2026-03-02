package dashboard

import (
	"encoding/json"
	"net/http"

	"github.com/Veritas-Calculus/vc-jump/internal/storage"
)

// hostImportEntry represents a single host to import.
type hostImportEntry struct {
	Name                  string   `json:"name"`
	Addr                  string   `json:"addr"`
	Port                  int      `json:"port"`
	User                  string   `json:"user"`
	Users                 []string `json:"users"`
	Groups                []string `json:"groups"`
	FolderID              string   `json:"folder_id"`
	KeyID                 string   `json:"key_id"`
	InsecureIgnoreHostKey bool     `json:"insecure_ignore_host_key"`
}

// hostImportRequest represents a batch host import request.
type hostImportRequest struct {
	Hosts  []hostImportEntry `json:"hosts"`
	DryRun bool              `json:"dry_run"`
}

// hostImportResult represents the result of a single host import.
type hostImportResult struct {
	Name    string `json:"name"`
	Status  string `json:"status"` // "created", "skipped", "error"
	Message string `json:"message,omitempty"`
}

// hostImportResponse represents the response of a batch host import.
type hostImportResponse struct {
	Total   int                `json:"total"`
	Created int                `json:"created"`
	Skipped int                `json:"skipped"`
	Errors  int                `json:"errors"`
	DryRun  bool               `json:"dry_run"`
	Results []hostImportResult `json:"results"`
}

// handleHostImport handles POST /api/hosts/import for batch host creation.
func (s *Server) handleHostImport(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		s.jsonError(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if !s.hasPermission(r, "host:create") {
		s.jsonError(w, "permission denied", http.StatusForbidden)
		return
	}

	var req hostImportRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.jsonError(w, "invalid request body", http.StatusBadRequest)
		return
	}

	if len(req.Hosts) == 0 {
		s.jsonError(w, "no hosts provided", http.StatusBadRequest)
		return
	}

	if len(req.Hosts) > 500 {
		s.jsonError(w, "too many hosts (max 500)", http.StatusBadRequest)
		return
	}

	resp := hostImportResponse{
		Total:  len(req.Hosts),
		DryRun: req.DryRun,
	}

	for _, entry := range req.Hosts {
		result := hostImportResult{Name: entry.Name}

		// Validate required fields.
		if entry.Name == "" {
			result.Status = "error"
			result.Message = "name is required"
			resp.Errors++
			resp.Results = append(resp.Results, result)
			continue
		}
		if entry.Addr == "" {
			result.Status = "error"
			result.Message = "addr is required"
			resp.Errors++
			resp.Results = append(resp.Results, result)
			continue
		}

		// Check for duplicates.
		existing, _ := s.store.GetHostByName(r.Context(), entry.Name)
		if existing != nil {
			result.Status = "skipped"
			result.Message = "host already exists"
			resp.Skipped++
			resp.Results = append(resp.Results, result)
			continue
		}

		if req.DryRun {
			result.Status = "created"
			result.Message = "will be created (dry run)"
			resp.Created++
			resp.Results = append(resp.Results, result)
			continue
		}

		// Create the host.
		port := entry.Port
		if port == 0 {
			port = 22
		}
		user := entry.User
		if user == "" {
			user = "root"
		}

		host := &storage.Host{
			Name:                  entry.Name,
			Addr:                  entry.Addr,
			Port:                  port,
			User:                  user,
			Users:                 entry.Users,
			Groups:                entry.Groups,
			FolderID:              entry.FolderID,
			KeyID:                 entry.KeyID,
			InsecureIgnoreHostKey: entry.InsecureIgnoreHostKey,
		}

		if err := s.store.CreateHost(r.Context(), host); err != nil {
			result.Status = "error"
			result.Message = err.Error()
			resp.Errors++
		} else {
			result.Status = "created"
			resp.Created++
		}

		resp.Results = append(resp.Results, result)
	}

	status := http.StatusOK
	if resp.Created > 0 && !req.DryRun {
		status = http.StatusCreated
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(resp)
}
