package dashboard

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
)

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
	recordingsPath := s.recordingCfg.LocalPath
	if recordingsPath == "" {
		s.jsonResponse(w, []interface{}{})
		return
	}

	entries, err := os.ReadDir(recordingsPath)
	if err != nil {
		s.jsonResponse(w, []interface{}{})
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
			"filename":  entry.Name(),
			"size":      info.Size(),
			"timestamp": info.ModTime(),
		})
	}
	if recordings == nil {
		recordings = []map[string]interface{}{}
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
	if !s.hasPermission(r, "recording:delete") {
		s.jsonError(w, "forbidden", http.StatusForbidden)
		return
	}

	recordingsPath := s.recordingCfg.LocalPath
	if recordingsPath == "" {
		s.jsonError(w, "recordings path not configured", http.StatusInternalServerError)
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

	const maxBatchSize = 100
	if len(req.Filenames) > maxBatchSize {
		s.jsonError(w, fmt.Sprintf("batch size exceeds limit of %d", maxBatchSize), http.StatusBadRequest)
		return
	}

	resp := BatchDeleteResponse{
		Deleted: []string{},
		Failed:  make(map[string]string),
	}

	for _, filename := range req.Filenames {
		// Validate filename: reject empty, path separators, and double-dot traversals.
		if filename == "" || strings.ContainsAny(filename, "/\\") || strings.Contains(filename, "..") {
			resp.Failed[filename] = "invalid filename"
			continue
		}

		filePath := filepath.Join(recordingsPath, filename)

		// Verify path is within recordings directory.
		if !isPathWithinBase(recordingsPath, filePath) {
			resp.Failed[filename] = "path traversal detected"
			continue
		}

		if err := os.Remove(filePath); err != nil { //nolint:gosec // G703: path already validated by isPathWithinBase
			resp.Failed[filename] = err.Error()
		} else {
			resp.Deleted = append(resp.Deleted, filename)
		}
	}

	s.jsonResponse(w, resp)
}

func (s *Server) handleRecording(w http.ResponseWriter, r *http.Request) {
	recordingsPath := s.recordingCfg.LocalPath
	if recordingsPath == "" {
		s.jsonError(w, "recordings not configured", http.StatusNotFound)
		return
	}

	filename := strings.TrimPrefix(r.URL.Path, "/api/recordings/")
	if filename == "" {
		s.jsonError(w, "filename required", http.StatusBadRequest)
		return
	}

	// Prevent directory traversal.
	if strings.Contains(filename, "..") || strings.Contains(filename, "/") || strings.Contains(filename, "\\") {
		s.jsonError(w, "invalid filename", http.StatusBadRequest)
		return
	}

	filePath := filepath.Join(recordingsPath, filename)
	if !isPathWithinBase(recordingsPath, filePath) {
		s.jsonError(w, "invalid path", http.StatusBadRequest)
		return
	}

	switch r.Method {
	case http.MethodGet:
		if !s.hasPermission(r, "recording:view") {
			s.jsonError(w, "forbidden", http.StatusForbidden)
			return
		}
		http.ServeFile(w, r, filePath)

	case http.MethodDelete:
		if !s.hasPermission(r, "recording:delete") {
			s.jsonError(w, "forbidden", http.StatusForbidden)
			return
		}
		if err := os.Remove(filePath); err != nil { //nolint:gosec // path validated by isPathWithinBase and filename checks
			s.jsonError(w, "failed to delete recording", http.StatusInternalServerError)
			return
		}
		s.jsonResponse(w, map[string]string{"status": "deleted"})

	default:
		s.jsonError(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}
