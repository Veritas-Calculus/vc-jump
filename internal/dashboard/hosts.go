package dashboard

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/Veritas-Calculus/vc-jump/internal/storage"
)

// handleHosts handles host list and creation.
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
