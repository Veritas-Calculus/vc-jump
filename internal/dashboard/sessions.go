package dashboard

import (
	"net/http"
	"strings"
	"time"

	"github.com/gorilla/websocket"
)

func (s *Server) handleSessions(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		s.jsonError(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if !s.hasPermission(r, "session:view") {
		s.jsonError(w, "forbidden", http.StatusForbidden)
		return
	}

	pg := parsePagination(r)
	if pg != nil {
		total, err := s.store.CountSessions(r.Context())
		if err != nil {
			s.jsonError(w, "failed to count sessions", http.StatusInternalServerError)
			return
		}
		sessions, err := s.store.ListSessions(r.Context(), "", pg.PageSize)
		if err != nil {
			s.jsonError(w, "failed to list sessions", http.StatusInternalServerError)
			return
		}
		s.jsonResponse(w, newPaginatedResponse(sessions, total, pg))
	} else {
		limit := 100
		sessions, err := s.store.ListSessions(r.Context(), "", limit)
		if err != nil {
			s.jsonError(w, "failed to list sessions", http.StatusInternalServerError)
			return
		}
		s.jsonResponse(w, sessions)
	}
}

func (s *Server) handleStats(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		s.jsonError(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	hosts, _ := s.store.ListHosts(r.Context())
	users, _ := s.store.ListUsers(r.Context())
	sessions, _ := s.store.ListSessions(r.Context(), "", 0)
	keys, _ := s.store.ListSSHKeys(r.Context())

	activeSessions := 0
	for _, session := range sessions {
		if session.EndTime.IsZero() {
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

	if !s.hasPermission(r, "session:view") {
		s.jsonError(w, "forbidden", http.StatusForbidden)
		return
	}

	sessions, err := s.store.ListSessions(r.Context(), "", 100)
	if err != nil {
		s.jsonError(w, "failed to list sessions", http.StatusInternalServerError)
		return
	}

	// Filter active sessions (no end time).
	var activeSessions []interface{}
	for _, session := range sessions {
		if session.EndTime.IsZero() {
			activeSessions = append(activeSessions, session)
		}
	}
	if activeSessions == nil {
		activeSessions = []interface{}{}
	}
	s.jsonResponse(w, activeSessions)
}

// handleTerminateSession terminates an active session.
// DELETE /api/sessions/active/:id
func (s *Server) handleTerminateSession(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodDelete {
		s.jsonError(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if !s.hasPermission(r, "session:terminate") {
		s.jsonError(w, "forbidden", http.StatusForbidden)
		return
	}

	sessionID := strings.TrimPrefix(r.URL.Path, "/api/sessions/active/")
	if sessionID == "" {
		s.jsonError(w, "session id required", http.StatusBadRequest)
		return
	}

	// Get session from DB.
	session, err := s.store.GetSession(r.Context(), sessionID)
	if err != nil {
		s.jsonError(w, "session not found", http.StatusNotFound)
		return
	}

	// Check if session is actually active (no end time).
	if !session.EndTime.IsZero() {
		s.jsonError(w, "session is not active", http.StatusConflict)
		return
	}

	// Mark session as ended in DB.
	session.EndTime = time.Now()
	if err := s.store.UpdateSession(r.Context(), session); err != nil {
		s.jsonError(w, "failed to terminate session", http.StatusInternalServerError)
		return
	}

	// Audit log.
	userID := r.Context().Value(contextKeyUserID).(string)
	user, _ := s.store.GetUser(r.Context(), userID)
	username := userID
	if user != nil {
		username = user.Username
	}
	s.logAudit("session_terminate", username, getClientIP(r), session.TargetHost,
		"terminate session "+sessionID, "success", map[string]interface{}{
			"terminated_user": session.Username,
			"session_id":      sessionID,
		})

	s.jsonResponse(w, map[string]string{
		"status":     "terminated",
		"session_id": sessionID,
	})
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
		s.jsonResponse(w, []interface{}{})
		return
	}

	activeSessions := s.recorder.ListActiveSessions()

	// Check if user has session:view permission.
	canViewAll := s.hasPermission(r, "session:view")

	if canViewAll {
		s.jsonResponse(w, activeSessions)
		return
	}

	// Filter to only the current user's sessions.
	userID := r.Context().Value(contextKeyUserID).(string)
	user, err := s.store.GetUser(r.Context(), userID)
	if err != nil {
		s.jsonResponse(w, []interface{}{})
		return
	}

	var userSessions []ActiveSessionInfo
	for _, session := range activeSessions {
		if session.Username == user.Username {
			userSessions = append(userSessions, session)
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
	if !s.hasPermission(r, "session:watch") {
		s.jsonError(w, "forbidden", http.StatusForbidden)
		return
	}

	if s.recorder == nil {
		s.jsonError(w, "recording not enabled", http.StatusNotFound)
		return
	}

	sessionID := strings.TrimPrefix(r.URL.Path, "/api/sessions/watch/")
	if sessionID == "" {
		s.jsonError(w, "session id required", http.StatusBadRequest)
		return
	}

	session, ok := s.recorder.GetSession(sessionID)
	if !ok {
		s.jsonError(w, "session not found or not active", http.StatusNotFound)
		return
	}

	conn, err := wsUpgrader.Upgrade(w, r, nil)
	if err != nil {
		return
	}
	defer func() { _ = conn.Close() }()

	// Create watcher channel.
	dataCh := make(chan []byte, 100)
	session.AddWatcher(dataCh)
	defer session.RemoveWatcher(dataCh)

	// Read loop (handles pings/close).
	go func() {
		for {
			if _, _, err := conn.ReadMessage(); err != nil {
				return
			}
		}
	}()

	// Write loop.
	for data := range dataCh {
		if err := conn.WriteMessage(websocket.TextMessage, data); err != nil {
			return
		}
	}
}
