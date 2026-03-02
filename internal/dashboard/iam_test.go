package dashboard

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestAPIErrorFormat verifies the standardized error response format.
func TestAPIErrorFormat(t *testing.T) {
	t.Parallel()

	s := &Server{}

	tests := []struct {
		name     string
		message  string
		code     int
		wantCode int
	}{
		{"bad request", "invalid input", http.StatusBadRequest, 400},
		{"unauthorized", "unauthorized", http.StatusUnauthorized, 401},
		{"forbidden", "forbidden", http.StatusForbidden, 403},
		{"not found", "resource not found", http.StatusNotFound, 404},
		{"internal error", "server error", http.StatusInternalServerError, 500},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			rr := httptest.NewRecorder()
			s.jsonError(rr, tt.message, tt.code)

			if rr.Code != tt.code {
				t.Errorf("status = %d, want %d", rr.Code, tt.code)
			}

			var resp APIError
			if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
				t.Fatalf("failed to unmarshal: %v", err)
			}

			if resp.Code != tt.wantCode {
				t.Errorf("resp.Code = %d, want %d", resp.Code, tt.wantCode)
			}
			if resp.Error != tt.message {
				t.Errorf("resp.Error = %q, want %q", resp.Error, tt.message)
			}
			// Backward compatibility: the "error" field must be present.
			raw := make(map[string]interface{})
			_ = json.Unmarshal(rr.Body.Bytes(), &raw)
			if _, ok := raw["error"]; !ok {
				t.Error("response must contain 'error' field for backward compatibility")
			}
		})
	}
}

// TestAPIErrorWithDetails verifies the detailed error response.
func TestAPIErrorWithDetails(t *testing.T) {
	t.Parallel()

	s := &Server{}
	rr := httptest.NewRecorder()
	s.jsonErrorWithDetails(rr, "validation failed", "field 'name' is required", http.StatusBadRequest)

	var resp APIError
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to unmarshal: %v", err)
	}

	if resp.Code != 400 {
		t.Errorf("code = %d, want 400", resp.Code)
	}
	if resp.Error != "validation failed" {
		t.Errorf("error = %q, want 'validation failed'", resp.Error)
	}
	if resp.Details != "field 'name' is required" {
		t.Errorf("details = %q, want \"field 'name' is required\"", resp.Details)
	}
}

// TestAPIErrorOmitsEmptyDetails verifies that details field is omitted when empty.
func TestAPIErrorOmitsEmptyDetails(t *testing.T) {
	t.Parallel()

	s := &Server{}
	rr := httptest.NewRecorder()
	s.jsonError(rr, "some error", http.StatusBadRequest)

	raw := make(map[string]interface{})
	if err := json.Unmarshal(rr.Body.Bytes(), &raw); err != nil {
		t.Fatalf("failed to unmarshal: %v", err)
	}

	if _, exists := raw["details"]; exists {
		t.Error("details field should be omitted when empty")
	}
}

// TestDeprecatedWrapper verifies the deprecated endpoint wrapper adds correct headers.
func TestDeprecatedWrapper(t *testing.T) {
	t.Parallel()

	s := &Server{}

	original := func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status":"ok"}`))
	}

	wrapped := s.deprecated(original, "/api/v2/new-endpoint")

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/old-endpoint", nil)
	wrapped(rr, req)

	// Must have deprecation header.
	if dep := rr.Header().Get("Deprecation"); dep != "true" {
		t.Errorf("Deprecation header = %q, want 'true'", dep)
	}

	// Must have sunset header.
	if sunset := rr.Header().Get("Sunset"); sunset == "" {
		t.Error("Sunset header should not be empty")
	}

	// Must have Link header with successor-version rel.
	link := rr.Header().Get("Link")
	if link == "" {
		t.Error("Link header should not be empty")
	}
	if link != "</api/v2/new-endpoint>; rel=\"successor-version\"" {
		t.Errorf("Link header = %q, want '</api/v2/new-endpoint>; rel=\"successor-version\"'", link)
	}

	// Original handler must still execute.
	if rr.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", rr.Code)
	}
}

// TestJsonCreated verifies the jsonCreated helper returns 201.
func TestJsonCreated(t *testing.T) {
	t.Parallel()

	s := &Server{}
	rr := httptest.NewRecorder()
	s.jsonCreated(rr, map[string]string{"id": "abc123"})

	if rr.Code != http.StatusCreated {
		t.Errorf("status = %d, want 201", rr.Code)
	}

	ct := rr.Header().Get("Content-Type")
	if ct != "application/json" {
		t.Errorf("Content-Type = %q, want 'application/json'", ct)
	}

	raw := make(map[string]interface{})
	if err := json.Unmarshal(rr.Body.Bytes(), &raw); err != nil {
		t.Fatalf("failed to unmarshal: %v", err)
	}
	if raw["id"] != "abc123" {
		t.Errorf("id = %v, want 'abc123'", raw["id"])
	}
}

// TestHandleRoleDualPrefix verifies handleRole works with both /api/iam/roles/ and /api/roles/ prefixes.
func TestHandleRoleDualPrefix(t *testing.T) {
	t.Parallel()

	s := &Server{}

	tests := []struct {
		name     string
		path     string
		wantCode int // We expect 405 (method not allowed for GET without store) or other,
		// but should not be 400 (role ID required).
	}{
		{
			name: "old iam prefix",
			path: "/api/iam/roles/test-role-id",
		},
		{
			name: "normalized prefix",
			path: "/api/roles/test-role-id",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			rr := httptest.NewRecorder()
			// Use GET method — without a store it will panic on getRole,
			// but we just need to verify the ID extraction doesn't fail.
			// We'll test with an invalid method to stay safe.
			req := httptest.NewRequest(http.MethodOptions, tt.path, nil)
			s.handleRole(rr, req)

			// Both paths should yield "method not allowed" (405), NOT "role ID required" (400).
			if rr.Code != http.StatusMethodNotAllowed {
				t.Errorf("path %s: status = %d, want 405 (method not allowed)", tt.path, rr.Code)
			}
		})
	}
}

// TestHandleRoleEmptyID verifies handleRole returns 400 for empty IDs.
func TestHandleRoleEmptyID(t *testing.T) {
	t.Parallel()

	s := &Server{}
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/iam/roles/", nil)
	s.handleRole(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", rr.Code)
	}
}

// TestHandleUserSubResourceRouting verifies the sub-resource router correctly dispatches paths.
func TestHandleUserSubResourceRouting(t *testing.T) {
	t.Parallel()

	s := &Server{}

	tests := []struct {
		name     string
		path     string
		method   string
		wantCode int
	}{
		{
			name:     "roles sub-resource with unsupported method returns 405",
			path:     "/api/users/user123/roles",
			method:   http.MethodDelete,
			wantCode: http.StatusMethodNotAllowed,
		},
		{
			name:     "host-permissions sub-resource with unsupported method returns 405",
			path:     "/api/users/user123/host-permissions",
			method:   http.MethodDelete,
			wantCode: http.StatusMethodNotAllowed,
		},
		{
			name:     "empty user ID returns 400",
			path:     "/api/users/",
			method:   http.MethodGet,
			wantCode: http.StatusBadRequest, // handleUser will see empty ID.
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			rr := httptest.NewRecorder()
			req := httptest.NewRequest(tt.method, tt.path, nil)
			s.handleUserSubResource(rr, req)

			if rr.Code != tt.wantCode {
				t.Errorf("path=%s method=%s: status = %d, want %d, body: %s",
					tt.path, tt.method, rr.Code, tt.wantCode, rr.Body.String())
			}
		})
	}
}

// TestHandleUserHostPermissionsRouting verifies the host-permissions sub-resource method dispatching.
func TestHandleUserHostPermissionsRouting(t *testing.T) {
	t.Parallel()

	s := &Server{}
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodDelete, "/api/users/user123/host-permissions", nil)
	s.handleUserHostPermissions(rr, req, "user123")

	if rr.Code != http.StatusMethodNotAllowed {
		t.Errorf("status = %d, want 405", rr.Code)
	}
}

// TestHandlePermissionsList verifies the permissions endpoint works.
func TestHandlePermissionsList(t *testing.T) {
	t.Parallel()

	s := &Server{}
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/iam/permissions", nil)
	s.handlePermissionsList(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", rr.Code)
	}

	var perms []permissionInfo
	if err := json.Unmarshal(rr.Body.Bytes(), &perms); err != nil {
		t.Fatalf("failed to unmarshal: %v", err)
	}

	if len(perms) == 0 {
		t.Error("expected non-empty permissions list")
	}

	// Check that all expected categories are present.
	categories := map[string]bool{}
	for _, p := range perms {
		categories[p.Category] = true
	}
	for _, cat := range []string{"Hosts", "Users", "Sessions", "Recordings", "SSH Keys", "IAM", "Audit", "Settings"} {
		if !categories[cat] {
			t.Errorf("missing permission category: %s", cat)
		}
	}
}

// TestHandlePermissionsListMethodNotAllowed verifies only GET is accepted.
func TestHandlePermissionsListMethodNotAllowed(t *testing.T) {
	t.Parallel()

	s := &Server{}
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/iam/permissions", nil)
	s.handlePermissionsList(rr, req)

	if rr.Code != http.StatusMethodNotAllowed {
		t.Errorf("status = %d, want 405", rr.Code)
	}
}

// TestHandleRolesMethodNotAllowed verifies unsupported methods are rejected.
func TestHandleRolesMethodNotAllowed(t *testing.T) {
	t.Parallel()

	s := &Server{}
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodDelete, "/api/roles", nil)
	s.handleRoles(rr, req)

	if rr.Code != http.StatusMethodNotAllowed {
		t.Errorf("status = %d, want 405", rr.Code)
	}
}
