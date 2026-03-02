package dashboard

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/Veritas-Calculus/vc-jump/internal/storage"
)

// TestParseDuration verifies the human-friendly duration parser.
func TestParseDuration(t *testing.T) {
	t.Parallel()

	tests := []struct {
		input   string
		wantErr bool
		wantH   int // Expected hours (approximate).
	}{
		{"1h", false, 1},
		{"24h", false, 24},
		{"1d", false, 24},
		{"7d", false, 168},
		{"1w", false, 168},
		{"30d", false, 720},
		{"90d", false, 2160},
		{"1y", false, 8760},
		{"2y", false, 17520},

		// Error cases.
		{"", true, 0},
		{"x", true, 0},
		{"1", true, 0},    // No unit.
		{"abcd", true, 0}, // No valid number.
		{"1m", true, 0},   // 'm' is not a valid unit.
		{"1s", true, 0},   // 's' is not a valid unit.
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			t.Parallel()
			d, err := parseDuration(tt.input)
			if tt.wantErr {
				if err == nil {
					t.Errorf("parseDuration(%q) = %v, want error", tt.input, d)
				}
				return
			}
			if err != nil {
				t.Fatalf("parseDuration(%q) error: %v", tt.input, err)
			}
			gotH := int(d.Hours())
			if gotH != tt.wantH {
				t.Errorf("parseDuration(%q) = %dh, want %dh", tt.input, gotH, tt.wantH)
			}
		})
	}
}

// TestGenerateAPIKeyToken verifies generated tokens have the correct format.
func TestGenerateAPIKeyToken(t *testing.T) {
	t.Parallel()

	token, err := generateAPIKeyToken()
	if err != nil {
		t.Fatalf("generateAPIKeyToken() error: %v", err)
	}

	// Must start with "vcj_" prefix.
	if !strings.HasPrefix(token, "vcj_") {
		t.Errorf("token = %q, want prefix 'vcj_'", token)
	}

	// Total length: 4 (prefix) + 48 (hex) = 52 chars.
	if len(token) != 52 {
		t.Errorf("token length = %d, want 52", len(token))
	}

	// Hex portion should only contain valid hex chars.
	hexPart := token[4:]
	for _, c := range hexPart {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			t.Errorf("invalid hex char '%c' in token", c)
		}
	}
}

// TestGenerateAPIKeyTokenUniqueness verifies tokens are unique.
func TestGenerateAPIKeyTokenUniqueness(t *testing.T) {
	t.Parallel()

	seen := make(map[string]bool)
	for i := 0; i < 100; i++ {
		token, err := generateAPIKeyToken()
		if err != nil {
			t.Fatalf("iteration %d: generateAPIKeyToken() error: %v", i, err)
		}
		if seen[token] {
			t.Fatalf("duplicate token generated at iteration %d", i)
		}
		seen[token] = true
	}
}

// TestHandleAPIKeysMethodNotAllowed verifies unsupported methods are rejected.
func TestHandleAPIKeysMethodNotAllowed(t *testing.T) {
	t.Parallel()

	s := &Server{}
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodDelete, "/api/api-keys", nil)
	s.handleAPIKeys(rr, req)

	if rr.Code != http.StatusMethodNotAllowed {
		t.Errorf("status = %d, want 405", rr.Code)
	}
}

// TestHandleAPIKeyRouting verifies route parsing for /api/api-keys/:id subpaths.
func TestHandleAPIKeyRouting(t *testing.T) {
	t.Parallel()

	s := &Server{}

	tests := []struct {
		name     string
		path     string
		method   string
		wantCode int
	}{
		{
			name:     "empty ID returns 400",
			path:     "/api/api-keys/",
			method:   http.MethodGet,
			wantCode: http.StatusBadRequest,
		},
		{
			name:     "unsupported method returns 405",
			path:     "/api/api-keys/some-id",
			method:   http.MethodPut,
			wantCode: http.StatusMethodNotAllowed,
		},
		{
			name:     "unknown sub-route returns 404",
			path:     "/api/api-keys/some-id/unknown",
			method:   http.MethodPost,
			wantCode: http.StatusNotFound,
		},
		{
			name:     "rotate with wrong method returns 404",
			path:     "/api/api-keys/some-id/rotate",
			method:   http.MethodGet,
			wantCode: http.StatusNotFound, // Only POST is accepted for rotate.
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			rr := httptest.NewRecorder()
			req := httptest.NewRequest(tt.method, tt.path, nil)
			s.handleAPIKey(rr, req)

			if rr.Code != tt.wantCode {
				t.Errorf("path=%s method=%s: status = %d, want %d", tt.path, tt.method, rr.Code, tt.wantCode)
			}
		})
	}
}

// TestToAPIKeyInfo verifies the safe conversion from storage model to response format.
func TestToAPIKeyInfo(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	key := &storage.ApiKey{
		ID:          "key-123",
		Name:        "test-key",
		Description: "a test key",
		TokenPrefix: "vcj_abc12345",
		TokenHash:   "secret_hash_should_not_appear",
		Scopes:      []string{"host:view", "host:connect"},
		IsActive:    true,
		CreatedAt:   now,
	}

	info := toAPIKeyInfo(key)

	if info.ID != "key-123" {
		t.Errorf("ID = %q, want 'key-123'", info.ID)
	}
	if info.Name != "test-key" {
		t.Errorf("Name = %q, want 'test-key'", info.Name)
	}
	if info.TokenPrefix != "vcj_abc12345" {
		t.Errorf("TokenPrefix = %q, want 'vcj_abc12345'", info.TokenPrefix)
	}
	if !info.IsActive {
		t.Error("IsActive should be true")
	}
	if len(info.Scopes) != 2 {
		t.Errorf("Scopes length = %d, want 2", len(info.Scopes))
	}
	if info.Description != "a test key" {
		t.Errorf("Description = %q, want 'a test key'", info.Description)
	}
}

// TestAPIKeyPrefix verifies the constant.
func TestAPIKeyPrefix(t *testing.T) {
	t.Parallel()

	if apiKeyPrefix != "vcj_" {
		t.Errorf("apiKeyPrefix = %q, want 'vcj_'", apiKeyPrefix)
	}
}

// TestCreateAPIKeyRequestValidation verifies JSON parsing of the create request.
func TestCreateAPIKeyRequestValidation(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		body    string
		wantErr bool
	}{
		{"valid minimal", `{"name":"my-key"}`, false},
		{"valid full", `{"name":"my-key","description":"desc","scopes":["host:view"],"expires_in":"90d"}`, false},
		{"invalid json", `{invalid`, true},
		{"empty body", ``, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			var req createAPIKeyRequest
			err := json.Unmarshal([]byte(tt.body), &req)
			if tt.wantErr {
				if err == nil {
					t.Errorf("expected error for input %q", tt.body)
				}
			} else {
				if err != nil {
					t.Errorf("unexpected error: %v", err)
				}
			}
		})
	}
}
