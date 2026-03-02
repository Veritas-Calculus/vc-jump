package dashboard

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/Veritas-Calculus/vc-jump/internal/config"
)

func TestIsPathWithinBase(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		basePath   string
		targetPath string
		want       bool
	}{
		{
			name:       "valid path within base",
			basePath:   "/tmp/recordings",
			targetPath: "/tmp/recordings/file.cast",
			want:       true,
		},
		{
			name:       "valid nested path",
			basePath:   "/tmp/recordings",
			targetPath: "/tmp/recordings/subdir/file.cast",
			want:       true,
		},
		{
			name:       "directory traversal attempt",
			basePath:   "/tmp/recordings",
			targetPath: "/tmp/recordings/../secret/file.txt",
			want:       false,
		},
		{
			name:       "absolute path outside base",
			basePath:   "/tmp/recordings",
			targetPath: "/etc/passwd",
			want:       false,
		},
		{
			name:       "same as base path",
			basePath:   "/tmp/recordings",
			targetPath: "/tmp/recordings",
			want:       true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := isPathWithinBase(tt.basePath, tt.targetPath)
			if got != tt.want {
				t.Errorf("isPathWithinBase(%q, %q) = %v, want %v", tt.basePath, tt.targetPath, got, tt.want)
			}
		})
	}
}

func TestStartsWithDotDot(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		path string
		want bool
	}{
		{"double dot", "..", true},
		{"double dot with separator", "../secret", true},
		{"normal path", "foo/bar", false},
		{"path starting with dot", ".hidden", false},
		{"double dot in middle", "foo/../bar", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := startsWithDotDot(tt.path)
			if got != tt.want {
				t.Errorf("startsWithDotDot(%q) = %v, want %v", tt.path, got, tt.want)
			}
		})
	}
}

func TestHandleRecordingsBatchDelete(t *testing.T) {
	t.Parallel()
	h := newTestHarness(t)

	// Create a temporary directory for test recordings.
	tmpDir, err := os.MkdirTemp("", "recordings-test-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer func() { _ = os.RemoveAll(tmpDir) }()

	// Inject recording path.
	h.server.recordingCfg = config.RecordingConfig{
		Enabled:   true,
		LocalPath: tmpDir,
	}

	// Create test files.
	testFiles := []string{"test1.cast", "test2.cast", "test3.cast"}
	for _, f := range testFiles {
		path := filepath.Join(tmpDir, f)
		if err := os.WriteFile(path, []byte("test content"), 0600); err != nil {
			t.Fatalf("failed to create test file %s: %v", f, err)
		}
	}

	t.Run("delete single file", func(t *testing.T) {
		rr := h.do(http.MethodDelete, "/api/recordings", BatchDeleteRequest{Filenames: []string{"test1.cast"}})
		h.assertStatus(rr, http.StatusOK)

		var resp BatchDeleteResponse
		h.unmarshal(rr, &resp)
		if len(resp.Deleted) != 1 {
			t.Errorf("deleted count = %d, want 1", len(resp.Deleted))
		}
	})

	t.Run("delete multiple files", func(t *testing.T) {
		rr := h.do(http.MethodDelete, "/api/recordings", BatchDeleteRequest{Filenames: []string{"test2.cast", "test3.cast"}})
		h.assertStatus(rr, http.StatusOK)

		var resp BatchDeleteResponse
		h.unmarshal(rr, &resp)
		if len(resp.Deleted) != 2 {
			t.Errorf("deleted count = %d, want 2", len(resp.Deleted))
		}
	})

	t.Run("delete non-existent file", func(t *testing.T) {
		rr := h.do(http.MethodDelete, "/api/recordings", BatchDeleteRequest{Filenames: []string{"nonexistent.cast"}})
		h.assertStatus(rr, http.StatusOK)

		var resp BatchDeleteResponse
		h.unmarshal(rr, &resp)
		if len(resp.Deleted) != 0 {
			t.Errorf("deleted count = %d, want 0", len(resp.Deleted))
		}
		if len(resp.Failed) != 1 {
			t.Errorf("failed count = %d, want 1", len(resp.Failed))
		}
	})

	t.Run("empty filenames", func(t *testing.T) {
		rr := h.do(http.MethodDelete, "/api/recordings", BatchDeleteRequest{Filenames: []string{}})
		h.assertStatus(rr, http.StatusBadRequest)
	})

	t.Run("directory traversal attempt", func(t *testing.T) {
		rr := h.do(http.MethodDelete, "/api/recordings", BatchDeleteRequest{Filenames: []string{"../secret.txt"}})
		h.assertStatus(rr, http.StatusOK)

		var resp BatchDeleteResponse
		h.unmarshal(rr, &resp)
		if len(resp.Deleted) != 0 {
			t.Errorf("deleted count = %d, want 0", len(resp.Deleted))
		}
		if len(resp.Failed) != 1 {
			t.Errorf("failed count = %d, want 1", len(resp.Failed))
		}
	})
}

func TestHandleRecordingsBatchDeleteValidation(t *testing.T) {
	t.Parallel()
	h := newTestHarness(t)

	tmpDir, err := os.MkdirTemp("", "recordings-validation-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer func() { _ = os.RemoveAll(tmpDir) }()

	h.server.recordingCfg = config.RecordingConfig{
		Enabled:   true,
		LocalPath: tmpDir,
	}

	tests := []struct {
		name        string
		filenames   []string
		wantFailed  []string
		wantDeleted []string
	}{
		{
			name:        "path with slash",
			filenames:   []string{"sub/file.cast"},
			wantFailed:  []string{"sub/file.cast"},
			wantDeleted: nil,
		},
		{
			name:        "path with backslash",
			filenames:   []string{"sub\\file.cast"},
			wantFailed:  []string{"sub\\file.cast"},
			wantDeleted: nil,
		},
		{
			name:        "empty filename",
			filenames:   []string{""},
			wantFailed:  []string{""},
			wantDeleted: nil,
		},
		{
			name:        "double dot",
			filenames:   []string{".."},
			wantFailed:  []string{".."},
			wantDeleted: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rr := h.do(http.MethodDelete, "/api/recordings", BatchDeleteRequest{Filenames: tt.filenames})

			var resp BatchDeleteResponse
			h.unmarshal(rr, &resp)

			for _, f := range tt.wantFailed {
				if _, ok := resp.Failed[f]; !ok {
					t.Errorf("expected %q to be in failed list", f)
				}
			}

			if len(resp.Deleted) != len(tt.wantDeleted) {
				t.Errorf("deleted = %v, want %v", resp.Deleted, tt.wantDeleted)
			}
		})
	}
}

func TestHandleRecordingsBatchDeleteDisabled(t *testing.T) {
	t.Parallel()
	h := newTestHarness(t)

	// No recording path configured.
	h.server.recordingCfg = config.RecordingConfig{
		Enabled:   false,
		LocalPath: "",
	}

	rr := h.do(http.MethodDelete, "/api/recordings", BatchDeleteRequest{Filenames: []string{"test.cast"}})
	if rr.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want %d", rr.Code, http.StatusInternalServerError)
	}
}

func TestHandleRecordingsBatchDeleteMaxLimit(t *testing.T) {
	t.Parallel()
	h := newTestHarness(t)

	tmpDir, err := os.MkdirTemp("", "recordings-limit-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer func() { _ = os.RemoveAll(tmpDir) }()

	h.server.recordingCfg = config.RecordingConfig{
		Enabled:   true,
		LocalPath: tmpDir,
	}

	// Create a request with more than maxBatchSize files.
	filenames := make([]string, 101)
	for i := range filenames {
		filenames[i] = "file" + string(rune('0'+i%10)) + ".cast"
	}

	body, _ := json.Marshal(BatchDeleteRequest{Filenames: filenames})
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodDelete, "/api/recordings", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+h.adminToken)
	h.server.server.Handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want %d", rr.Code, http.StatusBadRequest)
	}
}
