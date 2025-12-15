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
				t.Errorf("isPathWithinBase(%q, %q) = %v, want %v",
					tt.basePath, tt.targetPath, got, tt.want)
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
		{"empty string", "", false},
		{"single dot", ".", false},
		{"double dot only", "..", true},
		{"double dot with separator", "../foo", true},
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

// mockServer creates a minimal Server for testing.
func newTestServer(t *testing.T, recordingPath string) *Server {
	t.Helper()
	return &Server{
		recordingCfg: config.RecordingConfig{
			Enabled:   true,
			LocalPath: recordingPath,
		},
	}
}

func TestHandleRecordingsBatchDelete(t *testing.T) {
	t.Parallel()

	// Create a temporary directory for test recordings.
	tmpDir, err := os.MkdirTemp("", "recordings-test-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer func() { _ = os.RemoveAll(tmpDir) }()

	// Create test files.
	testFiles := []string{"test1.cast", "test2.cast", "test3.cast"}
	for _, f := range testFiles {
		path := filepath.Join(tmpDir, f)
		if err := os.WriteFile(path, []byte("test content"), 0600); err != nil {
			t.Fatalf("failed to create test file %s: %v", f, err)
		}
	}

	s := newTestServer(t, tmpDir)

	tests := []struct {
		name           string
		requestBody    interface{}
		wantStatus     int
		wantDeleted    int
		wantFailed     int
		checkFilesLeft int
	}{
		{
			name:           "delete single file",
			requestBody:    BatchDeleteRequest{Filenames: []string{"test1.cast"}},
			wantStatus:     http.StatusOK,
			wantDeleted:    1,
			wantFailed:     0,
			checkFilesLeft: 2,
		},
		{
			name:           "delete multiple files",
			requestBody:    BatchDeleteRequest{Filenames: []string{"test2.cast", "test3.cast"}},
			wantStatus:     http.StatusOK,
			wantDeleted:    2,
			wantFailed:     0,
			checkFilesLeft: 0,
		},
		{
			name:           "delete non-existent file",
			requestBody:    BatchDeleteRequest{Filenames: []string{"nonexistent.cast"}},
			wantStatus:     http.StatusOK,
			wantDeleted:    0,
			wantFailed:     1,
			checkFilesLeft: 0,
		},
		{
			name:           "empty filenames",
			requestBody:    BatchDeleteRequest{Filenames: []string{}},
			wantStatus:     http.StatusBadRequest,
			wantDeleted:    0,
			wantFailed:     0,
			checkFilesLeft: 0,
		},
		{
			name:           "directory traversal attempt",
			requestBody:    BatchDeleteRequest{Filenames: []string{"../secret.txt"}},
			wantStatus:     http.StatusOK,
			wantDeleted:    0,
			wantFailed:     1,
			checkFilesLeft: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			body, _ := json.Marshal(tt.requestBody)
			req := httptest.NewRequest(http.MethodDelete, "/api/recordings", bytes.NewReader(body))
			req.Header.Set("Content-Type", "application/json")

			rr := httptest.NewRecorder()
			s.handleRecordingsBatchDelete(rr, req)

			if rr.Code != tt.wantStatus {
				t.Errorf("status = %d, want %d", rr.Code, tt.wantStatus)
			}

			if tt.wantStatus == http.StatusOK {
				var resp BatchDeleteResponse
				if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
					t.Fatalf("failed to unmarshal response: %v", err)
				}

				if len(resp.Deleted) != tt.wantDeleted {
					t.Errorf("deleted count = %d, want %d", len(resp.Deleted), tt.wantDeleted)
				}

				if len(resp.Failed) != tt.wantFailed {
					t.Errorf("failed count = %d, want %d", len(resp.Failed), tt.wantFailed)
				}
			}
		})
	}
}

func TestHandleRecordingsBatchDeleteValidation(t *testing.T) {
	t.Parallel()

	tmpDir, err := os.MkdirTemp("", "recordings-validation-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer func() { _ = os.RemoveAll(tmpDir) }()

	s := newTestServer(t, tmpDir)

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
			body, _ := json.Marshal(BatchDeleteRequest{Filenames: tt.filenames})
			req := httptest.NewRequest(http.MethodDelete, "/api/recordings", bytes.NewReader(body))
			req.Header.Set("Content-Type", "application/json")

			rr := httptest.NewRecorder()
			s.handleRecordingsBatchDelete(rr, req)

			var resp BatchDeleteResponse
			if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
				t.Fatalf("failed to unmarshal response: %v", err)
			}

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

	s := &Server{
		recordingCfg: config.RecordingConfig{
			Enabled:   false,
			LocalPath: "",
		},
	}

	body, _ := json.Marshal(BatchDeleteRequest{Filenames: []string{"test.cast"}})
	req := httptest.NewRequest(http.MethodDelete, "/api/recordings", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")

	rr := httptest.NewRecorder()
	s.handleRecordingsBatchDelete(rr, req)

	if rr.Code != http.StatusNotFound {
		t.Errorf("status = %d, want %d", rr.Code, http.StatusNotFound)
	}
}

func TestHandleRecordingsBatchDeleteMaxLimit(t *testing.T) {
	t.Parallel()

	tmpDir, err := os.MkdirTemp("", "recordings-limit-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer func() { _ = os.RemoveAll(tmpDir) }()

	s := newTestServer(t, tmpDir)

	// Create a request with more than maxBatchSize files.
	filenames := make([]string, 101)
	for i := range filenames {
		filenames[i] = "file" + string(rune('0'+i%10)) + ".cast"
	}

	body, _ := json.Marshal(BatchDeleteRequest{Filenames: filenames})
	req := httptest.NewRequest(http.MethodDelete, "/api/recordings", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")

	rr := httptest.NewRecorder()
	s.handleRecordingsBatchDelete(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want %d", rr.Code, http.StatusBadRequest)
	}
}
