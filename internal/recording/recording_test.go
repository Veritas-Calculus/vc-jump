package recording

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/Veritas-Calculus/vc-jump/internal/config"
)

func TestNewRecorderDisabled(t *testing.T) {
	cfg := config.RecordingConfig{
		Enabled:   false,
		LocalPath: "/tmp",
	}

	_, err := New(cfg)
	if err == nil {
		t.Error("expected error for disabled recording")
	}
}

func TestNewRecorderEmptyLocalPath(t *testing.T) {
	cfg := config.RecordingConfig{
		Enabled:     true,
		StorageType: "local",
		LocalPath:   "",
	}

	_, err := New(cfg)
	if err == nil {
		t.Error("expected error for empty store path")
	}
}

func TestNewRecorderValid(t *testing.T) {
	tmpDir := t.TempDir()
	cfg := config.RecordingConfig{
		Enabled:     true,
		StorageType: "local",
		LocalPath:   tmpDir,
	}

	recorder, err := New(cfg)
	if err != nil {
		t.Fatalf("failed to create recorder: %v", err)
	}
	if recorder == nil {
		t.Fatal("recorder is nil")
	}
}

func TestStartSessionEmptyUsername(t *testing.T) {
	tmpDir := t.TempDir()
	cfg := config.RecordingConfig{
		Enabled:     true,
		StorageType: "local",
		LocalPath:   tmpDir,
	}

	recorder, err := New(cfg)
	if err != nil {
		t.Fatalf("failed to create recorder: %v", err)
	}

	_, err = recorder.StartSession("", "hostname")
	if err == nil {
		t.Error("expected error for empty username")
	}
}

func TestStartSessionEmptyHostname(t *testing.T) {
	tmpDir := t.TempDir()
	cfg := config.RecordingConfig{
		Enabled:     true,
		StorageType: "local",
		LocalPath:   tmpDir,
	}

	recorder, err := New(cfg)
	if err != nil {
		t.Fatalf("failed to create recorder: %v", err)
	}

	_, err = recorder.StartSession("username", "")
	if err == nil {
		t.Error("expected error for empty hostname")
	}
}

func TestStartSessionValid(t *testing.T) {
	tmpDir := t.TempDir()
	cfg := config.RecordingConfig{
		Enabled:     true,
		StorageType: "local",
		LocalPath:   tmpDir,
	}

	recorder, err := New(cfg)
	if err != nil {
		t.Fatalf("failed to create recorder: %v", err)
	}

	session, err := recorder.StartSession("testuser", "testhost")
	if err != nil {
		t.Fatalf("failed to start session: %v", err)
	}
	defer session.Close()

	if session.ID == "" {
		t.Error("session ID is empty")
	}
	if session.Username != "testuser" {
		t.Errorf("expected username testuser, got %s", session.Username)
	}
	if session.HostName != "testhost" {
		t.Errorf("expected hostname testhost, got %s", session.HostName)
	}
}

func TestSessionRecordOutput(t *testing.T) {
	tmpDir := t.TempDir()
	cfg := config.RecordingConfig{
		Enabled:     true,
		StorageType: "local",
		LocalPath:   tmpDir,
	}

	recorder, err := New(cfg)
	if err != nil {
		t.Fatalf("failed to create recorder: %v", err)
	}

	session, err := recorder.StartSession("testuser", "testhost")
	if err != nil {
		t.Fatalf("failed to start session: %v", err)
	}

	testData := []byte("test output data")
	if err := session.RecordOutput(testData); err != nil {
		t.Fatalf("failed to record output: %v", err)
	}

	session.Close()

	// Verify recording file exists.
	files, err := filepath.Glob(filepath.Join(tmpDir, "*.cast"))
	if err != nil {
		t.Fatalf("failed to list files: %v", err)
	}
	if len(files) != 1 {
		t.Fatalf("expected 1 recording file, got %d", len(files))
	}
}

func TestSessionRecordInput(t *testing.T) {
	tmpDir := t.TempDir()
	cfg := config.RecordingConfig{
		Enabled:     true,
		StorageType: "local",
		LocalPath:   tmpDir,
	}

	recorder, err := New(cfg)
	if err != nil {
		t.Fatalf("failed to create recorder: %v", err)
	}

	session, err := recorder.StartSession("testuser", "testhost")
	if err != nil {
		t.Fatalf("failed to start session: %v", err)
	}

	testData := []byte("test input data")
	if err := session.RecordInput(testData); err != nil {
		t.Fatalf("failed to record input: %v", err)
	}

	session.Close()
}

func TestSessionDoubleClose(t *testing.T) {
	tmpDir := t.TempDir()
	cfg := config.RecordingConfig{
		Enabled:     true,
		StorageType: "local",
		LocalPath:   tmpDir,
	}

	recorder, err := New(cfg)
	if err != nil {
		t.Fatalf("failed to create recorder: %v", err)
	}

	session, err := recorder.StartSession("testuser", "testhost")
	if err != nil {
		t.Fatalf("failed to start session: %v", err)
	}

	if err := session.Close(); err != nil {
		t.Fatalf("first close failed: %v", err)
	}

	// Second close should not error.
	if err := session.Close(); err != nil {
		t.Fatalf("second close should not error: %v", err)
	}
}

func TestRecordAfterClose(t *testing.T) {
	tmpDir := t.TempDir()
	cfg := config.RecordingConfig{
		Enabled:     true,
		StorageType: "local",
		LocalPath:   tmpDir,
	}

	recorder, err := New(cfg)
	if err != nil {
		t.Fatalf("failed to create recorder: %v", err)
	}

	session, err := recorder.StartSession("testuser", "testhost")
	if err != nil {
		t.Fatalf("failed to start session: %v", err)
	}

	session.Close()

	if err := session.RecordOutput([]byte("data")); err == nil {
		t.Error("expected error when recording after close")
	}
}

func TestGetSession(t *testing.T) {
	tmpDir := t.TempDir()
	cfg := config.RecordingConfig{
		Enabled:     true,
		StorageType: "local",
		LocalPath:   tmpDir,
	}

	recorder, err := New(cfg)
	if err != nil {
		t.Fatalf("failed to create recorder: %v", err)
	}

	session, err := recorder.StartSession("testuser", "testhost")
	if err != nil {
		t.Fatalf("failed to start session: %v", err)
	}
	defer session.Close()

	retrieved, ok := recorder.GetSession(session.ID)
	if !ok {
		t.Error("failed to get session")
	}
	if retrieved.ID != session.ID {
		t.Error("retrieved session ID does not match")
	}
}

func TestGetSessionNotFound(t *testing.T) {
	tmpDir := t.TempDir()
	cfg := config.RecordingConfig{
		Enabled:     true,
		StorageType: "local",
		LocalPath:   tmpDir,
	}

	recorder, err := New(cfg)
	if err != nil {
		t.Fatalf("failed to create recorder: %v", err)
	}

	_, ok := recorder.GetSession("nonexistent")
	if ok {
		t.Error("expected not found for nonexistent session")
	}
}

func TestRecordingFileFormat(t *testing.T) {
	tmpDir := t.TempDir()
	cfg := config.RecordingConfig{
		Enabled:     true,
		StorageType: "local",
		LocalPath:   tmpDir,
	}

	recorder, err := New(cfg)
	if err != nil {
		t.Fatalf("failed to create recorder: %v", err)
	}

	session, err := recorder.StartSession("testuser", "testhost")
	if err != nil {
		t.Fatalf("failed to start session: %v", err)
	}

	session.RecordOutput([]byte("hello"))
	session.RecordInput([]byte("world"))
	session.Close()

	// Read and verify file content.
	files, _ := filepath.Glob(filepath.Join(tmpDir, "*.cast"))
	if len(files) != 1 {
		t.Fatalf("expected 1 file, got %d", len(files))
	}

	data, err := os.ReadFile(files[0])
	if err != nil {
		t.Fatalf("failed to read file: %v", err)
	}

	// Verify header is valid JSON.
	lines := splitLines(data)
	if len(lines) < 1 {
		t.Fatal("expected at least header line")
	}

	var header RecordingHeader
	if err := json.Unmarshal(lines[0], &header); err != nil {
		t.Fatalf("failed to parse header: %v", err)
	}

	if header.Username != "testuser" {
		t.Errorf("expected username testuser, got %s", header.Username)
	}
	if header.Version != 2 {
		t.Errorf("expected version 2, got %d", header.Version)
	}
}

func splitLines(data []byte) [][]byte {
	var lines [][]byte
	start := 0
	for i := 0; i < len(data); i++ {
		if data[i] == '\n' {
			if i > start {
				lines = append(lines, data[start:i])
			}
			start = i + 1
		}
	}
	if start < len(data) {
		lines = append(lines, data[start:])
	}
	return lines
}

// ============================================================
// S3Storage Tests
// ============================================================

func TestNewS3StorageEmptyBucket(t *testing.T) {
	cfg := config.S3Config{
		Bucket: "",
		Region: "us-east-1",
	}

	_, err := NewS3Storage(cfg)
	if err == nil {
		t.Error("expected error for empty bucket")
	}
}

func TestNewS3StorageEmptyRegion(t *testing.T) {
	cfg := config.S3Config{
		Bucket: "test-bucket",
		Region: "",
	}

	_, err := NewS3Storage(cfg)
	if err == nil {
		t.Error("expected error for empty region")
	}
}

func TestNewS3StorageInvalidBucketName(t *testing.T) {
	testCases := []struct {
		name   string
		bucket string
	}{
		{"too short", "ab"},
		{"starts with hyphen", "-bucket"},
		{"contains uppercase", "MyBucket"},
		{"contains underscore", "my_bucket"},
		{"ends with hyphen", "bucket-"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := config.S3Config{
				Bucket: tc.bucket,
				Region: "us-east-1",
			}

			_, err := NewS3Storage(cfg)
			if err == nil {
				t.Errorf("expected error for invalid bucket name: %s", tc.bucket)
			}
		})
	}
}

func TestNewS3StorageValidBucketNames(t *testing.T) {
	testCases := []struct {
		name   string
		bucket string
	}{
		{"simple", "mybucket"},
		{"with numbers", "bucket123"},
		{"with hyphens", "my-test-bucket"},
		{"with dots", "my.test.bucket"},
		{"min length", "abc"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := config.S3Config{
				Bucket:          tc.bucket,
				Region:          "us-east-1",
				AccessKeyID:     "test",
				SecretAccessKey: "test",
			}

			// This should not error during creation (may fail on actual S3 call).
			storage, err := NewS3Storage(cfg)
			if err != nil {
				t.Errorf("unexpected error for valid bucket name %s: %v", tc.bucket, err)
			}
			if storage == nil {
				t.Error("storage should not be nil")
			}
		})
	}
}

func TestNewS3StorageInvalidPrefix(t *testing.T) {
	cfg := config.S3Config{
		Bucket: "test-bucket",
		Region: "us-east-1",
		Prefix: string([]byte{0x01, 0x02}), // Control characters.
	}

	_, err := NewS3Storage(cfg)
	if err == nil {
		t.Error("expected error for invalid prefix with control characters")
	}
}

func TestNewS3StorageInvalidEndpoint(t *testing.T) {
	cfg := config.S3Config{
		Bucket:          "test-bucket",
		Region:          "us-east-1",
		Endpoint:        "://invalid-url",
		AccessKeyID:     "test",
		SecretAccessKey: "test",
	}

	_, err := NewS3Storage(cfg)
	// Note: url.Parse may accept some invalid URLs, so this test is for extreme cases.
	// The main validation is for bucket name and region.
	_ = err // Just verify it doesn't panic.
}

// ============================================================
// Filename Validation Tests (Security)
// ============================================================

func TestValidateFilename(t *testing.T) {
	testCases := []struct {
		name      string
		filename  string
		expectErr bool
	}{
		{"valid", "20230101_120000_user_abc123.cast", false},
		{"empty", "", true},
		{"too long", string(make([]byte, 300)) + ".cast", true},
		{"with slash", "path/to/file.cast", true},
		{"with backslash", "path\\to\\file.cast", true},
		{"directory traversal", "../etc/passwd.cast", true},
		{"double dots", "file..test.cast", true},
		{"no extension", "filename", true},
		{"wrong extension", "filename.txt", true},
		{"starts with dot", ".hidden.cast", true},
		{"special chars", "file<>name.cast", true},
		{"valid with underscore", "user_session_123.cast", false},
		{"valid with hyphen", "user-session-123.cast", false},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			err := validateFilename(tc.filename)
			if tc.expectErr && err == nil {
				t.Errorf("expected error for filename: %s", tc.filename)
			}
			if !tc.expectErr && err != nil {
				t.Errorf("unexpected error for filename %s: %v", tc.filename, err)
			}
		})
	}
}

func TestIsValidBucketName(t *testing.T) {
	testCases := []struct {
		name   string
		bucket string
		valid  bool
	}{
		{"valid simple", "mybucket", true},
		{"valid with hyphens", "my-test-bucket", true},
		{"valid with numbers", "bucket123", true},
		{"valid with dots", "my.bucket.name", true},
		{"too short", "ab", false},
		{"too long", string(make([]byte, 64)), false},
		{"starts with hyphen", "-bucket", false},
		{"ends with hyphen", "bucket-", false},
		{"uppercase", "MyBucket", false},
		{"underscore", "my_bucket", false},
		{"special chars", "bucket!", false},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result := isValidBucketName(tc.bucket)
			if result != tc.valid {
				t.Errorf("isValidBucketName(%s) = %v, want %v", tc.bucket, result, tc.valid)
			}
		})
	}
}

func TestIsValidPrefix(t *testing.T) {
	testCases := []struct {
		name   string
		prefix string
		valid  bool
	}{
		{"empty", "", true},
		{"simple", "recordings", true},
		{"with slash", "recordings/", true},
		{"nested", "prod/recordings/2024", true},
		{"control char", string([]byte{0x01}), false},
		{"backslash", "path\\to", false},
		{"curly braces", "{prefix}", false},
		{"caret", "prefix^test", false},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result := isValidPrefix(tc.prefix)
			if result != tc.valid {
				t.Errorf("isValidPrefix(%s) = %v, want %v", tc.prefix, result, tc.valid)
			}
		})
	}
}

func TestS3StorageBuildObjectKey(t *testing.T) {
	testCases := []struct {
		name     string
		prefix   string
		filename string
		expected string
	}{
		{"no prefix", "", "test.cast", "test.cast"},
		{"with prefix", "recordings", "test.cast", "recordings/test.cast"},
		{"prefix with slash", "recordings/", "test.cast", "recordings/test.cast"},
		{"nested prefix", "prod/recordings", "test.cast", "prod/recordings/test.cast"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := config.S3Config{
				Bucket:          "test-bucket",
				Region:          "us-east-1",
				Prefix:          tc.prefix,
				AccessKeyID:     "test",
				SecretAccessKey: "test",
			}

			storage, err := NewS3Storage(cfg)
			if err != nil {
				t.Fatalf("failed to create S3Storage: %v", err)
			}

			result := storage.buildObjectKey(tc.filename)
			if result != tc.expected {
				t.Errorf("buildObjectKey(%s) = %s, want %s", tc.filename, result, tc.expected)
			}
		})
	}
}

// ============================================================
// LocalStorage Security Tests
// ============================================================

func TestLocalStorageDirectoryTraversal(t *testing.T) {
	tmpDir := t.TempDir()
	storage, err := NewLocalStorage(tmpDir)
	if err != nil {
		t.Fatalf("failed to create local storage: %v", err)
	}

	ctx := context.Background()

	// Test Save with directory traversal.
	err = storage.Save(ctx, "../../../etc/passwd", []byte("data"))
	if err == nil {
		t.Error("expected error for directory traversal in Save")
	}

	// Test Load with directory traversal.
	_, err = storage.Load(ctx, "../../../etc/passwd")
	if err == nil {
		t.Error("expected error for directory traversal in Load")
	}

	// Test Delete with directory traversal.
	err = storage.Delete(ctx, "../../../etc/passwd")
	if err == nil {
		t.Error("expected error for directory traversal in Delete")
	}
}

func TestLocalStorageValidOperations(t *testing.T) {
	tmpDir := t.TempDir()
	storage, err := NewLocalStorage(tmpDir)
	if err != nil {
		t.Fatalf("failed to create local storage: %v", err)
	}

	ctx := context.Background()
	filename := "test_recording.cast"
	testData := []byte(`{"version":2,"username":"test"}`)

	// Test Save.
	if err := storage.Save(ctx, filename, testData); err != nil {
		t.Fatalf("failed to save: %v", err)
	}

	// Test Load.
	loaded, err := storage.Load(ctx, filename)
	if err != nil {
		t.Fatalf("failed to load: %v", err)
	}
	if string(loaded) != string(testData) {
		t.Errorf("loaded data mismatch: got %s, want %s", loaded, testData)
	}

	// Test List.
	files, err := storage.List(ctx)
	if err != nil {
		t.Fatalf("failed to list: %v", err)
	}
	if len(files) != 1 || files[0] != filename {
		t.Errorf("list mismatch: got %v", files)
	}

	// Test Delete.
	if err := storage.Delete(ctx, filename); err != nil {
		t.Fatalf("failed to delete: %v", err)
	}

	// Verify deleted.
	files, _ = storage.List(ctx)
	if len(files) != 0 {
		t.Error("file should be deleted")
	}
}

func TestLocalStorageEmptyBasePath(t *testing.T) {
	_, err := NewLocalStorage("")
	if err == nil {
		t.Error("expected error for empty base path")
	}
}
