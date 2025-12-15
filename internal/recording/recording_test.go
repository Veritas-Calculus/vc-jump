package recording

import (
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
