package audit

import (
	"context"
	"testing"
	"time"

	"github.com/Veritas-Calculus/vc-jump/internal/config"
)

func TestNewAuditorDisabled(t *testing.T) {
	cfg := config.AuditConfig{
		Enabled: false,
	}

	_, err := New(cfg)
	if err == nil {
		t.Error("expected error for disabled audit")
	}
}

func TestNewAuditorLocal(t *testing.T) {
	tmpDir := t.TempDir()
	cfg := config.AuditConfig{
		Enabled:       true,
		StorageType:   "local",
		LocalPath:     tmpDir,
		RetentionDays: 30,
	}

	a, err := New(cfg)
	if err != nil {
		t.Fatalf("failed to create auditor: %v", err)
	}
	defer a.Close()

	if a == nil {
		t.Fatal("auditor is nil")
	}
}

func TestAuditorLogLogin(t *testing.T) {
	tmpDir := t.TempDir()
	cfg := config.AuditConfig{
		Enabled:     true,
		StorageType: "local",
		LocalPath:   tmpDir,
	}

	a, err := New(cfg)
	if err != nil {
		t.Fatalf("failed to create auditor: %v", err)
	}
	defer a.Close()

	a.LogLogin("testuser", "192.168.1.1", "success")

	// Allow time for async write.
	time.Sleep(100 * time.Millisecond)

	events, err := a.Query(context.Background(), QueryOptions{Username: "testuser"})
	if err != nil {
		t.Fatalf("query failed: %v", err)
	}

	if len(events) != 1 {
		t.Errorf("expected 1 event, got %d", len(events))
	}
}

func TestAuditorLogConnect(t *testing.T) {
	tmpDir := t.TempDir()
	cfg := config.AuditConfig{
		Enabled:     true,
		StorageType: "local",
		LocalPath:   tmpDir,
	}

	a, err := New(cfg)
	if err != nil {
		t.Fatalf("failed to create auditor: %v", err)
	}
	defer a.Close()

	a.LogConnect("testuser", "192.168.1.1", "server1", "success")

	time.Sleep(100 * time.Millisecond)

	events, err := a.Query(context.Background(), QueryOptions{
		EventType: EventConnect,
	})
	if err != nil {
		t.Fatalf("query failed: %v", err)
	}

	if len(events) != 1 {
		t.Errorf("expected 1 event, got %d", len(events))
	}
	if events[0].TargetHost != "server1" {
		t.Errorf("expected target host server1, got %s", events[0].TargetHost)
	}
}

func TestLocalStorageWrite(t *testing.T) {
	tmpDir := t.TempDir()
	storage, err := NewLocalStorage(tmpDir)
	if err != nil {
		t.Fatalf("failed to create storage: %v", err)
	}

	event := Event{
		ID:        "test-1",
		Timestamp: time.Now(),
		Type:      EventLogin,
		Username:  "testuser",
		SourceIP:  "192.168.1.1",
		Action:    "login",
		Result:    "success",
	}

	err = storage.Write(context.Background(), event)
	if err != nil {
		t.Fatalf("write failed: %v", err)
	}

	events, err := storage.Query(context.Background(), QueryOptions{})
	if err != nil {
		t.Fatalf("query failed: %v", err)
	}

	if len(events) != 1 {
		t.Errorf("expected 1 event, got %d", len(events))
	}
}

func TestQueryOptions(t *testing.T) {
	tmpDir := t.TempDir()
	storage, err := NewLocalStorage(tmpDir)
	if err != nil {
		t.Fatalf("failed to create storage: %v", err)
	}

	// Write multiple events.
	events := []Event{
		{ID: "1", Timestamp: time.Now(), Type: EventLogin, Username: "user1"},
		{ID: "2", Timestamp: time.Now(), Type: EventConnect, Username: "user2"},
		{ID: "3", Timestamp: time.Now(), Type: EventLogin, Username: "user1"},
	}

	for _, e := range events {
		storage.Write(context.Background(), e)
	}

	// Query by username.
	result, _ := storage.Query(context.Background(), QueryOptions{Username: "user1"})
	if len(result) != 2 {
		t.Errorf("expected 2 events for user1, got %d", len(result))
	}

	// Query by event type.
	result, _ = storage.Query(context.Background(), QueryOptions{EventType: EventConnect})
	if len(result) != 1 {
		t.Errorf("expected 1 connect event, got %d", len(result))
	}
}
