package storage

import (
	"context"
	"testing"
	"time"

	"github.com/Veritas-Calculus/vc-jump/internal/config"
)

func TestNewFileStore(t *testing.T) {
	tmpDir := t.TempDir()
	cfg := config.StorageConfig{
		Type:     "file",
		FilePath: tmpDir,
	}

	s, err := NewFileStore(cfg)
	if err != nil {
		t.Fatalf("failed to create storage: %v", err)
	}
	defer s.Close()

	if s == nil {
		t.Fatal("storage is nil")
	}
}

func TestFileStoreHostCRUD(t *testing.T) {
	tmpDir := t.TempDir()
	cfg := config.StorageConfig{
		Type:     "file",
		FilePath: tmpDir,
	}

	s, err := NewFileStore(cfg)
	if err != nil {
		t.Fatalf("failed to create storage: %v", err)
	}
	defer s.Close()

	ctx := context.Background()

	host := &Host{
		ID:        "host-1",
		Name:      "server1",
		Addr:      "192.168.1.10",
		Port:      22,
		Users:     []string{"admin"},
		Groups:    []string{"web"},
		KeyPath:   "/path/to/key",
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}

	err = s.CreateHost(ctx, host)
	if err != nil {
		t.Fatalf("failed to create host: %v", err)
	}

	got, err := s.GetHost(ctx, "host-1")
	if err != nil {
		t.Fatalf("failed to get host: %v", err)
	}

	if got.Name != host.Name {
		t.Errorf("expected name %s, got %s", host.Name, got.Name)
	}
	if got.Addr != host.Addr {
		t.Errorf("expected addr %s, got %s", host.Addr, got.Addr)
	}

	got, err = s.GetHostByName(ctx, "server1")
	if err != nil {
		t.Fatalf("failed to get host by name: %v", err)
	}
	if got.ID != "host-1" {
		t.Errorf("expected id host-1, got %s", got.ID)
	}

	hosts, err := s.ListHosts(ctx)
	if err != nil {
		t.Fatalf("failed to list hosts: %v", err)
	}
	if len(hosts) != 1 {
		t.Errorf("expected 1 host, got %d", len(hosts))
	}

	host.Groups = append(host.Groups, "db")
	err = s.UpdateHost(ctx, host)
	if err != nil {
		t.Fatalf("failed to update host: %v", err)
	}

	got, _ = s.GetHost(ctx, "host-1")
	if len(got.Groups) != 2 {
		t.Errorf("expected 2 groups, got %d", len(got.Groups))
	}

	err = s.DeleteHost(ctx, "host-1")
	if err != nil {
		t.Fatalf("failed to delete host: %v", err)
	}

	_, err = s.GetHost(ctx, "host-1")
	if err == nil {
		t.Error("expected error for deleted host")
	}
}

func TestFileStoreUserCRUD(t *testing.T) {
	tmpDir := t.TempDir()
	cfg := config.StorageConfig{
		Type:     "file",
		FilePath: tmpDir,
	}

	s, err := NewFileStore(cfg)
	if err != nil {
		t.Fatalf("failed to create storage: %v", err)
	}
	defer s.Close()

	ctx := context.Background()

	user := &User{
		ID:         "user-1",
		Username:   "testuser",
		Groups:     []string{"admin", "dev"},
		PublicKeys: []string{"ssh-rsa AAAA..."},
		CreatedAt:  time.Now(),
		UpdatedAt:  time.Now(),
	}

	err = s.CreateUser(ctx, user)
	if err != nil {
		t.Fatalf("failed to create user: %v", err)
	}

	got, err := s.GetUser(ctx, "user-1")
	if err != nil {
		t.Fatalf("failed to get user: %v", err)
	}
	if got.Username != user.Username {
		t.Errorf("expected username %s, got %s", user.Username, got.Username)
	}

	got, err = s.GetUserByUsername(ctx, "testuser")
	if err != nil {
		t.Fatalf("failed to get user by username: %v", err)
	}
	if got.ID != "user-1" {
		t.Errorf("expected id user-1, got %s", got.ID)
	}

	users, err := s.ListUsers(ctx)
	if err != nil {
		t.Fatalf("failed to list users: %v", err)
	}
	if len(users) != 1 {
		t.Errorf("expected 1 user, got %d", len(users))
	}

	user.Groups = append(user.Groups, "ops")
	err = s.UpdateUser(ctx, user)
	if err != nil {
		t.Fatalf("failed to update user: %v", err)
	}

	got, _ = s.GetUser(ctx, "user-1")
	if len(got.Groups) != 3 {
		t.Errorf("expected 3 groups, got %d", len(got.Groups))
	}

	err = s.DeleteUser(ctx, "user-1")
	if err != nil {
		t.Fatalf("failed to delete user: %v", err)
	}

	_, err = s.GetUser(ctx, "user-1")
	if err == nil {
		t.Error("expected error for deleted user")
	}
}

func TestFileStoreSessionCRUD(t *testing.T) {
	tmpDir := t.TempDir()
	cfg := config.StorageConfig{
		Type:     "file",
		FilePath: tmpDir,
	}

	s, err := NewFileStore(cfg)
	if err != nil {
		t.Fatalf("failed to create storage: %v", err)
	}
	defer s.Close()

	ctx := context.Background()

	session := &Session{
		ID:         "session-1",
		Username:   "testuser",
		SourceIP:   "192.168.1.100",
		TargetHost: "server1",
		StartTime:  time.Now(),
	}

	err = s.CreateSession(ctx, session)
	if err != nil {
		t.Fatalf("failed to create session: %v", err)
	}

	got, err := s.GetSession(ctx, "session-1")
	if err != nil {
		t.Fatalf("failed to get session: %v", err)
	}
	if got.Username != session.Username {
		t.Errorf("expected username %s, got %s", session.Username, got.Username)
	}

	sessions, err := s.ListSessions(ctx, "testuser", 10)
	if err != nil {
		t.Fatalf("failed to list sessions: %v", err)
	}
	if len(sessions) != 1 {
		t.Errorf("expected 1 session, got %d", len(sessions))
	}

	session.EndTime = time.Now()
	session.Recording = "/path/to/recording"
	err = s.UpdateSession(ctx, session)
	if err != nil {
		t.Fatalf("failed to update session: %v", err)
	}

	got, _ = s.GetSession(ctx, "session-1")
	if got.Recording != "/path/to/recording" {
		t.Errorf("expected recording path, got %s", got.Recording)
	}
}

func TestFileStorePersistence(t *testing.T) {
	tmpDir := t.TempDir()
	cfg := config.StorageConfig{
		Type:     "file",
		FilePath: tmpDir,
	}

	s1, err := NewFileStore(cfg)
	if err != nil {
		t.Fatalf("failed to create storage: %v", err)
	}

	ctx := context.Background()
	host := &Host{
		ID:   "host-1",
		Name: "server1",
		Addr: "192.168.1.10",
		Port: 22,
	}
	s1.CreateHost(ctx, host)
	s1.Close()

	s2, err := NewFileStore(cfg)
	if err != nil {
		t.Fatalf("failed to create second storage: %v", err)
	}
	defer s2.Close()

	got, err := s2.GetHost(ctx, "host-1")
	if err != nil {
		t.Fatalf("failed to get host from new storage: %v", err)
	}
	if got.Name != "server1" {
		t.Errorf("expected name server1, got %s", got.Name)
	}
}

func TestGetHostNotFound(t *testing.T) {
	tmpDir := t.TempDir()
	cfg := config.StorageConfig{Type: "file", FilePath: tmpDir}
	s, _ := NewFileStore(cfg)
	defer s.Close()

	_, err := s.GetHost(context.Background(), "nonexistent")
	if err == nil {
		t.Error("expected error for nonexistent host")
	}
}

func TestGetUserNotFound(t *testing.T) {
	tmpDir := t.TempDir()
	cfg := config.StorageConfig{Type: "file", FilePath: tmpDir}
	s, _ := NewFileStore(cfg)
	defer s.Close()

	_, err := s.GetUser(context.Background(), "nonexistent")
	if err == nil {
		t.Error("expected error for nonexistent user")
	}
}

func TestGetSessionNotFound(t *testing.T) {
	tmpDir := t.TempDir()
	cfg := config.StorageConfig{Type: "file", FilePath: tmpDir}
	s, _ := NewFileStore(cfg)
	defer s.Close()

	_, err := s.GetSession(context.Background(), "nonexistent")
	if err == nil {
		t.Error("expected error for nonexistent session")
	}
}

func TestEmptyFilePathError(t *testing.T) {
	cfg := config.StorageConfig{Type: "file", FilePath: ""}
	_, err := NewFileStore(cfg)
	if err == nil {
		t.Error("expected error for empty file path")
	}
}
