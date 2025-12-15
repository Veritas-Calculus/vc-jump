package config

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestDefaultConfig(t *testing.T) {
	cfg := DefaultConfig()
	if cfg == nil {
		t.Fatal("DefaultConfig returned nil")
	}

	if cfg.Server.ListenAddr != ":2222" {
		t.Errorf("expected listen addr :2222, got %s", cfg.Server.ListenAddr)
	}
	if cfg.Server.MaxConnections != 100 {
		t.Errorf("expected max connections 100, got %d", cfg.Server.MaxConnections)
	}
	if cfg.Auth.CacheDuration != 24*time.Hour {
		t.Errorf("expected cache duration 24h, got %v", cfg.Auth.CacheDuration)
	}
	if cfg.Recording.Enabled != true {
		t.Error("expected recording to be enabled by default")
	}
}

func TestLoadEmptyPath(t *testing.T) {
	_, err := Load("")
	if err == nil {
		t.Error("expected error for empty path")
	}
}

func TestLoadNonExistentFile(t *testing.T) {
	cfg, err := Load("/non/existent/path/config.yaml")
	if err != nil {
		t.Fatalf("unexpected error for non-existent file: %v", err)
	}
	if cfg == nil {
		t.Fatal("expected default config for non-existent file")
	}
}

func TestLoadValidConfig(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.yaml")

	configContent := `
server:
  listen_addr: ":3333"
  host_key_path: "./test_key"
  max_connections: 50
auth:
  cache_duration: 12h
  cache_path: "./test_cache"
session:
  idle_timeout: 15m
  max_duration: 4h
recording:
  enabled: false
  store_path: "./test_recordings"
hosts:
  - name: "test-server"
    addr: "10.0.0.1"
    port: 22
`
	if err := os.WriteFile(configPath, []byte(configContent), 0644); err != nil {
		t.Fatalf("failed to write test config: %v", err)
	}

	cfg, err := Load(configPath)
	if err != nil {
		t.Fatalf("failed to load config: %v", err)
	}

	if cfg.Server.ListenAddr != ":3333" {
		t.Errorf("expected listen addr :3333, got %s", cfg.Server.ListenAddr)
	}
	if cfg.Server.MaxConnections != 50 {
		t.Errorf("expected max connections 50, got %d", cfg.Server.MaxConnections)
	}
	if cfg.Recording.Enabled != false {
		t.Error("expected recording to be disabled")
	}
	if len(cfg.Hosts) != 1 {
		t.Errorf("expected 1 host, got %d", len(cfg.Hosts))
	}
	if cfg.Hosts[0].Name != "test-server" {
		t.Errorf("expected host name test-server, got %s", cfg.Hosts[0].Name)
	}
}

func TestValidateEmptyListenAddr(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Server.ListenAddr = ""
	err := cfg.Validate()
	if err == nil {
		t.Error("expected validation error for empty listen addr")
	}
}

func TestValidateNegativeMaxConnections(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Server.MaxConnections = -1
	err := cfg.Validate()
	if err == nil {
		t.Error("expected validation error for negative max connections")
	}
}

func TestValidateZeroCacheDuration(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Auth.CacheDuration = 0
	err := cfg.Validate()
	if err == nil {
		t.Error("expected validation error for zero cache duration")
	}
}

func TestValidateRecordingWithoutStorePath(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Recording.Enabled = true
	cfg.Recording.LocalPath = ""
	err := cfg.Validate()
	if err == nil {
		t.Error("expected validation error for recording without store path")
	}
}

func TestValidateHostWithoutName(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Hosts = []HostConfig{
		{Name: "", Addr: "10.0.0.1", Port: 22},
	}
	err := cfg.Validate()
	if err == nil {
		t.Error("expected validation error for host without name")
	}
}

func TestValidateHostWithoutAddr(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Hosts = []HostConfig{
		{Name: "test", Addr: "", Port: 22},
	}
	err := cfg.Validate()
	if err == nil {
		t.Error("expected validation error for host without addr")
	}
}

func TestValidateHostInvalidPort(t *testing.T) {
	tests := []struct {
		name string
		port int
	}{
		{"zero port", 0},
		{"negative port", -1},
		{"port too high", 65536},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := DefaultConfig()
			cfg.Hosts = []HostConfig{
				{Name: "test", Addr: "10.0.0.1", Port: tt.port},
			}
			err := cfg.Validate()
			if err == nil {
				t.Errorf("expected validation error for %s", tt.name)
			}
		})
	}
}

func TestLoadInvalidYAML(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "invalid.yaml")

	invalidContent := `
server:
  listen_addr: ":3333"
  invalid_yaml: [unclosed
`
	if err := os.WriteFile(configPath, []byte(invalidContent), 0644); err != nil {
		t.Fatalf("failed to write test config: %v", err)
	}

	_, err := Load(configPath)
	if err == nil {
		t.Error("expected error for invalid YAML")
	}
}
