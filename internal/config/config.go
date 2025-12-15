// Package config provides configuration loading and validation for vc-jump.
package config

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"gopkg.in/yaml.v3"
)

// Config holds all configuration for the vc-jump server.
type Config struct {
	Server    ServerConfig    `yaml:"server"`
	Auth      AuthConfig      `yaml:"auth"`
	Session   SessionConfig   `yaml:"session"`
	Hosts     []HostConfig    `yaml:"hosts"`
	Recording RecordingConfig `yaml:"recording"`
	Logging   LoggingConfig   `yaml:"logging"`
	Audit     AuditConfig     `yaml:"audit"`
	Storage   StorageConfig   `yaml:"storage"`
	Dashboard DashboardConfig `yaml:"dashboard"`
}

// ServerConfig holds SSH server configuration.
type ServerConfig struct {
	ListenAddr     string `yaml:"listen_addr"`
	HostKeyPath    string `yaml:"host_key_path"`
	MaxConnections int    `yaml:"max_connections"`
}

// AuthConfig holds authentication configuration.
type AuthConfig struct {
	SSOEndpoint          string        `yaml:"sso_endpoint"`
	CacheDuration        time.Duration `yaml:"cache_duration"`
	CachePath            string        `yaml:"cache_path"`
	AllowSSHAutoRegister bool          `yaml:"allow_ssh_auto_register"` // If true, auto-create users on first SSH login.
}

// SessionConfig holds session management configuration.
type SessionConfig struct {
	IdleTimeout time.Duration `yaml:"idle_timeout"`
	MaxDuration time.Duration `yaml:"max_duration"`
}

// HostConfig defines a target host configuration.
type HostConfig struct {
	Name           string   `yaml:"name"`
	Addr           string   `yaml:"addr"`
	Port           int      `yaml:"port"`
	Users          []string `yaml:"users"`
	Groups         []string `yaml:"groups"`
	KeyPath        string   `yaml:"key_path"`
	KnownHostsPath string   `yaml:"known_hosts_path"` // Path to known_hosts file for host key verification.
}

// RecordingConfig holds session recording configuration.
type RecordingConfig struct {
	Enabled     bool     `yaml:"enabled"`
	StorageType string   `yaml:"storage_type"` // "local" or "s3"
	LocalPath   string   `yaml:"local_path"`
	S3Config    S3Config `yaml:"s3"`
}

// S3Config holds S3 storage configuration.
type S3Config struct {
	Endpoint        string `yaml:"endpoint"`
	Bucket          string `yaml:"bucket"`
	Region          string `yaml:"region"`
	AccessKeyID     string `yaml:"access_key_id"`
	SecretAccessKey string `yaml:"secret_access_key"`
	UseSSL          bool   `yaml:"use_ssl"`
}

// LoggingConfig holds logging configuration.
type LoggingConfig struct {
	Level         string `yaml:"level"`  // debug, info, warn, error
	Format        string `yaml:"format"` // json, text
	Output        string `yaml:"output"` // stdout, file
	FilePath      string `yaml:"file_path"`
	RetentionDays int    `yaml:"retention_days"`
	MaxSizeMB     int    `yaml:"max_size_mb"`
	MaxBackups    int    `yaml:"max_backups"`
}

// AuditConfig holds audit logging configuration.
type AuditConfig struct {
	Enabled       bool     `yaml:"enabled"`
	StorageType   string   `yaml:"storage_type"` // "local" or "s3"
	LocalPath     string   `yaml:"local_path"`
	S3Config      S3Config `yaml:"s3"`
	RetentionDays int      `yaml:"retention_days"`
}

// StorageConfig holds data persistence configuration.
type StorageConfig struct {
	Type     string `yaml:"type"`      // "file" or "sqlite"
	FilePath string `yaml:"file_path"` // For file-based storage
	DBPath   string `yaml:"db_path"`   // For SQLite storage
}

// DashboardConfig holds dashboard configuration.
type DashboardConfig struct {
	Enabled        bool   `yaml:"enabled"`
	ListenAddr     string `yaml:"listen_addr"`
	Username       string `yaml:"username"`
	Password       string `yaml:"password"`
	EnableHTTPS    bool   `yaml:"enable_https"`
	CertFile       string `yaml:"cert_file"`
	KeyFile        string `yaml:"key_file"`
	SessionTimeout string `yaml:"session_timeout"`
}

// DefaultConfig returns a Config with sensible defaults.
func DefaultConfig() *Config {
	return &Config{
		Server: ServerConfig{
			ListenAddr:     ":2222",
			HostKeyPath:    "./host_key",
			MaxConnections: 100,
		},
		Auth: AuthConfig{
			CacheDuration: 24 * time.Hour,
			CachePath:     "./cache",
		},
		Session: SessionConfig{
			IdleTimeout: 30 * time.Minute,
			MaxDuration: 8 * time.Hour,
		},
		Recording: RecordingConfig{
			Enabled:     true,
			StorageType: "local",
			LocalPath:   "./recordings",
		},
		Logging: LoggingConfig{
			Level:         "info",
			Format:        "json",
			Output:        "stdout",
			RetentionDays: 30,
			MaxSizeMB:     100,
			MaxBackups:    5,
		},
		Audit: AuditConfig{
			Enabled:       true,
			StorageType:   "local",
			LocalPath:     "./audit",
			RetentionDays: 90,
		},
		Storage: StorageConfig{
			Type:     "sqlite",
			FilePath: "./data",
			DBPath:   "./data/vc-jump.db",
		},
		Dashboard: DashboardConfig{
			Enabled:        true,
			ListenAddr:     ":8080",
			EnableHTTPS:    false,
			SessionTimeout: "24h",
		},
	}
}

// Load reads configuration from the specified file path.
// If the file does not exist, it returns default configuration.
func Load(path string) (*Config, error) {
	if path == "" {
		return nil, errors.New("config path cannot be empty")
	}

	// Clean and validate the path.
	cleanPath := filepath.Clean(path)

	cfg := DefaultConfig()

	data, err := os.ReadFile(cleanPath)
	if err != nil {
		if os.IsNotExist(err) {
			return cfg, nil
		}
		return nil, fmt.Errorf("failed to read config file: %w", err)
	}

	if err := yaml.Unmarshal(data, cfg); err != nil {
		return nil, fmt.Errorf("failed to parse config file: %w", err)
	}

	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("invalid configuration: %w", err)
	}

	return cfg, nil
}

// Validate checks the configuration for errors.
func (c *Config) Validate() error {
	if c.Server.ListenAddr == "" {
		return errors.New("server.listen_addr is required")
	}
	if c.Server.MaxConnections <= 0 {
		return errors.New("server.max_connections must be positive")
	}
	if c.Auth.CacheDuration <= 0 {
		return errors.New("auth.cache_duration must be positive")
	}
	if c.Session.IdleTimeout <= 0 {
		return errors.New("session.idle_timeout must be positive")
	}
	if c.Session.MaxDuration <= 0 {
		return errors.New("session.max_duration must be positive")
	}

	// Validate recording configuration.
	if c.Recording.Enabled {
		if c.Recording.StorageType != "local" && c.Recording.StorageType != "s3" {
			return errors.New("recording.storage_type must be 'local' or 's3'")
		}
		if c.Recording.StorageType == "local" && c.Recording.LocalPath == "" {
			return errors.New("recording.local_path is required when storage_type is 'local'")
		}
		if c.Recording.StorageType == "s3" {
			if c.Recording.S3Config.Bucket == "" {
				return errors.New("recording.s3.bucket is required when storage_type is 's3'")
			}
		}
	}

	// Validate logging configuration.
	validLogLevels := map[string]bool{"debug": true, "info": true, "warn": true, "error": true}
	if !validLogLevels[c.Logging.Level] {
		return errors.New("logging.level must be one of: debug, info, warn, error")
	}
	validLogFormats := map[string]bool{"json": true, "text": true}
	if !validLogFormats[c.Logging.Format] {
		return errors.New("logging.format must be 'json' or 'text'")
	}

	// Validate audit configuration.
	if c.Audit.Enabled {
		if c.Audit.StorageType != "local" && c.Audit.StorageType != "s3" {
			return errors.New("audit.storage_type must be 'local' or 's3'")
		}
		if c.Audit.StorageType == "local" && c.Audit.LocalPath == "" {
			return errors.New("audit.local_path is required when storage_type is 'local'")
		}
	}

	// Validate storage configuration.
	if c.Storage.Type != "file" && c.Storage.Type != "sqlite" {
		return errors.New("storage.type must be 'file' or 'sqlite'")
	}
	if c.Storage.Type == "file" && c.Storage.FilePath == "" {
		return errors.New("storage.file_path is required when type is 'file'")
	}
	if c.Storage.Type == "sqlite" && c.Storage.DBPath == "" {
		return errors.New("storage.db_path is required when type is 'sqlite'")
	}

	for i, h := range c.Hosts {
		if h.Name == "" {
			return fmt.Errorf("hosts[%d].name is required", i)
		}
		if h.Addr == "" {
			return fmt.Errorf("hosts[%d].addr is required", i)
		}
		if h.Port <= 0 || h.Port > 65535 {
			return fmt.Errorf("hosts[%d].port must be between 1 and 65535", i)
		}
	}

	return nil
}
