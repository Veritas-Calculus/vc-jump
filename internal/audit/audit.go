// Package audit provides operation audit logging for vc-jump.
package audit

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/Veritas-Calculus/vc-jump/internal/config"
)

// EventType represents the type of audit event.
type EventType string

const (
	EventLogin        EventType = "login"
	EventLogout       EventType = "logout"
	EventConnect      EventType = "connect"
	EventDisconnect   EventType = "disconnect"
	EventCommand      EventType = "command"
	EventFileUpload   EventType = "file_upload"
	EventFileDownload EventType = "file_download"
	EventError        EventType = "error"
)

// Event represents an audit log event.
type Event struct {
	ID         string                 `json:"id"`
	Timestamp  time.Time              `json:"timestamp"`
	Type       EventType              `json:"type"`
	Username   string                 `json:"username"`
	SourceIP   string                 `json:"source_ip"`
	TargetHost string                 `json:"target_host,omitempty"`
	Action     string                 `json:"action"`
	Result     string                 `json:"result"` // "success" or "failure"
	Details    map[string]interface{} `json:"details,omitempty"`
}

// Auditor handles audit logging.
type Auditor struct {
	cfg     config.AuditConfig
	storage Storage
	eventCh chan Event
	done    chan struct{}
	wg      sync.WaitGroup
	mu      sync.Mutex
	counter int64
}

// Storage defines the interface for audit log storage.
type Storage interface {
	Write(ctx context.Context, event Event) error
	Query(ctx context.Context, opts QueryOptions) ([]Event, error)
	Cleanup(ctx context.Context, before time.Time) error
}

// QueryOptions defines options for querying audit logs.
type QueryOptions struct {
	Username  string
	EventType EventType
	StartTime time.Time
	EndTime   time.Time
	Limit     int
	Offset    int
}

// LocalStorage implements Storage using local filesystem.
type LocalStorage struct {
	basePath string
	mu       sync.Mutex
}

// NewLocalStorage creates a new LocalStorage instance.
func NewLocalStorage(basePath string) (*LocalStorage, error) {
	if basePath == "" {
		return nil, errors.New("base path cannot be empty")
	}
	if err := os.MkdirAll(basePath, 0700); err != nil {
		return nil, fmt.Errorf("failed to create audit directory: %w", err)
	}
	return &LocalStorage{basePath: basePath}, nil
}

func (s *LocalStorage) Write(ctx context.Context, event Event) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Create daily log file.
	filename := fmt.Sprintf("audit_%s.jsonl", event.Timestamp.Format("20060102"))
	filePath := filepath.Join(s.basePath, filename)

	// Validate that the constructed path is within basePath to prevent directory traversal.
	if !isPathWithinBase(s.basePath, filePath) {
		return errors.New("invalid file path: directory traversal attempt detected")
	}

	file, err := os.OpenFile(filePath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600) // #nosec G304 -- path validated by isPathWithinBase
	if err != nil {
		return fmt.Errorf("failed to open audit file: %w", err)
	}
	defer func() { _ = file.Close() }()

	data, err := json.Marshal(event)
	if err != nil {
		return fmt.Errorf("failed to marshal event: %w", err)
	}

	if _, err := file.Write(append(data, '\n')); err != nil {
		return fmt.Errorf("failed to write event: %w", err)
	}

	return nil
}

func (s *LocalStorage) Query(ctx context.Context, opts QueryOptions) ([]Event, error) {
	// For simplicity, read all files and filter.
	entries, err := os.ReadDir(s.basePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read audit directory: %w", err)
	}

	var events []Event
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}

		filePath := filepath.Join(s.basePath, entry.Name())
		fileEvents, err := s.readFile(filePath)
		if err != nil {
			continue
		}

		for _, event := range fileEvents {
			if s.matchesQuery(event, opts) {
				events = append(events, event)
			}
		}
	}

	// Apply offset and limit.
	if opts.Offset > 0 && opts.Offset < len(events) {
		events = events[opts.Offset:]
	}
	if opts.Limit > 0 && opts.Limit < len(events) {
		events = events[:opts.Limit]
	}

	return events, nil
}

func (s *LocalStorage) readFile(filePath string) ([]Event, error) {
	// Validate that the path is within basePath to prevent directory traversal.
	if !isPathWithinBase(s.basePath, filePath) {
		return nil, errors.New("invalid file path: directory traversal attempt detected")
	}

	data, err := os.ReadFile(filePath) // #nosec G304 -- path validated by isPathWithinBase
	if err != nil {
		return nil, err
	}

	var events []Event
	lines := splitLines(data)
	for _, line := range lines {
		if len(line) == 0 {
			continue
		}
		var event Event
		if err := json.Unmarshal(line, &event); err != nil {
			continue
		}
		events = append(events, event)
	}
	return events, nil
}

func (s *LocalStorage) matchesQuery(event Event, opts QueryOptions) bool {
	if opts.Username != "" && event.Username != opts.Username {
		return false
	}
	if opts.EventType != "" && event.Type != opts.EventType {
		return false
	}
	if !opts.StartTime.IsZero() && event.Timestamp.Before(opts.StartTime) {
		return false
	}
	if !opts.EndTime.IsZero() && event.Timestamp.After(opts.EndTime) {
		return false
	}
	return true
}

func (s *LocalStorage) Cleanup(ctx context.Context, before time.Time) error {
	entries, err := os.ReadDir(s.basePath)
	if err != nil {
		return fmt.Errorf("failed to read audit directory: %w", err)
	}

	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}

		info, err := entry.Info()
		if err != nil {
			continue
		}

		if info.ModTime().Before(before) {
			filePath := filepath.Join(s.basePath, entry.Name())
			_ = os.Remove(filePath)
		}
	}

	return nil
}

// isPathWithinBase validates that the given path is within the base directory.
// This prevents directory traversal attacks.
func isPathWithinBase(basePath, targetPath string) bool {
	// Clean both paths.
	absBase, err := filepath.Abs(basePath)
	if err != nil {
		return false
	}
	absTarget, err := filepath.Abs(targetPath)
	if err != nil {
		return false
	}

	// Ensure the target path starts with the base path.
	relPath, err := filepath.Rel(absBase, absTarget)
	if err != nil {
		return false
	}

	// If the relative path starts with "..", it's outside the base directory.
	return !startsWithDotDot(relPath)
}

// startsWithDotDot checks if a path starts with "..".
func startsWithDotDot(path string) bool {
	if len(path) < 2 {
		return false
	}
	return path[0] == '.' && path[1] == '.' && (len(path) == 2 || path[2] == filepath.Separator)
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

// New creates a new Auditor with the given configuration.
func New(cfg config.AuditConfig) (*Auditor, error) {
	if !cfg.Enabled {
		return nil, errors.New("audit is not enabled")
	}

	var storage Storage
	var err error

	switch cfg.StorageType {
	case "local":
		if cfg.LocalPath == "" {
			return nil, errors.New("local_path is required for local storage")
		}
		storage, err = NewLocalStorage(cfg.LocalPath)
	case "s3":
		return nil, errors.New("S3 audit storage not yet implemented")
	default:
		return nil, fmt.Errorf("unsupported storage type: %s", cfg.StorageType)
	}

	if err != nil {
		return nil, fmt.Errorf("failed to create storage: %w", err)
	}

	a := &Auditor{
		cfg:     cfg,
		storage: storage,
		eventCh: make(chan Event, 1000),
		done:    make(chan struct{}),
	}

	// Start background writer.
	a.wg.Add(1)
	go a.writeLoop()

	// Start cleanup goroutine.
	if cfg.RetentionDays > 0 {
		a.wg.Add(1)
		go a.cleanupLoop()
	}

	return a, nil
}

// Close stops the auditor.
func (a *Auditor) Close() error {
	close(a.done)
	a.wg.Wait()
	return nil
}

// Log records an audit event.
func (a *Auditor) Log(event Event) {
	a.mu.Lock()
	a.counter++
	event.ID = fmt.Sprintf("%d-%d", time.Now().UnixNano(), a.counter)
	a.mu.Unlock()

	if event.Timestamp.IsZero() {
		event.Timestamp = time.Now()
	}

	select {
	case a.eventCh <- event:
	default:
		// Channel full, drop event.
	}
}

// LogLogin records a login event.
func (a *Auditor) LogLogin(username, sourceIP, result string) {
	a.Log(Event{
		Type:     EventLogin,
		Username: username,
		SourceIP: sourceIP,
		Action:   "user login",
		Result:   result,
	})
}

// LogConnect records a connection event.
func (a *Auditor) LogConnect(username, sourceIP, targetHost, result string) {
	a.Log(Event{
		Type:       EventConnect,
		Username:   username,
		SourceIP:   sourceIP,
		TargetHost: targetHost,
		Action:     "connect to host",
		Result:     result,
	})
}

// LogCommand records a command execution event.
func (a *Auditor) LogCommand(username, sourceIP, targetHost, command, result string) {
	a.Log(Event{
		Type:       EventCommand,
		Username:   username,
		SourceIP:   sourceIP,
		TargetHost: targetHost,
		Action:     "execute command",
		Result:     result,
		Details:    map[string]interface{}{"command": command},
	})
}

// Query queries audit logs.
func (a *Auditor) Query(ctx context.Context, opts QueryOptions) ([]Event, error) {
	return a.storage.Query(ctx, opts)
}

func (a *Auditor) writeLoop() {
	defer a.wg.Done()

	for {
		select {
		case event := <-a.eventCh:
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			_ = a.storage.Write(ctx, event)
			cancel()
		case <-a.done:
			// Drain remaining events.
			for {
				select {
				case event := <-a.eventCh:
					ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
					_ = a.storage.Write(ctx, event)
					cancel()
				default:
					return
				}
			}
		}
	}
}

func (a *Auditor) cleanupLoop() {
	defer a.wg.Done()

	ticker := time.NewTicker(24 * time.Hour)
	defer ticker.Stop()

	// Run cleanup immediately.
	a.runCleanup()

	for {
		select {
		case <-ticker.C:
			a.runCleanup()
		case <-a.done:
			return
		}
	}
}

func (a *Auditor) runCleanup() {
	if a.cfg.RetentionDays <= 0 {
		return
	}

	before := time.Now().AddDate(0, 0, -a.cfg.RetentionDays)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	_ = a.storage.Cleanup(ctx, before)
}
