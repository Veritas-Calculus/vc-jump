// Package recording provides session recording functionality for audit and playback.
package recording

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/Veritas-Calculus/vc-jump/internal/config"
)

// Storage defines the interface for recording storage backends.
type Storage interface {
	// Save stores the recording data.
	Save(ctx context.Context, filename string, data []byte) error
	// Load retrieves recording data.
	Load(ctx context.Context, filename string) ([]byte, error)
	// List returns all recording filenames.
	List(ctx context.Context) ([]string, error)
	// Delete removes a recording.
	Delete(ctx context.Context, filename string) error
}

// LocalStorage implements Storage using local filesystem.
type LocalStorage struct {
	basePath string
}

// NewLocalStorage creates a new LocalStorage instance.
func NewLocalStorage(basePath string) (*LocalStorage, error) {
	if basePath == "" {
		return nil, errors.New("base path cannot be empty")
	}
	if err := os.MkdirAll(basePath, 0700); err != nil {
		return nil, fmt.Errorf("failed to create storage directory: %w", err)
	}
	return &LocalStorage{basePath: basePath}, nil
}

func (s *LocalStorage) Save(ctx context.Context, filename string, data []byte) error {
	filePath := filepath.Join(s.basePath, filename)
	return os.WriteFile(filePath, data, 0600)
}

func (s *LocalStorage) Load(_ context.Context, filename string) ([]byte, error) {
	filePath := filepath.Join(s.basePath, filename)
	return os.ReadFile(filePath) //nolint:gosec // filePath is constructed from basePath
}

func (s *LocalStorage) List(ctx context.Context) ([]string, error) {
	entries, err := os.ReadDir(s.basePath)
	if err != nil {
		return nil, err
	}
	var files []string
	for _, entry := range entries {
		if !entry.IsDir() {
			files = append(files, entry.Name())
		}
	}
	return files, nil
}

func (s *LocalStorage) Delete(ctx context.Context, filename string) error {
	filePath := filepath.Join(s.basePath, filename)
	return os.Remove(filePath)
}

// S3Storage implements Storage using S3-compatible object storage.
type S3Storage struct {
	cfg config.S3Config
}

// NewS3Storage creates a new S3Storage instance.
func NewS3Storage(cfg config.S3Config) (*S3Storage, error) {
	if cfg.Bucket == "" {
		return nil, errors.New("S3 bucket cannot be empty")
	}
	return &S3Storage{cfg: cfg}, nil
}

func (s *S3Storage) Save(ctx context.Context, filename string, data []byte) error {
	// TODO: Implement S3 upload using AWS SDK or compatible library.
	// For now, return an error indicating not implemented.
	return errors.New("S3 storage not yet implemented - use local storage")
}

func (s *S3Storage) Load(ctx context.Context, filename string) ([]byte, error) {
	return nil, errors.New("S3 storage not yet implemented - use local storage")
}

func (s *S3Storage) List(ctx context.Context) ([]string, error) {
	return nil, errors.New("S3 storage not yet implemented - use local storage")
}

func (s *S3Storage) Delete(ctx context.Context, filename string) error {
	return errors.New("S3 storage not yet implemented - use local storage")
}

// Recorder manages session recordings.
type Recorder struct {
	cfg      config.RecordingConfig
	storage  Storage
	sessions sync.Map
}

// New creates a new Recorder with the given configuration.
func New(cfg config.RecordingConfig) (*Recorder, error) {
	if !cfg.Enabled {
		return nil, errors.New("recording is not enabled")
	}

	var storage Storage
	var err error

	switch cfg.StorageType {
	case "local":
		if cfg.LocalPath == "" {
			return nil, errors.New("local_path cannot be empty for local storage")
		}
		storage, err = NewLocalStorage(cfg.LocalPath)
	case "s3":
		storage, err = NewS3Storage(cfg.S3Config)
	default:
		return nil, fmt.Errorf("unsupported storage type: %s", cfg.StorageType)
	}

	if err != nil {
		return nil, fmt.Errorf("failed to create storage: %w", err)
	}

	return &Recorder{
		cfg:     cfg,
		storage: storage,
	}, nil
}

// GetStorage returns the underlying storage backend.
func (r *Recorder) GetStorage() Storage {
	return r.storage
}

// Session represents an active recording session.
type Session struct {
	ID        string
	Username  string
	HostName  string
	StartTime time.Time
	file      *os.File
	encoder   *json.Encoder
	filePath  string
	recorder  *Recorder
	mu        sync.Mutex
	closed    bool
}

// RecordEvent represents a single event in the recording.
type RecordEvent struct {
	Time int64  `json:"time"` // Milliseconds since session start.
	Type string `json:"type"` // "i" for input, "o" for output.
	Data string `json:"data"` // Base64 encoded data.
}

// RecordingHeader contains metadata about the recording.
type RecordingHeader struct {
	Version   int       `json:"version"`
	Username  string    `json:"username"`
	HostName  string    `json:"hostname"`
	StartTime time.Time `json:"start_time"`
	Width     int       `json:"width"`
	Height    int       `json:"height"`
}

// StartSession begins recording a new session.
func (r *Recorder) StartSession(username, hostname string) (*Session, error) {
	if username == "" {
		return nil, errors.New("username cannot be empty")
	}
	if hostname == "" {
		return nil, errors.New("hostname cannot be empty")
	}

	sessionID := generateSessionID()
	startTime := time.Now()

	// Create recording file.
	filename := fmt.Sprintf("%s_%s_%s.cast",
		startTime.Format("20060102_150405"),
		username,
		sessionID,
	)

	// Get the storage path based on storage type.
	var filePath string
	if r.cfg.StorageType == "local" {
		filePath = filepath.Join(r.cfg.LocalPath, filename)
	} else {
		// For S3, we still create a temporary local file first.
		filePath = filepath.Join(os.TempDir(), filename)
	}

	file, err := os.OpenFile(filePath, os.O_CREATE|os.O_WRONLY|os.O_EXCL, 0600) //nolint:gosec // filePath constructed from safe components
	if err != nil {
		return nil, fmt.Errorf("failed to create recording file: %w", err)
	}

	session := &Session{
		ID:        sessionID,
		Username:  username,
		HostName:  hostname,
		StartTime: startTime,
		file:      file,
		encoder:   json.NewEncoder(file),
		filePath:  filePath,
		recorder:  r,
	}

	// Write header.
	header := RecordingHeader{
		Version:   2,
		Username:  username,
		HostName:  hostname,
		StartTime: startTime,
		Width:     80,
		Height:    24,
	}
	if err := session.encoder.Encode(header); err != nil {
		_ = file.Close()
		_ = os.Remove(filePath)
		return nil, fmt.Errorf("failed to write recording header: %w", err)
	}

	r.sessions.Store(sessionID, session)
	return session, nil
}

// GetSession retrieves an active session by ID.
func (r *Recorder) GetSession(id string) (*Session, bool) {
	val, ok := r.sessions.Load(id)
	if !ok {
		return nil, false
	}
	return val.(*Session), true
}

// FilePath returns the path to the recording file.
func (s *Session) FilePath() string {
	return s.filePath
}

// Close closes the recording session.
func (s *Session) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.closed {
		return nil
	}
	s.closed = true

	return s.file.Close()
}

// RecordOutput records output data.
func (s *Session) RecordOutput(data []byte) error {
	return s.recordEvent("o", data)
}

// RecordInput records input data.
func (s *Session) RecordInput(data []byte) error {
	return s.recordEvent("i", data)
}

func (s *Session) recordEvent(eventType string, data []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.closed {
		return errors.New("session is closed")
	}

	elapsed := time.Since(s.StartTime).Milliseconds()
	event := RecordEvent{
		Time: elapsed,
		Type: eventType,
		Data: string(data),
	}

	return s.encoder.Encode(event)
}

// Wrap wraps an io.ReadWriteCloser to record all I/O.
func (s *Session) Wrap(rw io.ReadWriteCloser) io.ReadWriteCloser {
	return &recordingWrapper{
		session: s,
		rw:      rw,
	}
}

type recordingWrapper struct {
	session *Session
	rw      io.ReadWriteCloser
}

func (w *recordingWrapper) Read(p []byte) (int, error) {
	n, err := w.rw.Read(p)
	if n > 0 {
		_ = w.session.RecordInput(p[:n])
	}
	return n, err
}

func (w *recordingWrapper) Write(p []byte) (int, error) {
	_ = w.session.RecordOutput(p)
	return w.rw.Write(p)
}

func (w *recordingWrapper) Close() error {
	return w.rw.Close()
}

func generateSessionID() string {
	now := time.Now().UnixNano()
	return fmt.Sprintf("%x", now)
}
