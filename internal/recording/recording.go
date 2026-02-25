// Package recording provides session recording functionality for audit and playback.
package recording

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/Veritas-Calculus/vc-jump/internal/config"
	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
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

	// Validate that the path is within basePath to prevent directory traversal.
	if !isPathWithinBase(s.basePath, filePath) {
		return errors.New("invalid file path: directory traversal attempt detected")
	}

	return os.WriteFile(filePath, data, 0600)
}

func (s *LocalStorage) Load(_ context.Context, filename string) ([]byte, error) {
	filePath := filepath.Join(s.basePath, filename)

	// Validate that the path is within basePath to prevent directory traversal.
	if !isPathWithinBase(s.basePath, filePath) {
		return nil, errors.New("invalid file path: directory traversal attempt detected")
	}

	return os.ReadFile(filePath) // #nosec G304 -- path validated by isPathWithinBase
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

	// Validate that the path is within basePath to prevent directory traversal.
	if !isPathWithinBase(s.basePath, filePath) {
		return errors.New("invalid file path: directory traversal attempt detected")
	}

	return os.Remove(filePath)
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

// filenameRegex validates recording filenames to prevent injection attacks.
var filenameRegex = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_\-\.]*\.cast$`)

// validateFilename checks if a filename is safe for storage operations.
func validateFilename(filename string) error {
	if filename == "" {
		return errors.New("filename cannot be empty")
	}
	if len(filename) > 255 {
		return errors.New("filename too long")
	}
	if strings.Contains(filename, "/") || strings.Contains(filename, "\\") {
		return errors.New("filename contains path separator")
	}
	if strings.Contains(filename, "..") {
		return errors.New("filename contains directory traversal")
	}
	if !filenameRegex.MatchString(filename) {
		return errors.New("filename contains invalid characters")
	}
	return nil
}

// S3Storage implements Storage using S3-compatible object storage.
type S3Storage struct {
	cfg    config.S3Config
	client *s3.Client
}

// NewS3Storage creates a new S3Storage instance.
func NewS3Storage(cfg config.S3Config) (*S3Storage, error) {
	if cfg.Bucket == "" {
		return nil, errors.New("S3 bucket cannot be empty")
	}
	if cfg.Region == "" {
		return nil, errors.New("S3 region cannot be empty")
	}

	// Validate bucket name to prevent injection.
	if !isValidBucketName(cfg.Bucket) {
		return nil, errors.New("invalid S3 bucket name")
	}

	// Validate prefix if provided.
	if cfg.Prefix != "" && !isValidPrefix(cfg.Prefix) {
		return nil, errors.New("invalid S3 prefix")
	}

	// Build S3 client configuration.
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	var opts []func(*awsconfig.LoadOptions) error

	// Set region.
	opts = append(opts, awsconfig.WithRegion(cfg.Region))

	// Set static credentials if provided.
	if cfg.AccessKeyID != "" && cfg.SecretAccessKey != "" {
		opts = append(opts, awsconfig.WithCredentialsProvider(
			credentials.NewStaticCredentialsProvider(
				cfg.AccessKeyID,
				cfg.SecretAccessKey,
				"", // session token
			),
		))
	}

	awsCfg, err := awsconfig.LoadDefaultConfig(ctx, opts...)
	if err != nil {
		return nil, fmt.Errorf("failed to load AWS config: %w", err)
	}

	// Build S3 client options.
	s3Opts := []func(*s3.Options){}

	// Set custom endpoint if provided (for MinIO, etc.).
	if cfg.Endpoint != "" {
		// Validate endpoint URL.
		if _, err := url.Parse(cfg.Endpoint); err != nil {
			return nil, fmt.Errorf("invalid S3 endpoint URL: %w", err)
		}
		s3Opts = append(s3Opts, func(o *s3.Options) {
			o.BaseEndpoint = aws.String(cfg.Endpoint)
		})
	}

	// Use path-style addressing if required (for MinIO).
	if cfg.ForcePathStyle {
		s3Opts = append(s3Opts, func(o *s3.Options) {
			o.UsePathStyle = true
		})
	}

	client := s3.NewFromConfig(awsCfg, s3Opts...)

	return &S3Storage{
		cfg:    cfg,
		client: client,
	}, nil
}

// isValidBucketName validates S3 bucket name according to AWS rules.
func isValidBucketName(name string) bool {
	if len(name) < 3 || len(name) > 63 {
		return false
	}
	// Must start with lowercase letter or number.
	if (name[0] < 'a' || name[0] > 'z') && (name[0] < '0' || name[0] > '9') {
		return false
	}
	// Only lowercase letters, numbers, and hyphens.
	for _, c := range name {
		if (c < 'a' || c > 'z') && (c < '0' || c > '9') && c != '-' && c != '.' {
			return false
		}
	}
	// Cannot end with hyphen.
	if name[len(name)-1] == '-' {
		return false
	}
	return true
}

// isValidPrefix validates S3 object key prefix.
func isValidPrefix(prefix string) bool {
	if len(prefix) > 1024 {
		return false
	}
	// Disallow control characters and some special chars.
	for _, c := range prefix {
		if c < 32 || c == '\\' || c == '{' || c == '}' || c == '^' {
			return false
		}
	}
	return true
}

// buildObjectKey constructs the full object key from prefix and filename.
func (s *S3Storage) buildObjectKey(filename string) string {
	if s.cfg.Prefix == "" {
		return filename
	}
	// Ensure prefix ends with /
	prefix := s.cfg.Prefix
	if !strings.HasSuffix(prefix, "/") {
		prefix += "/"
	}
	return prefix + filename
}

func (s *S3Storage) Save(ctx context.Context, filename string, data []byte) error {
	if err := validateFilename(filename); err != nil {
		return fmt.Errorf("invalid filename: %w", err)
	}

	key := s.buildObjectKey(filename)

	_, err := s.client.PutObject(ctx, &s3.PutObjectInput{
		Bucket:      aws.String(s.cfg.Bucket),
		Key:         aws.String(key),
		Body:        bytes.NewReader(data),
		ContentType: aws.String("application/json"),
	})
	if err != nil {
		return fmt.Errorf("failed to upload to S3: %w", err)
	}

	return nil
}

func (s *S3Storage) Load(ctx context.Context, filename string) ([]byte, error) {
	if err := validateFilename(filename); err != nil {
		return nil, fmt.Errorf("invalid filename: %w", err)
	}

	key := s.buildObjectKey(filename)

	result, err := s.client.GetObject(ctx, &s3.GetObjectInput{
		Bucket: aws.String(s.cfg.Bucket),
		Key:    aws.String(key),
	})
	if err != nil {
		return nil, fmt.Errorf("failed to download from S3: %w", err)
	}
	defer func() { _ = result.Body.Close() }()

	// Limit read size to prevent memory exhaustion (100MB max).
	const maxSize = 100 * 1024 * 1024
	limitedReader := io.LimitReader(result.Body, maxSize)

	data, err := io.ReadAll(limitedReader)
	if err != nil {
		return nil, fmt.Errorf("failed to read S3 object: %w", err)
	}

	return data, nil
}

func (s *S3Storage) List(ctx context.Context) ([]string, error) {
	var files []string
	var continuationToken *string

	prefix := s.cfg.Prefix
	if prefix != "" && !strings.HasSuffix(prefix, "/") {
		prefix += "/"
	}

	for {
		input := &s3.ListObjectsV2Input{
			Bucket:            aws.String(s.cfg.Bucket),
			ContinuationToken: continuationToken,
			MaxKeys:           aws.Int32(1000),
		}
		if prefix != "" {
			input.Prefix = aws.String(prefix)
		}

		result, err := s.client.ListObjectsV2(ctx, input)
		if err != nil {
			return nil, fmt.Errorf("failed to list S3 objects: %w", err)
		}

		for _, obj := range result.Contents {
			if obj.Key != nil {
				// Strip prefix to get just the filename.
				filename := *obj.Key
				if prefix != "" && strings.HasPrefix(filename, prefix) {
					filename = filename[len(prefix):]
				}
				// Only include .cast files.
				if strings.HasSuffix(filename, ".cast") {
					files = append(files, filename)
				}
			}
		}

		if result.IsTruncated == nil || !*result.IsTruncated {
			break
		}
		continuationToken = result.NextContinuationToken
	}

	return files, nil
}

func (s *S3Storage) Delete(ctx context.Context, filename string) error {
	if err := validateFilename(filename); err != nil {
		return fmt.Errorf("invalid filename: %w", err)
	}

	key := s.buildObjectKey(filename)

	_, err := s.client.DeleteObject(ctx, &s3.DeleteObjectInput{
		Bucket: aws.String(s.cfg.Bucket),
		Key:    aws.String(key),
	})
	if err != nil {
		return fmt.Errorf("failed to delete from S3: %w", err)
	}

	return nil
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
	watchers  map[chan []byte]struct{}
	watcherMu sync.RWMutex
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
	var basePath string
	if r.cfg.StorageType == "local" {
		basePath = r.cfg.LocalPath
		filePath = filepath.Join(basePath, filename)
	} else {
		// For S3, we still create a temporary local file first.
		basePath = os.TempDir()
		filePath = filepath.Join(basePath, filename)
	}

	// Validate that the path is within basePath to prevent directory traversal.
	if !isPathWithinBase(basePath, filePath) {
		return nil, errors.New("invalid file path: directory traversal attempt detected")
	}

	file, err := os.OpenFile(filePath, os.O_CREATE|os.O_WRONLY|os.O_EXCL, 0600) // #nosec G304 -- path validated by isPathWithinBase
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
		watchers:  make(map[chan []byte]struct{}),
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

// ActiveSessionInfo contains info about an active session.
type ActiveSessionInfo struct {
	ID        string    `json:"id"`
	Username  string    `json:"username"`
	HostName  string    `json:"hostname"`
	StartTime time.Time `json:"start_time"`
}

// ListActiveSessions returns information about all active recording sessions.
func (r *Recorder) ListActiveSessions() []ActiveSessionInfo {
	var sessions []ActiveSessionInfo
	r.sessions.Range(func(key, value interface{}) bool {
		s := value.(*Session)
		s.mu.Lock()
		closed := s.closed
		s.mu.Unlock()
		if !closed {
			sessions = append(sessions, ActiveSessionInfo{
				ID:        s.ID,
				Username:  s.Username,
				HostName:  s.HostName,
				StartTime: s.StartTime,
			})
		}
		return true
	})
	return sessions
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

	// Close all watchers.
	s.watcherMu.Lock()
	for ch := range s.watchers {
		close(ch)
	}
	s.watchers = nil
	s.watcherMu.Unlock()

	return s.file.Close()
}

// AddWatcher adds a new watcher channel that receives output data.
func (s *Session) AddWatcher(ch chan []byte) {
	s.watcherMu.Lock()
	defer s.watcherMu.Unlock()
	if s.watchers != nil {
		s.watchers[ch] = struct{}{}
	}
}

// RemoveWatcher removes a watcher channel.
func (s *Session) RemoveWatcher(ch chan []byte) {
	s.watcherMu.Lock()
	defer s.watcherMu.Unlock()
	if s.watchers != nil {
		delete(s.watchers, ch)
	}
}

// broadcastToWatchers sends data to all watchers.
func (s *Session) broadcastToWatchers(data []byte) {
	s.watcherMu.RLock()
	defer s.watcherMu.RUnlock()
	for ch := range s.watchers {
		select {
		case ch <- data:
		default:
			// Skip if channel is full.
		}
	}
}

// RecordOutput records output data.
func (s *Session) RecordOutput(data []byte) error {
	// Broadcast to watchers (output only, not input for security).
	s.broadcastToWatchers(data)
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
