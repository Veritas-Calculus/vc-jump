// Package logger provides structured logging with retention management.
package logger

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"

	"github.com/Veritas-Calculus/vc-jump/internal/config"
)

// Level represents a log level.
type Level int

const (
	LevelDebug Level = iota
	LevelInfo
	LevelWarn
	LevelError
)

func (l Level) String() string {
	switch l {
	case LevelDebug:
		return "debug"
	case LevelInfo:
		return "info"
	case LevelWarn:
		return "warn"
	case LevelError:
		return "error"
	default:
		return "unknown"
	}
}

// ParseLevel parses a log level string.
func ParseLevel(s string) Level {
	switch s {
	case "debug":
		return LevelDebug
	case "info":
		return LevelInfo
	case "warn":
		return LevelWarn
	case "error":
		return LevelError
	default:
		return LevelInfo
	}
}

// Entry represents a log entry.
type Entry struct {
	Time    time.Time              `json:"time"`
	Level   string                 `json:"level"`
	Message string                 `json:"message"`
	Fields  map[string]interface{} `json:"fields,omitempty"`
}

// Logger provides structured logging capabilities.
type Logger struct {
	cfg       config.LoggingConfig
	level     Level
	output    io.Writer
	file      *os.File
	mu        sync.Mutex
	fields    map[string]interface{}
	cleanupCh chan struct{}
}

// New creates a new Logger with the given configuration.
func New(cfg config.LoggingConfig) (*Logger, error) {
	l := &Logger{
		cfg:       cfg,
		level:     ParseLevel(cfg.Level),
		fields:    make(map[string]interface{}),
		cleanupCh: make(chan struct{}),
	}

	// Setup output.
	switch cfg.Output {
	case "stdout":
		l.output = os.Stdout
	case "file":
		if cfg.FilePath == "" {
			return nil, fmt.Errorf("file_path is required when output is 'file'")
		}
		if err := os.MkdirAll(filepath.Dir(cfg.FilePath), 0750); err != nil {
			return nil, fmt.Errorf("failed to create log directory: %w", err)
		}
		file, err := os.OpenFile(cfg.FilePath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600) //nolint:gosec
		if err != nil {
			return nil, fmt.Errorf("failed to open log file: %w", err)
		}
		l.file = file
		l.output = file
	default:
		l.output = os.Stdout
	}

	// Start cleanup goroutine if retention is configured.
	if cfg.RetentionDays > 0 && cfg.Output == "file" {
		go l.cleanupLoop()
	}

	return l, nil
}

// Close closes the logger.
func (l *Logger) Close() error {
	close(l.cleanupCh)
	if l.file != nil {
		return l.file.Close()
	}
	return nil
}

// WithFields returns a new logger with the given fields.
func (l *Logger) WithFields(fields map[string]interface{}) *Logger {
	newLogger := &Logger{
		cfg:    l.cfg,
		level:  l.level,
		output: l.output,
		file:   l.file,
		fields: make(map[string]interface{}),
	}
	for k, v := range l.fields {
		newLogger.fields[k] = v
	}
	for k, v := range fields {
		newLogger.fields[k] = v
	}
	return newLogger
}

// WithField returns a new logger with the given field.
func (l *Logger) WithField(key string, value interface{}) *Logger {
	return l.WithFields(map[string]interface{}{key: value})
}

// Debug logs a debug message.
func (l *Logger) Debug(msg string) {
	l.log(LevelDebug, msg)
}

// Debugf logs a formatted debug message.
func (l *Logger) Debugf(format string, args ...interface{}) {
	l.log(LevelDebug, fmt.Sprintf(format, args...))
}

// Info logs an info message.
func (l *Logger) Info(msg string) {
	l.log(LevelInfo, msg)
}

// Infof logs a formatted info message.
func (l *Logger) Infof(format string, args ...interface{}) {
	l.log(LevelInfo, fmt.Sprintf(format, args...))
}

// Warn logs a warning message.
func (l *Logger) Warn(msg string) {
	l.log(LevelWarn, msg)
}

// Warnf logs a formatted warning message.
func (l *Logger) Warnf(format string, args ...interface{}) {
	l.log(LevelWarn, fmt.Sprintf(format, args...))
}

// Error logs an error message.
func (l *Logger) Error(msg string) {
	l.log(LevelError, msg)
}

// Errorf logs a formatted error message.
func (l *Logger) Errorf(format string, args ...interface{}) {
	l.log(LevelError, fmt.Sprintf(format, args...))
}

func (l *Logger) log(level Level, msg string) {
	if level < l.level {
		return
	}

	entry := Entry{
		Time:    time.Now(),
		Level:   level.String(),
		Message: msg,
		Fields:  l.fields,
	}

	l.mu.Lock()
	defer l.mu.Unlock()

	if l.cfg.Format == "json" {
		data, _ := json.Marshal(entry)
		_, _ = l.output.Write(data)
		_, _ = l.output.Write([]byte("\n"))
	} else {
		// Text format.
		fieldsStr := ""
		for k, v := range l.fields {
			fieldsStr += fmt.Sprintf(" %s=%v", k, v)
		}
		_, _ = fmt.Fprintf(l.output, "%s [%s] %s%s\n",
			entry.Time.Format("2006-01-02 15:04:05"),
			entry.Level,
			entry.Message,
			fieldsStr)
	}
}

func (l *Logger) cleanupLoop() {
	ticker := time.NewTicker(24 * time.Hour)
	defer ticker.Stop()

	// Run cleanup immediately on start.
	l.cleanup()

	for {
		select {
		case <-ticker.C:
			l.cleanup()
		case <-l.cleanupCh:
			return
		}
	}
}

func (l *Logger) cleanup() {
	if l.cfg.FilePath == "" || l.cfg.RetentionDays <= 0 {
		return
	}

	dir := filepath.Dir(l.cfg.FilePath)
	pattern := filepath.Base(l.cfg.FilePath) + "*"

	files, err := filepath.Glob(filepath.Join(dir, pattern))
	if err != nil {
		return
	}

	cutoff := time.Now().AddDate(0, 0, -l.cfg.RetentionDays)

	for _, file := range files {
		info, err := os.Stat(file)
		if err != nil {
			continue
		}
		if info.ModTime().Before(cutoff) {
			_ = os.Remove(file)
		}
	}
}

// CleanupOldLogs removes log files older than the retention period.
func CleanupOldLogs(ctx context.Context, logDir string, retentionDays int) error {
	if retentionDays <= 0 {
		return nil
	}

	entries, err := os.ReadDir(logDir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("failed to read log directory: %w", err)
	}

	cutoff := time.Now().AddDate(0, 0, -retentionDays)

	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}

		info, err := entry.Info()
		if err != nil {
			continue
		}

		if info.ModTime().Before(cutoff) {
			filePath := filepath.Join(logDir, entry.Name())
			if err := os.Remove(filePath); err != nil {
				continue
			}
		}
	}

	return nil
}

// RotateLog rotates the log file if it exceeds the max size.
func (l *Logger) RotateLog() error {
	if l.file == nil || l.cfg.MaxSizeMB <= 0 {
		return nil
	}

	info, err := l.file.Stat()
	if err != nil {
		return err
	}

	maxBytes := int64(l.cfg.MaxSizeMB) * 1024 * 1024
	if info.Size() < maxBytes {
		return nil
	}

	l.mu.Lock()
	defer l.mu.Unlock()

	// Close current file.
	_ = l.file.Close()

	// Rename current file with timestamp.
	timestamp := time.Now().Format("20060102_150405")
	rotatedPath := fmt.Sprintf("%s.%s", l.cfg.FilePath, timestamp)
	if err := os.Rename(l.cfg.FilePath, rotatedPath); err != nil {
		return err
	}

	// Open new file.
	file, err := os.OpenFile(l.cfg.FilePath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600) //nolint:gosec
	if err != nil {
		return err
	}
	l.file = file
	l.output = file

	// Remove old backups if needed.
	l.removeOldBackups()

	return nil
}

func (l *Logger) removeOldBackups() {
	if l.cfg.MaxBackups <= 0 {
		return
	}

	dir := filepath.Dir(l.cfg.FilePath)
	base := filepath.Base(l.cfg.FilePath)

	files, err := filepath.Glob(filepath.Join(dir, base+".*"))
	if err != nil {
		return
	}

	if len(files) <= l.cfg.MaxBackups {
		return
	}

	// Sort by modification time (oldest first).
	sort.Slice(files, func(i, j int) bool {
		fi, _ := os.Stat(files[i])
		fj, _ := os.Stat(files[j])
		return fi.ModTime().Before(fj.ModTime())
	})

	// Remove oldest files.
	for i := 0; i < len(files)-l.cfg.MaxBackups; i++ {
		_ = os.Remove(files[i])
	}
}
