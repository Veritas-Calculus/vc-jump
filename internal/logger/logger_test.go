package logger

import (
"bytes"
"context"
"os"
"path/filepath"
"strings"
"testing"
"time"

"github.com/Veritas-Calculus/vc-jump/internal/config"
)

func TestNew(t *testing.T) {
tmpDir := t.TempDir()
cfg := config.LoggingConfig{
Level:         "info",
Format:        "text",
Output:        "file",
FilePath:      filepath.Join(tmpDir, "test.log"),
MaxSizeMB:     10,
MaxBackups:    3,
RetentionDays: 7,
}

l, err := New(cfg)
if err != nil {
t.Fatalf("failed to create logger: %v", err)
}
defer l.Close()

if l == nil {
t.Fatal("logger is nil")
}
}

func TestNewStdout(t *testing.T) {
cfg := config.LoggingConfig{
Level:  "debug",
Format: "text",
Output: "stdout",
}

l, err := New(cfg)
if err != nil {
t.Fatalf("failed to create logger: %v", err)
}
defer l.Close()

if l == nil {
t.Fatal("logger is nil")
}
}

func TestParseLevel(t *testing.T) {
tests := []struct {
input    string
expected Level
}{
{"debug", LevelDebug},
{"info", LevelInfo},
{"warn", LevelWarn},
{"error", LevelError},
{"", LevelInfo},
{"invalid", LevelInfo},
}

for _, tt := range tests {
got := ParseLevel(tt.input)
if got != tt.expected {
t.Errorf("ParseLevel(%q) = %v, want %v", tt.input, got, tt.expected)
}
}
}

func TestLogLevels(t *testing.T) {
var buf bytes.Buffer
l := &Logger{
level:  LevelDebug,
output: &buf,
cfg:    config.LoggingConfig{Format: "text"},
fields: make(map[string]interface{}),
}

l.Debug("debug message")
l.Info("info message")
l.Warn("warn message")
l.Error("error message")

output := buf.String()
if !strings.Contains(output, "debug message") {
t.Error("expected debug message in output")
}
if !strings.Contains(output, "info message") {
t.Error("expected info message in output")
}
if !strings.Contains(output, "warn message") {
t.Error("expected warn message in output")
}
if !strings.Contains(output, "error message") {
t.Error("expected error message in output")
}
}

func TestLogLevelFiltering(t *testing.T) {
var buf bytes.Buffer
l := &Logger{
level:  LevelWarn,
output: &buf,
cfg:    config.LoggingConfig{Format: "text"},
fields: make(map[string]interface{}),
}

l.Debug("debug message")
l.Info("info message")
l.Warn("warn message")
l.Error("error message")

output := buf.String()
if strings.Contains(output, "debug message") {
t.Error("debug message should be filtered")
}
if strings.Contains(output, "info message") {
t.Error("info message should be filtered")
}
if !strings.Contains(output, "warn message") {
t.Error("expected warn message in output")
}
if !strings.Contains(output, "error message") {
t.Error("expected error message in output")
}
}

func TestWithField(t *testing.T) {
var buf bytes.Buffer
l := &Logger{
level:  LevelInfo,
output: &buf,
cfg:    config.LoggingConfig{Format: "text"},
fields: make(map[string]interface{}),
}

l.WithField("key", "value").Info("test message")

output := buf.String()
if !strings.Contains(output, "key=value") {
t.Errorf("expected key=value in output, got: %s", output)
}
}

func TestWithFields(t *testing.T) {
var buf bytes.Buffer
l := &Logger{
level:  LevelInfo,
output: &buf,
cfg:    config.LoggingConfig{Format: "text"},
fields: make(map[string]interface{}),
}

l.WithFields(map[string]interface{}{
"user": "testuser",
"host": "server1",
}).Info("test message")

output := buf.String()
if !strings.Contains(output, "user=testuser") {
t.Errorf("expected user=testuser in output, got: %s", output)
}
if !strings.Contains(output, "host=server1") {
t.Errorf("expected host=server1 in output, got: %s", output)
}
}

func TestJSONFormat(t *testing.T) {
var buf bytes.Buffer
l := &Logger{
level:  LevelInfo,
output: &buf,
cfg:    config.LoggingConfig{Format: "json"},
fields: make(map[string]interface{}),
}

l.Info("test message")

output := buf.String()
if !strings.Contains(output, `"message":"test message"`) {
t.Errorf("expected JSON formatted output, got: %s", output)
}
if !strings.Contains(output, `"level":"info"`) {
t.Errorf("expected level in JSON output, got: %s", output)
}
}

func TestCleanupOldLogs(t *testing.T) {
tmpDir := t.TempDir()
logDir := filepath.Join(tmpDir, "logs")
os.MkdirAll(logDir, 0755)

oldFile := filepath.Join(logDir, "old.log")
newFile := filepath.Join(logDir, "new.log")

os.WriteFile(oldFile, []byte("old"), 0644)
os.WriteFile(newFile, []byte("new"), 0644)

oldTime := time.Now().AddDate(0, 0, -10)
os.Chtimes(oldFile, oldTime, oldTime)

err := CleanupOldLogs(context.Background(), logDir, 7)
if err != nil {
t.Fatalf("cleanup failed: %v", err)
}

if _, err := os.Stat(oldFile); !os.IsNotExist(err) {
t.Error("old file should be deleted")
}
if _, err := os.Stat(newFile); os.IsNotExist(err) {
t.Error("new file should exist")
}
}

func TestLevelString(t *testing.T) {
tests := []struct {
level    Level
expected string
}{
{LevelDebug, "debug"},
{LevelInfo, "info"},
{LevelWarn, "warn"},
{LevelError, "error"},
}

for _, tt := range tests {
got := tt.level.String()
if got != tt.expected {
t.Errorf("Level(%d).String() = %q, want %q", tt.level, got, tt.expected)
}
}
}
