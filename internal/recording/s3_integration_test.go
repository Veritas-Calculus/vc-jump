//go:build integration

// Package recording provides session recording functionality for audit and playback.
// This file contains S3 integration tests using LocalStack as the S3-compatible backend.
package recording

import (
	"bytes"
	"context"
	"crypto/rand"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/Veritas-Calculus/vc-jump/internal/config"
)

// Integration tests for S3 storage.
// Run with: go test -v -tags=integration ./internal/recording/...
// Requires environment variables:
//   TEST_S3_ENDPOINT, TEST_S3_BUCKET, TEST_S3_REGION, TEST_S3_ACCESS_KEY, TEST_S3_SECRET_KEY
//
// For local testing with LocalStack:
//   docker run -d -p 4566:4566 -e SERVICES=s3 localstack/localstack
//   aws --endpoint-url=http://localhost:4566 s3 mb s3://test-recordings

func getS3TestConfig(t *testing.T) config.S3Config {
	t.Helper()

	endpoint := os.Getenv("TEST_S3_ENDPOINT")
	bucket := os.Getenv("TEST_S3_BUCKET")
	region := os.Getenv("TEST_S3_REGION")
	accessKey := os.Getenv("TEST_S3_ACCESS_KEY")
	secretKey := os.Getenv("TEST_S3_SECRET_KEY")
	forcePathStyle := os.Getenv("TEST_S3_FORCE_PATH_STYLE") == "true"

	if endpoint == "" || bucket == "" || accessKey == "" || secretKey == "" {
		t.Skip("S3 integration test environment variables not set")
	}

	if region == "" {
		region = "us-east-1"
	}

	return config.S3Config{
		Endpoint:        endpoint,
		Bucket:          bucket,
		Region:          region,
		AccessKeyID:     accessKey,
		SecretAccessKey: secretKey,
		ForcePathStyle:  forcePathStyle,
		Prefix:          "integration-tests",
	}
}

func TestS3Storage_Integration_SaveLoadDelete(t *testing.T) {
	cfg := getS3TestConfig(t)

	storage, err := NewS3Storage(cfg)
	if err != nil {
		t.Fatalf("failed to create S3 storage: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	filename := "test_integration_20231201_120000.cast"
	testData := []byte(`{"version":2,"username":"testuser","hostname":"testhost"}
{"time":0,"type":"o","data":"Hello, World!"}
{"time":100,"type":"o","data":"Integration test complete."}`)

	// Test Save.
	t.Run("Save", func(t *testing.T) {
		err := storage.Save(ctx, filename, testData)
		if err != nil {
			t.Fatalf("failed to save recording: %v", err)
		}
	})

	// Test Load.
	t.Run("Load", func(t *testing.T) {
		loaded, err := storage.Load(ctx, filename)
		if err != nil {
			t.Fatalf("failed to load recording: %v", err)
		}
		if string(loaded) != string(testData) {
			t.Errorf("data mismatch:\ngot:  %s\nwant: %s", loaded, testData)
		}
	})

	// Test List.
	t.Run("List", func(t *testing.T) {
		files, err := storage.List(ctx)
		if err != nil {
			t.Fatalf("failed to list recordings: %v", err)
		}

		found := false
		for _, f := range files {
			if f == filename {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("uploaded file not found in list: %v", files)
		}
	})

	// Test Delete.
	t.Run("Delete", func(t *testing.T) {
		err := storage.Delete(ctx, filename)
		if err != nil {
			t.Fatalf("failed to delete recording: %v", err)
		}

		// Verify deleted.
		_, err = storage.Load(ctx, filename)
		if err == nil {
			t.Error("expected error loading deleted file")
		}
	})
}

func TestS3Storage_Integration_MultipleFiles(t *testing.T) {
	cfg := getS3TestConfig(t)

	storage, err := NewS3Storage(cfg)
	if err != nil {
		t.Fatalf("failed to create S3 storage: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	// Create multiple files.
	files := []string{
		"multi_test_file1.cast",
		"multi_test_file2.cast",
		"multi_test_file3.cast",
	}

	for _, filename := range files {
		data := []byte(`{"version":2,"filename":"` + filename + `"}`)
		if err := storage.Save(ctx, filename, data); err != nil {
			t.Fatalf("failed to save %s: %v", filename, err)
		}
	}

	// List and verify.
	list, err := storage.List(ctx)
	if err != nil {
		t.Fatalf("failed to list files: %v", err)
	}

	for _, filename := range files {
		found := false
		for _, f := range list {
			if f == filename {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("file %s not found in list", filename)
		}
	}

	// Cleanup.
	for _, filename := range files {
		if err := storage.Delete(ctx, filename); err != nil {
			t.Errorf("failed to delete %s: %v", filename, err)
		}
	}
}

func TestS3Storage_Integration_LargeFile(t *testing.T) {
	cfg := getS3TestConfig(t)

	storage, err := NewS3Storage(cfg)
	if err != nil {
		t.Fatalf("failed to create S3 storage: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()

	filename := "large_test_file.cast"

	// Create a 5MB file.
	data := make([]byte, 5*1024*1024)
	for i := range data {
		data[i] = byte(i % 256)
	}

	// Save large file.
	if err := storage.Save(ctx, filename, data); err != nil {
		t.Fatalf("failed to save large file: %v", err)
	}

	// Load and verify.
	loaded, err := storage.Load(ctx, filename)
	if err != nil {
		t.Fatalf("failed to load large file: %v", err)
	}

	if len(loaded) != len(data) {
		t.Errorf("size mismatch: got %d, want %d", len(loaded), len(data))
	}

	// Cleanup.
	if err := storage.Delete(ctx, filename); err != nil {
		t.Errorf("failed to delete large file: %v", err)
	}
}

func TestS3Storage_Integration_SecurityValidation(t *testing.T) {
	cfg := getS3TestConfig(t)

	storage, err := NewS3Storage(cfg)
	if err != nil {
		t.Fatalf("failed to create S3 storage: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Test that malicious filenames are rejected.
	maliciousNames := []string{
		"../../../etc/passwd.cast",
		"path/to/file.cast",
		"file\x00null.cast",
		"",
	}

	for _, filename := range maliciousNames {
		t.Run("Reject_"+filename, func(t *testing.T) {
			err := storage.Save(ctx, filename, []byte("test"))
			if err == nil {
				t.Errorf("expected error for malicious filename: %q", filename)
				// Cleanup if accidentally created.
				_ = storage.Delete(ctx, filename)
			}
		})
	}
}

func TestS3Storage_Integration_ConcurrentAccess(t *testing.T) {
	cfg := getS3TestConfig(t)

	storage, err := NewS3Storage(cfg)
	if err != nil {
		t.Fatalf("failed to create S3 storage: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()

	const numGoroutines = 10
	var wg sync.WaitGroup
	errChan := make(chan error, numGoroutines*2)

	// Concurrent writes.
	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			filename := "concurrent_test_" + string(rune('A'+idx)) + ".cast"
			data := make([]byte, 1024)
			rand.Read(data)
			if err := storage.Save(ctx, filename, data); err != nil {
				errChan <- err
				return
			}
			// Read back.
			loaded, err := storage.Load(ctx, filename)
			if err != nil {
				errChan <- err
				return
			}
			if !bytes.Equal(loaded, data) {
				errChan <- err
			}
			// Cleanup.
			_ = storage.Delete(ctx, filename)
		}(i)
	}

	wg.Wait()
	close(errChan)

	for err := range errChan {
		if err != nil {
			t.Errorf("concurrent access error: %v", err)
		}
	}
}
