package screenshot

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestScreenshotter(t *testing.T) {
	// Skip test if running in CI without Chrome
	if os.Getenv("CI") == "true" {
		t.Skip("Skipping browser test in CI")
	}

	// Create a temporary directory for screenshots
	tempDir, err := os.MkdirTemp("", "screenshot-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	// Create screenshotter with a small pool
	screenshotter, err := New(2, tempDir)
	if err != nil {
		t.Fatalf("Failed to create screenshotter: %v", err)
	}
	defer screenshotter.Close()

	// Test screenshot capture
	opts := &Options{
		URL:       "https://example.com",
		Format:    "jpeg",
		Quality:   75,
		Width:     1280,
		Height:    720,
		TimeoutMs: 5000,
		Timeout:   5 * time.Second,
	}

	ctx := context.Background()
	result, err := screenshotter.Capture(ctx, opts)
	if err != nil {
		t.Fatalf("Failed to capture screenshot: %v", err)
	}

	// Verify result
	if !result.Success {
		t.Errorf("Expected success to be true, got false")
	}

	if result.FilePath == "" {
		t.Errorf("Expected file path to be set")
	}

	if result.SizeBytes <= 0 {
		t.Errorf("Expected size to be greater than 0, got %d", result.SizeBytes)
	}

	if result.CaptureTimeMs <= 0 {
		t.Errorf("Expected capture time to be greater than 0, got %d", result.CaptureTimeMs)
	}

	// Verify file exists
	fullPath := filepath.Join(tempDir, result.FilePath[len("/screenshots"):])
	if _, err := os.Stat(fullPath); os.IsNotExist(err) {
		t.Errorf("Screenshot file does not exist: %s", fullPath)
	}
}

func TestBrowserPool(t *testing.T) {
	// Skip test if running in CI without Chrome
	if os.Getenv("CI") == "true" {
		t.Skip("Skipping browser test in CI")
	}

	// Create a small pool
	pool, err := NewBrowserPool(3)
	if err != nil {
		t.Fatalf("Failed to create browser pool: %v", err)
	}
	defer pool.Close()

	// Test health
	available, total := pool.Health()
	if total != 3 {
		t.Errorf("Expected total instances to be 3, got %d", total)
	}
	if available != 3 {
		t.Errorf("Expected available instances to be 3, got %d", available)
	}

	// Test acquire and release
	ctx := context.Background()
	instance1, err := pool.Acquire(ctx)
	if err != nil {
		t.Fatalf("Failed to acquire instance: %v", err)
	}

	available, _ = pool.Health()
	if available != 2 {
		t.Errorf("Expected available instances to be 2 after acquire, got %d", available)
	}

	pool.Release(instance1)

	available, _ = pool.Health()
	if available != 3 {
		t.Errorf("Expected available instances to be 3 after release, got %d", available)
	}
}

func TestOptionsValidation(t *testing.T) {
	tests := []struct {
		name    string
		opts    *Options
		wantErr bool
	}{
		{
			name:    "Empty URL",
			opts:    &Options{},
			wantErr: true,
		},
		{
			name: "Valid options",
			opts: &Options{
				URL:       "https://example.com",
				Format:    "jpeg",
				Quality:   85,
				Width:     1920,
				Height:    1080,
				TimeoutMs: 5000,
			},
			wantErr: false,
		},
		{
			name: "Default values applied",
			opts: &Options{
				URL: "https://example.com",
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.opts.Validate()
			if (err != nil) != tt.wantErr {
				t.Errorf("Validate() error = %v, wantErr %v", err, tt.wantErr)
			}

			// Check defaults are applied
			if !tt.wantErr && tt.opts.Format == "" {
				t.Errorf("Expected format to be set to default")
			}
		})
	}
}