package screenshot

import (
	"context"
	"os"
	"testing"
	"time"
)

func BenchmarkScreenshotCapture(b *testing.B) {
	// Skip if running in CI without Chrome
	if os.Getenv("CI") == "true" {
		b.Skip("Skipping browser benchmark in CI")
	}

	// Create a temporary directory for screenshots
	tempDir, err := os.MkdirTemp("", "screenshot-bench-*")
	if err != nil {
		b.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	// Create screenshotter with a large pool for speed
	screenshotter, err := New(10, tempDir)
	if err != nil {
		b.Fatalf("Failed to create screenshotter: %v", err)
	}
	defer screenshotter.Close()

	opts := &Options{
		URL:       "https://example.com",
		Format:    "jpeg",
		Quality:   75,
		Width:     1280,
		Height:    720,
		TimeoutMs: 3000,
		Timeout:   3 * time.Second,
	}

	ctx := context.Background()

	// Reset timer after setup
	b.ResetTimer()

	// Run benchmark
	for i := 0; i < b.N; i++ {
		result, err := screenshotter.Capture(ctx, opts)
		if err != nil {
			b.Fatalf("Failed to capture screenshot: %v", err)
		}
		if !result.Success {
			b.Fatalf("Screenshot capture was not successful")
		}
	}

	// Report custom metrics
	b.ReportAllocs()
}

func BenchmarkParallelScreenshots(b *testing.B) {
	// Skip if running in CI without Chrome
	if os.Getenv("CI") == "true" {
		b.Skip("Skipping browser benchmark in CI")
	}

	// Create a temporary directory for screenshots
	tempDir, err := os.MkdirTemp("", "screenshot-bench-parallel-*")
	if err != nil {
		b.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	// Create screenshotter with a large pool for speed
	screenshotter, err := New(10, tempDir)
	if err != nil {
		b.Fatalf("Failed to create screenshotter: %v", err)
	}
	defer screenshotter.Close()

	opts := &Options{
		URL:       "https://example.com",
		Format:    "jpeg",
		Quality:   75,
		Width:     1280,
		Height:    720,
		TimeoutMs: 3000,
		Timeout:   3 * time.Second,
	}

	ctx := context.Background()

	// Reset timer after setup
	b.ResetTimer()

	// Run benchmark in parallel
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			result, err := screenshotter.Capture(ctx, opts)
			if err != nil {
				b.Errorf("Failed to capture screenshot: %v", err)
			}
			if !result.Success {
				b.Errorf("Screenshot capture was not successful")
			}
		}
	})

	// Report custom metrics
	b.ReportAllocs()
}