package screenshot

import (
	"context"
	"log"
	"os"
	"path/filepath"
	"time"
)

// CleanupService manages automatic deletion of old screenshots
type CleanupService struct {
	dir       string
	maxAge    time.Duration
	interval  time.Duration
	ctx       context.Context
	cancel    context.CancelFunc
}

// NewCleanupService creates a new cleanup service
func NewCleanupService(dir string, maxAge, interval time.Duration) *CleanupService {
	ctx, cancel := context.WithCancel(context.Background())
	return &CleanupService{
		dir:      dir,
		maxAge:   maxAge,
		interval: interval,
		ctx:      ctx,
		cancel:   cancel,
	}
}

// Start begins the automatic cleanup process
func (c *CleanupService) Start() {
	go func() {
		// Run cleanup immediately on start
		c.cleanup()

		// Then run periodically
		ticker := time.NewTicker(c.interval)
		defer ticker.Stop()

		for {
			select {
			case <-ticker.C:
				c.cleanup()
			case <-c.ctx.Done():
				return
			}
		}
	}()
}

// Stop stops the cleanup service
func (c *CleanupService) Stop() {
	c.cancel()
}

// cleanup removes old screenshots
func (c *CleanupService) cleanup() {
	cutoff := time.Now().Add(-c.maxAge)
	deletedCount := 0
	deletedSize := int64(0)

	err := filepath.Walk(c.dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil // Skip files with errors
		}

		// Skip directories
		if info.IsDir() {
			// Remove empty directories older than cutoff
			if path != c.dir && info.ModTime().Before(cutoff) {
				entries, _ := os.ReadDir(path)
				if len(entries) == 0 {
					os.Remove(path)
				}
			}
			return nil
		}

		// Remove old files
		if info.ModTime().Before(cutoff) {
			size := info.Size()
			if err := os.Remove(path); err == nil {
				deletedCount++
				deletedSize += size
			}
		}

		return nil
	})

	if err != nil {
		log.Printf("Cleanup error: %v", err)
	}

	if deletedCount > 0 {
		log.Printf("Cleanup: deleted %d files (%.2f MB)", deletedCount, float64(deletedSize)/1024/1024)
	}
}