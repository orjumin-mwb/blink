package screenshot

import (
	"bytes"
	"context"
	"crypto/md5"
	"encoding/base64"
	"fmt"
	"image/png"
	"os"
	"path/filepath"
	"time"

	"github.com/buckket/go-blurhash"
	"github.com/chromedp/chromedp"
	"github.com/olegrjumin/blink/internal/logging"
)

// Screenshotter handles screenshot capture operations
type Screenshotter struct {
	pool        *BrowserPool
	storageDir  string
	logger      *logging.Logger
}

// New creates a new Screenshotter instance
func New(poolSize int, storageDir string) (*Screenshotter, error) {
	// Ensure storage directory exists
	if err := os.MkdirAll(storageDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create storage directory: %w", err)
	}

	// Create browser pool
	pool, err := NewBrowserPool(poolSize)
	if err != nil {
		return nil, fmt.Errorf("failed to create browser pool: %w", err)
	}

	return &Screenshotter{
		pool:       pool,
		storageDir: storageDir,
		logger:     logging.New(),
	}, nil
}

// Capture takes a screenshot of the specified URL
func (s *Screenshotter) Capture(ctx context.Context, opts *Options) (*Result, error) {
	start := time.Now()

	// Validate options
	if err := opts.Validate(); err != nil {
		return &Result{
			Success: false,
			URL:     opts.URL,
			Error:   err.Error(),
		}, err
	}

	// Get browser from pool
	browser, err := s.pool.Acquire(ctx)
	if err != nil {
		s.logger.Error("Failed to acquire browser from pool",
			"url", opts.URL,
			"error", err.Error(),
			"pool_size", s.pool.Size())
		return &Result{
			Success: false,
			URL:     opts.URL,
			Error:   ErrBrowserUnavailable.Error(),
		}, ErrBrowserUnavailable
	}
	defer s.pool.Release(browser)

	// Create timeout context using browser's context
	timeoutCtx, cancel := context.WithTimeout(browser.Context(), opts.Timeout)
	defer cancel()

	// Capture screenshot
	var buf []byte
	err = chromedp.Run(timeoutCtx,
		chromedp.EmulateViewport(int64(opts.Width), int64(opts.Height)),
		chromedp.Navigate(opts.URL),
		chromedp.WaitVisible(`body`, chromedp.ByQuery),
		chromedp.CaptureScreenshot(&buf),
	)

	if err != nil {
		// Mark browser instance as potentially unhealthy
		s.pool.MarkUnhealthy(browser)

		if timeoutCtx.Err() == context.DeadlineExceeded {
			s.logger.Error("Screenshot capture timed out",
				"url", opts.URL,
				"timeout", opts.Timeout,
				"error", err.Error())
			return &Result{
				Success: false,
				URL:     opts.URL,
				Error:   ErrTimeout.Error(),
			}, ErrTimeout
		}
		s.logger.Error("Screenshot capture failed",
			"url", opts.URL,
			"error", err.Error())
		return &Result{
			Success: false,
			URL:     opts.URL,
			Error:   ErrScreenshotFailed.Error(),
		}, ErrScreenshotFailed
	}

	captureTime := time.Since(start).Milliseconds()

	// Decode PNG and generate blurhash
	img, err := png.Decode(bytes.NewReader(buf))
	if err != nil {
		// Log error but don't fail - blurhash is optional enhancement
		// Screenshot can still succeed without blurhash
		s.logger.Error("Failed to decode PNG for blurhash generation",
			"url", opts.URL,
			"error", err.Error(),
			"screenshot_size", len(buf))
	}

	var blurHashStr string
	var imgWidth, imgHeight int

	if img != nil {
		imgWidth = img.Bounds().Dx()
		imgHeight = img.Bounds().Dy()

		// Generate blurhash (4x3 components for quality/size balance)
		hash, err := blurhash.Encode(4, 3, img)
		if err != nil {
			// Log error but don't fail - blurhash is optional
			s.logger.Error("Failed to generate blurhash",
				"url", opts.URL,
				"error", err.Error(),
				"image_width", imgWidth,
				"image_height", imgHeight)
		} else {
			blurHashStr = hash
			s.logger.Info("Blurhash generated successfully",
				"url", opts.URL,
				"blurhash_length", len(hash),
				"image_dimensions", fmt.Sprintf("%dx%d", imgWidth, imgHeight))
		}
	}

	result := &Result{
		Success:       true,
		SizeBytes:     int64(len(buf)),
		CaptureTimeMs: captureTime,
		URL:           opts.URL,
		ResponseType:  opts.ResponseType,
		BlurHash:      blurHashStr,
		Width:         imgWidth,
		Height:        imgHeight,
	}

	// Log successful capture
	s.logger.Info("Screenshot captured successfully",
		"url", opts.URL,
		"capture_time_ms", captureTime,
		"size_bytes", len(buf),
		"has_blurhash", blurHashStr != "",
		"dimensions", fmt.Sprintf("%dx%d", imgWidth, imgHeight))

	// Handle response type
	if opts.ResponseType == "base64" {
		// Return base64 encoded data
		mimeType := "image/jpeg"
		if opts.Format == "png" {
			mimeType = "image/png"
		} else if opts.Format == "webp" {
			mimeType = "image/webp"
		}
		result.Base64Data = fmt.Sprintf("data:%s;base64,%s", mimeType, base64.StdEncoding.EncodeToString(buf))
	} else {
		// Save to filesystem
		filePath, err := s.saveScreenshot(buf, opts.URL, opts.Format)
		if err != nil {
			return &Result{
				Success: false,
				URL:     opts.URL,
				Error:   ErrStorageFailed.Error(),
			}, ErrStorageFailed
		}
		result.FilePath = filePath
	}

	return result, nil
}

// saveScreenshot saves the screenshot to the filesystem
func (s *Screenshotter) saveScreenshot(data []byte, url, format string) (string, error) {
	// Create date-based subdirectory
	now := time.Now()
	dateDir := now.Format("2006-01-02")
	fullDir := filepath.Join(s.storageDir, dateDir)

	if err := os.MkdirAll(fullDir, 0755); err != nil {
		return "", err
	}

	// Generate filename from URL hash
	hash := md5.Sum([]byte(url))
	filename := fmt.Sprintf("%x.%s", hash, format)
	filePath := filepath.Join(fullDir, filename)

	// Write file
	if err := os.WriteFile(filePath, data, 0644); err != nil {
		return "", err
	}

	// Return relative path for API response
	return filepath.Join("/screenshots", dateDir, filename), nil
}

// Close shuts down the screenshotter and its browser pool
func (s *Screenshotter) Close() error {
	if s.pool != nil {
		return s.pool.Close()
	}
	return nil
}

// CleanupOldScreenshots removes screenshots older than the specified duration
func (s *Screenshotter) CleanupOldScreenshots(maxAge time.Duration) error {
	cutoff := time.Now().Add(-maxAge)

	return filepath.Walk(s.storageDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		// Skip directories
		if info.IsDir() {
			return nil
		}

		// Remove old files
		if info.ModTime().Before(cutoff) {
			os.Remove(path)
		}

		return nil
	})
}