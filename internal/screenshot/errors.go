package screenshot

import "errors"

var (
	// ErrBrowserUnavailable indicates the browser pool is exhausted
	ErrBrowserUnavailable = errors.New("browser pool exhausted")

	// ErrNavigationFailed indicates the page failed to load
	ErrNavigationFailed = errors.New("page navigation failed")

	// ErrScreenshotFailed indicates the screenshot capture failed
	ErrScreenshotFailed = errors.New("screenshot capture failed")

	// ErrTimeout indicates the operation timed out
	ErrTimeout = errors.New("screenshot operation timed out")

	// ErrInvalidURL indicates the provided URL is invalid
	ErrInvalidURL = errors.New("invalid URL provided")

	// ErrStorageFailed indicates filesystem storage operation failed
	ErrStorageFailed = errors.New("failed to store screenshot")
)