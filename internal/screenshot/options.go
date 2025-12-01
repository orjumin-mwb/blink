package screenshot

import "time"

// Options defines screenshot capture options
type Options struct {
	URL          string        `json:"url"`
	Format       string        `json:"format"`
	Quality      int           `json:"quality"`
	Width        int           `json:"width"`
	Height       int           `json:"height"`
	TimeoutMs    int           `json:"timeout_ms"`
	Timeout      time.Duration `json:"-"`
	ResponseType string        `json:"response_type"` // "file_path" or "base64"
}

// DefaultOptions returns speed-optimized default options
func DefaultOptions() *Options {
	return &Options{
		Format:       "jpeg",
		Quality:      75,          // Lower quality for speed
		Width:        1280,        // Fixed viewport
		Height:       720,         // Fixed viewport
		TimeoutMs:    3000,        // 3 second timeout
		Timeout:      3 * time.Second,
		ResponseType: "file_path", // Default to file path for backward compatibility
	}
}

// Validate ensures options are within acceptable ranges
func (o *Options) Validate() error {
	if o.URL == "" {
		return ErrInvalidURL
	}

	// Set defaults if not provided
	if o.Format == "" {
		o.Format = "jpeg"
	}
	if o.Quality <= 0 || o.Quality > 100 {
		o.Quality = 75
	}
	if o.Width <= 0 {
		o.Width = 1280
	}
	if o.Height <= 0 {
		o.Height = 720
	}
	if o.TimeoutMs <= 0 {
		o.TimeoutMs = 3000
	}
	o.Timeout = time.Duration(o.TimeoutMs) * time.Millisecond

	// Validate response type
	if o.ResponseType == "" {
		o.ResponseType = "file_path"
	}
	if o.ResponseType != "file_path" && o.ResponseType != "base64" {
		o.ResponseType = "file_path"
	}

	return nil
}

// Result represents a screenshot capture result
type Result struct {
	Success       bool   `json:"success"`
	FilePath      string `json:"file_path,omitempty"`
	Base64Data    string `json:"base64_data,omitempty"`
	SizeBytes     int64  `json:"size_bytes,omitempty"`
	CaptureTimeMs int64  `json:"capture_time_ms,omitempty"`
	URL           string `json:"url"`
	Error         string `json:"error,omitempty"`
	ResponseType  string `json:"response_type,omitempty"`
	BlurHash      string `json:"blurhash,omitempty"`  // BlurHash for progressive loading
	Width         int    `json:"width,omitempty"`     // Image dimensions for decode
	Height        int    `json:"height,omitempty"`    // Image dimensions for decode
}