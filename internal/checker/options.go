package checker

import "time"

// CheckOptions holds optional parameters for URL checking
type CheckOptions struct {
	// Timeout for the entire check operation
	Timeout time.Duration

	// FollowRedirects controls whether to follow HTTP redirects
	FollowRedirects bool

	// MaxRedirects is the maximum number of redirects to follow
	MaxRedirects int

	// Method is the HTTP method to use (HEAD or GET)
	Method string

	// UserAgent is the User-Agent header to send
	UserAgent string
}

// DefaultOptions returns CheckOptions with sensible defaults
func DefaultOptions() CheckOptions {
	return CheckOptions{
		Timeout:         3 * time.Second,
		FollowRedirects: true,
		MaxRedirects:    5,
		Method:          "HEAD",
		UserAgent:       "blink-checker/1.0",
	}
}
