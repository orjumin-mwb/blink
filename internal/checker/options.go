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

// DeepCheckOptions holds options for deep checking
type DeepCheckOptions struct {
	// Inherit basic options
	CheckOptions

	// Runtime detection using headless browser
	EnableRuntimeDetection bool
	RuntimeTimeout         time.Duration

	// Analysis options
	AnalyzeJS       bool
	FetchExternalJS bool
	MaxJSFiles      int
	JSTimeout       time.Duration
}

// DefaultDeepCheckOptions returns DeepCheckOptions with sensible defaults
func DefaultDeepCheckOptions() DeepCheckOptions {
	return DeepCheckOptions{
		CheckOptions: CheckOptions{
			Timeout:         60 * time.Second, // Deep checks need longer by default
			FollowRedirects: true,
			MaxRedirects:    5,
			Method:          "GET",
			UserAgent:       "blink-checker/1.0",
		},
		EnableRuntimeDetection: true,
		RuntimeTimeout:         5 * time.Second,
		AnalyzeJS:              true,
		FetchExternalJS:        true,
		MaxJSFiles:             20,
		JSTimeout:              3 * time.Second,
	}
}
