package service

import (
	"context"
	"time"

	"github.com/olegrjumin/blink/internal/checker"
	"github.com/olegrjumin/blink/internal/logging"
)

// Service provides the business logic layer for URL checking
// It sits between the HTTP transport layer and the domain/checker layer
type Service struct {
	checker *checker.Checker
	logger  *logging.Logger
	options checker.CheckOptions
}

// New creates a new Service instance
func New(chk *checker.Checker, logger *logging.Logger, opts checker.CheckOptions) *Service {
	return &Service{
		checker: chk,
		logger:  logger,
		options: opts,
	}
}

// CheckURL performs a URL check with the given options
// This is the main entry point for the URL checking use case
func (s *Service) CheckURL(ctx context.Context, url string, opts *checker.CheckOptions) *checker.CheckResult {
	// Merge provided options with defaults
	finalOpts := s.mergeOptions(opts)

	// Create a context with timeout
	ctx, cancel := context.WithTimeout(ctx, finalOpts.Timeout)
	defer cancel()

	// Log the check request
	s.logger.Info("Checking URL", "url", url, "method", finalOpts.Method)

	// Perform the check using the checker
	result := s.checker.CheckURL(ctx, url, finalOpts)

	// Log the result
	s.logger.Info("Check completed",
		"url", url,
		"ok", result.OK,
		"status", result.Status,
		"error_type", result.ErrorType,
		"total_ms", result.TotalMs,
	)

	return result
}

// mergeOptions merges provided options with service defaults
// If opts is nil, returns service defaults
func (s *Service) mergeOptions(opts *checker.CheckOptions) checker.CheckOptions {
	if opts == nil {
		return s.options
	}

	// Start with defaults
	merged := s.options

	// Override with provided values (only if non-zero)
	if opts.Timeout > 0 {
		merged.Timeout = opts.Timeout
	}
	if opts.MaxRedirects > 0 {
		merged.MaxRedirects = opts.MaxRedirects
	}
	if opts.Method != "" {
		merged.Method = opts.Method
	}
	if opts.UserAgent != "" {
		merged.UserAgent = opts.UserAgent
	}

	// FollowRedirects is a boolean, so we need to check if it was explicitly set
	// For now, we'll just use the provided value
	merged.FollowRedirects = opts.FollowRedirects

	return merged
}

// mergeDeepOptions merges provided options with service defaults for deep check
func (s *Service) mergeDeepOptions(opts *checker.DeepCheckOptions) checker.DeepCheckOptions {
	if opts == nil {
		// Use defaults
		return checker.DeepCheckOptions{
			CheckOptions:           s.options,
			EnableRuntimeDetection: false,
			RuntimeTimeout:         5 * time.Second,
			AnalyzeJS:             true,
			FetchExternalJS:       true,
			MaxJSFiles:           20,
			JSTimeout:            3 * time.Second,
		}
	}

	// Start with provided options
	merged := *opts

	// Apply defaults where not specified
	if merged.Timeout == 0 {
		merged.Timeout = s.options.Timeout
	}
	if merged.UserAgent == "" {
		merged.UserAgent = s.options.UserAgent
	}
	if merged.MaxRedirects == 0 {
		merged.MaxRedirects = s.options.MaxRedirects
	}
	if merged.RuntimeTimeout == 0 {
		merged.RuntimeTimeout = 5 * time.Second
	}
	if merged.JSTimeout == 0 {
		merged.JSTimeout = 3 * time.Second
	}
	if merged.MaxJSFiles == 0 {
		merged.MaxJSFiles = 20
	}

	return merged
}

// DeepCheckURL performs a deep URL check with JavaScript analysis
func (s *Service) DeepCheckURL(ctx context.Context, url string, opts *checker.DeepCheckOptions) *checker.DeepCheckResult {
	// Merge provided options with defaults
	finalOpts := s.mergeDeepOptions(opts)

	// Create a context with timeout
	ctx, cancel := context.WithTimeout(ctx, finalOpts.Timeout)
	defer cancel()

	// Log the deep check request
	s.logger.Info("Deep checking URL", "url", url)

	// Perform the deep check using the checker
	result := s.checker.DeepCheckURL(ctx, url, finalOpts)

	// Log the result
	techCount := 0
	if result.Technologies != nil && result.Technologies.Stack != nil {
		techCount = len(result.Technologies.Stack)
	}
	trackerCount := 0
	if result.Tracking != nil && result.Tracking.Services != nil {
		trackerCount = len(result.Tracking.Services)
	}
	apiCount := 0
	if result.APIUsage != nil && result.APIUsage.Detected != nil {
		apiCount = len(result.APIUsage.Detected)
	}
	s.logger.Info("Deep check completed",
		"url", url,
		"apis", apiCount,
		"trackers", trackerCount,
		"technologies", techCount,
		"duration", result.AnalysisDuration,
	)

	return result
}

// DeepCheckURLStreaming performs JavaScript analysis with streaming results
func (s *Service) DeepCheckURLStreaming(ctx context.Context, url string, opts *checker.DeepCheckOptions, resultChan chan<- checker.StreamEvent) {
	// Merge options (using default options for streaming)
	finalOpts := s.mergeDeepOptions(opts)

	// Create context with timeout
	ctx, cancel := context.WithTimeout(ctx, finalOpts.Timeout)
	defer cancel()

	// Log the streaming deep check request
	s.logger.Info("Deep check streaming request", "url", url)

	// Create internal channel for checker events
	checkerEvents := make(chan checker.StreamEvent, 10)

	// Forward events from checker to service channel
	go func() {
		for evt := range checkerEvents {
			select {
			case resultChan <- evt:
			case <-ctx.Done():
				return
			}
		}
		close(resultChan)
	}()

	// Perform streaming deep check
	s.checker.DeepCheckURLStreaming(ctx, url, finalOpts, checkerEvents)
}
