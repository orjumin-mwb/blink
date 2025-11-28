package service

import (
	"context"

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
