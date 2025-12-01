package service

import (
	"context"

	"github.com/olegrjumin/blink/internal/checker"
	"github.com/olegrjumin/blink/internal/logging"
)

// StreamEvent represents a progressive event during URL checking
type StreamEvent struct {
	Stage   string      `json:"stage"`   // "start", "dns", "tcp", "tls", "response", "complete", "error"
	Message string      `json:"message"` // Human-readable message
	Data    interface{} `json:"data"`    // Stage-specific data or final result
}

// StreamingService wraps the standard Service to provide streaming capabilities
type StreamingService struct {
	service *Service
	logger  *logging.Logger
}

// NewStreamingService creates a new StreamingService
func NewStreamingService(svc *Service, logger *logging.Logger) *StreamingService {
	return &StreamingService{
		service: svc,
		logger:  logger,
	}
}

// CheckURLStreaming performs a URL check and emits progressive events in real-time
// Returns a channel that receives events as the check progresses
func (s *StreamingService) CheckURLStreaming(ctx context.Context, url string, opts *checker.CheckOptions) <-chan StreamEvent {
	events := make(chan StreamEvent, 10)

	go func() {
		defer close(events)

		// Send start event immediately
		select {
		case events <- StreamEvent{
			Stage:   "start",
			Message: "Starting check...",
			Data:    map[string]string{"url": url},
		}:
		case <-ctx.Done():
			return
		}

		// Merge options
		finalOpts := s.service.mergeOptions(opts)

		// Use the streaming checker for real-time events
		// Convert service events to checker events
		checkerEvents := make(chan checker.StreamEvent, 10)

		// Forward events from checker to service events
		done := make(chan struct{})
		go func() {
			defer close(done)
			for evt := range checkerEvents {
				select {
				case events <- StreamEvent{
					Stage:   evt.Stage,
					Message: evt.Message,
					Data:    evt.Data,
				}:
				case <-ctx.Done():
					return
				}
			}
		}()

		// Run the checker (this will close checkerEvents when done)
		s.service.checker.CheckURLStreaming(ctx, url, finalOpts, checkerEvents)

		// Wait for event forwarding to complete
		<-done
	}()

	return events
}
