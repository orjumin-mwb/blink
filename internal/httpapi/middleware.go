package httpapi

import (
	"net/http"
	"time"

	"github.com/olegrjumin/blink/internal/logging"
)

// responseWriter wraps http.ResponseWriter to capture the status code
type responseWriter struct {
	http.ResponseWriter
	status int
}

// WriteHeader captures the status code and calls the underlying WriteHeader
func (rw *responseWriter) WriteHeader(code int) {
	rw.status = code
	rw.ResponseWriter.WriteHeader(code)
}

// Flush implements http.Flusher to support SSE streaming
func (rw *responseWriter) Flush() {
	if flusher, ok := rw.ResponseWriter.(http.Flusher); ok {
		flusher.Flush()
	}
}

// loggingMiddleware logs each HTTP request with method, path, status, and duration
func loggingMiddleware(logger *logging.Logger, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Record the start time
		start := time.Now()

		// Wrap the ResponseWriter to capture status code
		wrapped := &responseWriter{
			ResponseWriter: w,
			status:         http.StatusOK, // Default status if WriteHeader isn't called
		}

		// Call the next handler
		next.ServeHTTP(wrapped, r)

		// Calculate duration
		duration := time.Since(start)

		// Log the request
		logger.Info("Request completed",
			"method", r.Method,
			"path", r.URL.Path,
			"status", wrapped.status,
			"duration_ms", duration.Milliseconds(),
		)
	})
}
