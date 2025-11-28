package httpapi

import (
	"encoding/json"
	"net/http"

	"github.com/olegrjumin/blink/internal/logging"
	"github.com/olegrjumin/blink/internal/service"
)

// NewServer creates and configures a new HTTP server
func NewServer(addr string, logger *logging.Logger, svc *service.Service) *http.Server {
	// Create a new router (multiplexer) to handle different routes
	mux := http.NewServeMux()

	// Register the health endpoint
	mux.HandleFunc("/health", healthHandler)

	// Register the check endpoint
	mux.HandleFunc("/check", checkHandler(svc))

	// Register the deep-check endpoint
	mux.HandleFunc("/deep-check", deepCheckHandler(svc))

	// Wrap the mux with logging middleware
	handler := loggingMiddleware(logger, mux)

	// Create and return the HTTP server
	return &http.Server{
		Addr:    addr,
		Handler: handler,
	}
}

// healthHandler handles GET requests to /health
// Returns a simple JSON response indicating the service is healthy
func healthHandler(w http.ResponseWriter, r *http.Request) {
	// Create the response data
	response := map[string]string{
		"status":  "ok",
		"service": "linkchecker-api",
	}

	// Write JSON response
	writeJSON(w, http.StatusOK, response)
}

// writeJSON is a helper function to write JSON responses
// It sets the correct Content-Type header and encodes the data as JSON
func writeJSON(w http.ResponseWriter, status int, data interface{}) {
	// Set Content-Type header to application/json
	w.Header().Set("Content-Type", "application/json")

	// Set the HTTP status code
	w.WriteHeader(status)

	// Encode the data as JSON and write to response
	// If encoding fails, the error is ignored (acceptable for this simple case)
	json.NewEncoder(w).Encode(data)
}
