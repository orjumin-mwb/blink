package httpapi

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/olegrjumin/blink/internal/checker"
	"github.com/olegrjumin/blink/internal/service"
)

// checkRequest represents the JSON request body for /check endpoint
type checkRequest struct {
	URL             string `json:"url"`
	FollowRedirects *bool  `json:"follow_redirects,omitempty"`
	MaxRedirects    *int   `json:"max_redirects,omitempty"`
	Method          string `json:"method,omitempty"`
	TimeoutMs       *int   `json:"timeout_ms,omitempty"`
}

// checkHandler handles POST requests to /check
// Accepts a JSON body with a URL and optional parameters, returns check results
func checkHandler(svc *service.Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Only accept POST requests
		if r.Method != http.MethodPost {
			writeJSON(w, http.StatusMethodNotAllowed, map[string]string{
				"error": "Method not allowed",
			})
			return
		}

		// Parse JSON request body
		var req checkRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{
				"error": "Invalid JSON",
			})
			return
		}

		// Trim whitespace from URL
		req.URL = strings.TrimSpace(req.URL)

		// Validate that URL is provided
		if req.URL == "" {
			writeJSON(w, http.StatusBadRequest, map[string]string{
				"error": "URL is required",
			})
			return
		}

		// Build options from request
		var opts *checker.CheckOptions
		if req.FollowRedirects != nil || req.MaxRedirects != nil || req.Method != "" || req.TimeoutMs != nil {
			defaultOpts := checker.DefaultOptions()
			opts = &defaultOpts

			if req.FollowRedirects != nil {
				opts.FollowRedirects = *req.FollowRedirects
			}
			if req.MaxRedirects != nil {
				opts.MaxRedirects = *req.MaxRedirects
			}
			if req.Method != "" {
				opts.Method = req.Method
			}
			// Note: Timeout is handled by service layer
		}

		// Perform the check through the service layer
		result := svc.CheckURL(r.Context(), req.URL, opts)

		// Return the result
		writeJSON(w, http.StatusOK, result)
	}
}

// deepCheckRequest represents the JSON request body for /deep-check endpoint
type deepCheckRequest struct {
	URL                    string `json:"url"`
	FollowRedirects        *bool  `json:"follow_redirects,omitempty"`
	MaxRedirects           *int   `json:"max_redirects,omitempty"`
	TimeoutMs              *int   `json:"timeout_ms,omitempty"`
	// Runtime detection options
	EnableRuntimeDetection *bool  `json:"runtime_detection,omitempty"`
	RuntimeTimeoutMs       *int   `json:"runtime_timeout_ms,omitempty"`
	// Note: Method is always GET for deep check
}

// deepCheckHandler handles POST requests to /deep-check
// Performs JavaScript and browser API analysis with optional streaming
func deepCheckHandler(svc *service.Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Only accept POST requests
		if r.Method != http.MethodPost {
			writeJSON(w, http.StatusMethodNotAllowed, map[string]string{
				"error": "Method not allowed",
			})
			return
		}

		// Parse JSON request body
		var req deepCheckRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{
				"error": "Invalid JSON",
			})
			return
		}

		// Trim whitespace from URL
		req.URL = strings.TrimSpace(req.URL)

		// Validate that URL is provided
		if req.URL == "" {
			writeJSON(w, http.StatusBadRequest, map[string]string{
				"error": "URL is required",
			})
			return
		}

		// Check if client accepts streaming (SSE)
		acceptHeader := r.Header.Get("Accept")
		if acceptHeader == "text/event-stream" {
			// Set headers for SSE
			w.Header().Set("Content-Type", "text/event-stream")
			w.Header().Set("Cache-Control", "no-cache")
			w.Header().Set("Connection", "keep-alive")
			w.Header().Set("Access-Control-Allow-Origin", "*")

			// Create flusher
			flusher, ok := w.(http.Flusher)
			if !ok {
				writeJSON(w, http.StatusInternalServerError, map[string]string{
					"error": "Streaming not supported",
				})
				return
			}

			// Create channel for streaming results
			resultChan := make(chan checker.StreamEvent, 10)

			// Build deep check options
			var opts *checker.DeepCheckOptions
			defaultOpts := checker.DefaultDeepCheckOptions()
			opts = &defaultOpts

			if req.FollowRedirects != nil {
				opts.FollowRedirects = *req.FollowRedirects
			}
			if req.MaxRedirects != nil {
				opts.MaxRedirects = *req.MaxRedirects
			}
			if req.EnableRuntimeDetection != nil {
				opts.EnableRuntimeDetection = *req.EnableRuntimeDetection
			}
			if req.RuntimeTimeoutMs != nil {
				opts.RuntimeTimeout = time.Duration(*req.RuntimeTimeoutMs) * time.Millisecond
			}

			// Start streaming analysis
			go svc.DeepCheckURLStreaming(r.Context(), req.URL, opts, resultChan)

			// Stream events to client
			for event := range resultChan {
				// Marshal event data
				data, err := json.Marshal(event.Data)
				if err != nil {
					continue
				}

				// Send SSE event
				fmt.Fprintf(w, "event: %s\n", event.Stage)
				fmt.Fprintf(w, "data: %s\n\n", data)
				flusher.Flush()
			}

			// Send final done event
			fmt.Fprintf(w, "event: done\n")
			fmt.Fprintf(w, "data: {}\n\n")
			flusher.Flush()

			return
		}

		// Non-streaming response (backwards compatible)
		// Build deep check options from request (force GET method for deep check)
		var opts *checker.DeepCheckOptions
		defaultOpts := checker.DefaultDeepCheckOptions()
		opts = &defaultOpts
		opts.Method = "GET" // Always use GET for deep check

		if req.FollowRedirects != nil {
			opts.FollowRedirects = *req.FollowRedirects
		}
		if req.MaxRedirects != nil {
			opts.MaxRedirects = *req.MaxRedirects
		}
		if req.EnableRuntimeDetection != nil {
			opts.EnableRuntimeDetection = *req.EnableRuntimeDetection
		}
		if req.RuntimeTimeoutMs != nil {
			opts.RuntimeTimeout = time.Duration(*req.RuntimeTimeoutMs) * time.Millisecond
		}
		// Note: Timeout is handled by service layer

		// Perform the deep check through the service layer
		result := svc.DeepCheckURL(r.Context(), req.URL, opts)

		// Return the result
		writeJSON(w, http.StatusOK, result)
	}
}
