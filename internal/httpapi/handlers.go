package httpapi

import (
	"encoding/json"
	"net/http"

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
