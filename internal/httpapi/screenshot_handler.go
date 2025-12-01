package httpapi

import (
	"encoding/json"
	"net/http"

	"github.com/olegrjumin/blink/internal/screenshot"
)

// screenshotHandler handles POST requests to /screenshot
// Accepts a JSON body with a URL and optional parameters, returns screenshot result
func screenshotHandler(screenshotter interface{}) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Only accept POST requests
		if r.Method != http.MethodPost {
			writeJSON(w, http.StatusMethodNotAllowed, map[string]string{
				"error": "Method not allowed",
			})
			return
		}

		// Parse JSON request body
		var opts screenshot.Options
		if err := json.NewDecoder(r.Body).Decode(&opts); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{
				"error": "Invalid JSON",
			})
			return
		}

		// Validate that URL is provided
		if opts.URL == "" {
			writeJSON(w, http.StatusBadRequest, map[string]string{
				"error": "URL is required",
			})
			return
		}

		// Take screenshot using appropriate method
		var result *screenshot.Result
		var err error

		// Check if we have a queued screenshotter
		if qs, ok := screenshotter.(*screenshot.QueuedScreenshotter); ok {
			result, err = qs.CaptureQueued(r.Context(), &opts)
		} else if s, ok := screenshotter.(*screenshot.Screenshotter); ok {
			result, err = s.Capture(r.Context(), &opts)
		} else {
			writeJSON(w, http.StatusInternalServerError, map[string]string{
				"error": "Invalid screenshotter configuration",
			})
			return
		}
		if err != nil {
			// Return error response with appropriate status code
			status := http.StatusInternalServerError
			if err == screenshot.ErrInvalidURL {
				status = http.StatusBadRequest
			} else if err == screenshot.ErrBrowserUnavailable {
				status = http.StatusServiceUnavailable
			} else if err == screenshot.ErrTimeout || err == screenshot.ErrQueueTimeout {
				status = http.StatusGatewayTimeout
			} else if err == screenshot.ErrQueueFull {
				status = http.StatusTooManyRequests
			}

			writeJSON(w, status, result)
			return
		}

		// Return successful result
		writeJSON(w, http.StatusOK, result)
	}
}