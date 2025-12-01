package httpapi

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"html/template"
	"net/http"

	"github.com/olegrjumin/blink/internal/service"
)

//go:embed templates/ui_form.html
var uiFormTemplate string

//go:embed templates/ui_result.html
var uiResultTemplate string

// Template helper functions
var templateFuncs = template.FuncMap{
	"add": func(a, b int) int {
		return a + b
	},
}

// uiFormHandler serves the main UI form page
func uiFormHandler() http.HandlerFunc {
	// Parse template once at initialization
	tmpl := template.Must(template.New("form").Parse(uiFormTemplate))

	return func(w http.ResponseWriter, r *http.Request) {
		// Only accept GET requests
		if r.Method != http.MethodGet {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		// Render the form template
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		if err := tmpl.Execute(w, nil); err != nil {
			http.Error(w, "Internal server error", http.StatusInternalServerError)
		}
	}
}

// uiStreamHandler handles SSE streaming for URL checks
func uiStreamHandler(streamingSvc *service.StreamingService) http.HandlerFunc {
	// Parse result template once at initialization with helper functions
	resultTmpl := template.Must(template.New("result").Funcs(templateFuncs).Parse(uiResultTemplate))

	return func(w http.ResponseWriter, r *http.Request) {
		// Accept GET requests (EventSource only supports GET)
		if r.Method != http.MethodGet {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		// Get URL from query parameters
		url := r.URL.Query().Get("url")
		if url == "" {
			http.Error(w, "URL required", http.StatusBadRequest)
			return
		}

		// Set SSE headers
		w.Header().Set("Content-Type", "text/event-stream")
		w.Header().Set("Cache-Control", "no-cache")
		w.Header().Set("Connection", "keep-alive")
		w.Header().Set("X-Accel-Buffering", "no") // Disable nginx buffering

		// Get flusher for immediate writes
		flusher, ok := w.(http.Flusher)
		if !ok {
			http.Error(w, "Streaming not supported", http.StatusInternalServerError)
			return
		}

		// Start streaming check
		eventChan := streamingSvc.CheckURLStreaming(r.Context(), url, nil)

		// Stream events
		for event := range eventChan {
			// Handle complete, error, and malicious events specially - render HTML
			if event.Stage == "complete" || event.Stage == "error" || event.Stage == "malicious" {
				// Render the result template
				var htmlBuf []byte
				if resultHTML, err := renderResultTemplate(resultTmpl, event.Data); err == nil {
					htmlBuf = []byte(resultHTML)
				} else {
					// Fallback to JSON if template fails
					htmlBuf, _ = json.Marshal(event)
				}

				// Send as SSE event with HTML data
				// For multi-line data, we need to escape newlines or send as JSON string
				htmlStr := string(htmlBuf)
				htmlJSON, _ := json.Marshal(htmlStr) // This will escape newlines and quotes
				fmt.Fprintf(w, "event: %s\n", event.Stage)
				fmt.Fprintf(w, "data: %s\n\n", string(htmlJSON))
				flusher.Flush()
				continue
			}

			// For other events, send JSON data
			data, err := json.Marshal(event)
			if err != nil {
				continue
			}

			fmt.Fprintf(w, "event: %s\n", event.Stage)
			fmt.Fprintf(w, "data: %s\n\n", string(data))
			flusher.Flush()

			// Check if client disconnected
			select {
			case <-r.Context().Done():
				return
			default:
			}
		}
	}
}

// renderResultTemplate renders the result template with the given data
func renderResultTemplate(tmpl *template.Template, data interface{}) (string, error) {
	var buf []byte
	writer := &byteWriter{buf: buf}

	if err := tmpl.Execute(writer, data); err != nil {
		return "", err
	}

	return string(writer.buf), nil
}

// byteWriter implements io.Writer for writing to a byte slice
type byteWriter struct {
	buf []byte
}

func (bw *byteWriter) Write(p []byte) (n int, err error) {
	bw.buf = append(bw.buf, p...)
	return len(p), nil
}
