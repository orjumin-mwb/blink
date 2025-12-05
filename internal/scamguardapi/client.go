package scamguardapi

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// Client handles requests to ScamGuard V2 API
type Client struct {
	baseURL    string
	httpClient *http.Client
	userAgent  string
}

// CreateResponseRequest represents the V2 API request body
type CreateResponseRequest struct {
	Input        string         `json:"input"`
	Stream       bool           `json:"stream"`
	Capabilities []Capability   `json:"capabilities"`
	Metadata     *Metadata      `json:"metadata,omitempty"`
}

// Capability represents a capability type
type Capability struct {
	Type string `json:"type"`
}

// Metadata contains optional client metadata
type Metadata struct {
	ClientTimezone     string   `json:"client_timezone,omitempty"`
	PreferredLanguages []string `json:"preferred_languages,omitempty"`
}

// StreamEvent represents a parsed SSE event
type StreamEvent struct {
	Type string          `json:"type"`
	Data json.RawMessage `json:"data"`
}

// ScanResult contains the final scan result
type ScanResult struct {
	Verdict        string           `json:"verdict"`
	Analysis       string           `json:"analysis"`
	DestinationURL string           `json:"destination_url"`
	Reachable      bool             `json:"reachable"`
	ResponseID     string           `json:"response_id"`
	ThreadID       string           `json:"thread_id"`
	Enhanced       *EnhancedVerdict `json:"enhanced,omitempty"` // Enhanced verdict from text analysis
}

// New creates a new ScamGuard API client
func New(baseURL, userAgent string) *Client {
	return &Client{
		baseURL:   baseURL,
		userAgent: userAgent,
		httpClient: &http.Client{
			Timeout: 30 * time.Second, // Total request timeout
		},
	}
}

// Enhanced prompt for better structured responses
const enhancedPrompt = `Analyze this URL for security threats. In your response, please include:
1. Whether the site appears legitimate, suspicious, or malicious
2. Key indicators that led to your assessment
3. Any reputation or historical information about the domain
4. Potential risks or concerns
5. If the site is an established service, mention that clearly

URL to analyze: `

// ScanURLStreaming performs a streaming URL scan and forwards SSE events
func (c *Client) ScanURLStreaming(ctx context.Context, url string, events chan<- StreamEvent) (*ScanResult, error) {
	// Build request body with enhanced prompt
	reqBody := CreateResponseRequest{
		Input:  enhancedPrompt + url,
		Stream: true,
		Capabilities: []Capability{
			{Type: "scan_url"},
		},
	}

	// Marshal request
	jsonData, err := json.Marshal(reqBody)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %w", err)
	}

	// Create HTTP request
	req, err := http.NewRequestWithContext(ctx, "POST", c.baseURL+"/v2/chat/responses", strings.NewReader(string(jsonData)))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	// Set required headers
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", c.userAgent)

	// Make request
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to call ScamGuard API: %w", err)
	}
	defer resp.Body.Close()

	// Check status code
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("ScamGuard API returned status %d: %s", resp.StatusCode, string(body))
	}

	// Parse SSE stream
	result, err := c.parseSSEStream(resp.Body, events)
	if err != nil {
		return nil, fmt.Errorf("failed to parse SSE stream: %w", err)
	}

	return result, nil
}

// parseSSEStream parses the SSE event stream and extracts the final result
func (c *Client) parseSSEStream(body io.Reader, events chan<- StreamEvent) (*ScanResult, error) {
	scanner := bufio.NewScanner(body)
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024) // Increase buffer size for large messages

	var currentEvent string
	var dataLines []string
	var analysisBuilder strings.Builder
	var verdict string
	var responseID string
	var threadID string
	var destinationURL string
	var reachable bool

	for scanner.Scan() {
		line := scanner.Text()

		if strings.HasPrefix(line, "event:") {
			// New event type
			currentEvent = strings.TrimSpace(strings.TrimPrefix(line, "event:"))
		} else if strings.HasPrefix(line, "data:") {
			// Event data (can be multiline)
			data := strings.TrimSpace(strings.TrimPrefix(line, "data:"))
			dataLines = append(dataLines, data)
		} else if line == "" {
			// Empty line marks end of event
			if currentEvent != "" && len(dataLines) > 0 {
				// Join multiline data
				fullData := strings.Join(dataLines, "\n")

				// Parse and extract relevant data
				switch currentEvent {
				case "response.created":
					// Extract response ID and thread ID
					var createdData struct {
						Response struct {
							ID       string `json:"id"`
							ThreadID string `json:"thread_id"`
						} `json:"response"`
					}
					if err := json.Unmarshal([]byte(fullData), &createdData); err == nil {
						responseID = createdData.Response.ID
						threadID = createdData.Response.ThreadID
					}

				case "response.output_item.done", "response.scan_url_tool.completed":
					// Extract verdict and scan result
					var scanData struct {
						Item struct {
							Result struct {
								Verdict        string `json:"verdict"`
								DestinationURL string `json:"destination_url"`
								Reachable      bool   `json:"reachable"`
							} `json:"result"`
						} `json:"item"`
					}
					if err := json.Unmarshal([]byte(fullData), &scanData); err == nil {
						verdict = scanData.Item.Result.Verdict
						destinationURL = scanData.Item.Result.DestinationURL
						reachable = scanData.Item.Result.Reachable
					}

				case "response.text.delta":
					// Accumulate text chunks
					var deltaData struct {
						Delta string `json:"delta"`
					}
					if err := json.Unmarshal([]byte(fullData), &deltaData); err == nil {
						analysisBuilder.WriteString(deltaData.Delta)
					}
				}

				// Forward event to caller
				if events != nil {
					events <- StreamEvent{
						Type: currentEvent,
						Data: json.RawMessage(fullData),
					}
				}
			}

			// Reset for next event
			currentEvent = ""
			dataLines = nil
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("error reading SSE stream: %w", err)
	}

	// Build final result
	result := &ScanResult{
		Verdict:        verdict,
		Analysis:       analysisBuilder.String(),
		DestinationURL: destinationURL,
		Reachable:      reachable,
		ResponseID:     responseID,
		ThreadID:       threadID,
	}

	// Parse the text to get enhanced verdict
	result.Enhanced = ParseVerdictFromText(result.Analysis, verdict)

	// If the original verdict was unknown and we found a better one, update it
	if verdict == "unknown" && result.Enhanced != nil && result.Enhanced.Verdict != "unknown" {
		result.Verdict = result.Enhanced.Verdict
	}

	return result, nil
}
