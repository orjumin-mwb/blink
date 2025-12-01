package checker

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/olegrjumin/blink/internal/httpclient"
	"github.com/olegrjumin/blink/internal/scamguardapi"
)

// StreamEvent represents a progressive event during URL checking
type StreamEvent struct {
	Stage   string      `json:"stage"`
	Message string      `json:"message"`
	Data    interface{} `json:"data"`
}

// CheckURLStreaming performs a check and emits real-time events to the provided channel
// This method handles its own event sending and closes when done
func (c *Checker) CheckURLStreaming(ctx context.Context, rawURL string, opts CheckOptions, events chan<- StreamEvent) {
	startTime := time.Now()

	// Initialize result
	result := &CheckResult{
		URL:           rawURL,
		OK:            false,
		Status:        0,
		ErrorType:     ErrorNone,
		RedirectCount: 0,
	}

	// Validate URL
	parsedURL, err := url.Parse(rawURL)
	if err != nil || parsedURL.Scheme == "" || parsedURL.Host == "" {
		result.ErrorType = ErrorInvalidURL
		result.ErrorMessage = "invalid URL format"
		result.TotalMs = time.Since(startTime).Milliseconds()
		sendEvent(ctx, events, "error", result.ErrorMessage, result)
		return
	}

	if parsedURL.Scheme != "http" && parsedURL.Scheme != "https" {
		result.ErrorType = ErrorInvalidURL
		result.ErrorMessage = "URL must use http or https"
		result.TotalMs = time.Since(startTime).Milliseconds()
		sendEvent(ctx, events, "error", result.ErrorMessage, result)
		return
	}

	result.Protocol = parsedURL.Scheme

	// Check MWB reputation FIRST - fail fast if malicious
	isMalicious, err := c.mwbClient.CheckURL(ctx, rawURL)
	if err != nil {
		// If MWB check fails, log but continue with regular check
		result.MWBURLChecker = false
	} else {
		result.MWBURLChecker = isMalicious
		if isMalicious {
			// URL is malicious - stop immediately
			result.ErrorType = ErrorHTTP
			result.ErrorMessage = "URL flagged as malicious by Malwarebytes URL Checker"
			result.TotalMs = time.Since(startTime).Milliseconds()
			sendEvent(ctx, events, "malicious", result.ErrorMessage, result)
			return
		}
	}

	// Launch ScamGuard check in parallel (only if MWB didn't block it)
	var scamGuardResult *ScamGuardResult
	scamGuardDone := make(chan struct{})

	if c.scamGuardClient != nil {
		go func() {
			defer close(scamGuardDone)

			// Create sub-channel for ScamGuard events
			sgEvents := make(chan scamguardapi.StreamEvent, 10)

			// Forward ScamGuard events to main event stream
			go func() {
				for sgEvt := range sgEvents {
					// Transform ScamGuard events to our event format
					switch sgEvt.Type {
					case "response.created":
						sendEvent(ctx, events, "scamguard.started", "ScamGuard analysis started", map[string]string{"url": rawURL})

					case "response.scan_url_tool.in_progress":
						sendEvent(ctx, events, "scamguard.scanning", "Scanning URL with ScamGuard", nil)

					case "response.output_item.done", "response.scan_url_tool.completed":
						// Extract verdict
						var scanData struct {
							Item struct {
								Result struct {
									Verdict string `json:"verdict"`
								} `json:"result"`
							} `json:"item"`
						}
						if err := json.Unmarshal(sgEvt.Data, &scanData); err == nil {
							sendEvent(ctx, events, "scamguard.verdict", "Scan verdict received", map[string]string{
								"verdict": scanData.Item.Result.Verdict,
							})
						}

					case "response.text.delta":
						// Stream analysis text chunks
						var deltaData struct {
							Delta string `json:"delta"`
						}
						if err := json.Unmarshal(sgEvt.Data, &deltaData); err == nil {
							sendEvent(ctx, events, "scamguard.text", "Analysis text", map[string]string{
								"text": deltaData.Delta,
							})
						}

					case "response.completed":
						sendEvent(ctx, events, "scamguard.completed", "ScamGuard analysis complete", nil)
					}
				}
			}()

			// Call ScamGuard API
			sgResult, err := c.scamGuardClient.ScanURLStreaming(ctx, rawURL, sgEvents)
			if err != nil {
				scamGuardResult = &ScamGuardResult{
					Error: err.Error(),
				}
				sendEvent(ctx, events, "scamguard.error", "ScamGuard scan failed", map[string]string{"error": err.Error()})
			} else if sgResult != nil {
				scamGuardResult = &ScamGuardResult{
					Verdict:        sgResult.Verdict,
					Analysis:       sgResult.Analysis,
					DestinationURL: sgResult.DestinationURL,
					Reachable:      sgResult.Reachable,
					ResponseID:     sgResult.ResponseID,
					ThreadID:       sgResult.ThreadID,
				}
			}
		}()
	}

	// Follow redirects manually and emit events between hops
	currentURL := rawURL
	redirectCount := 0
	var lastResp *httpclient.Response
	redirectChain := make([]RedirectHop, 0, opts.MaxRedirects)

	for {
		// Perform request
		resp, err := c.client.Do(ctx, opts.Method, currentURL, opts.UserAgent)
		if err != nil {
			// Try GET if HEAD failed with 405
			if opts.Method == "HEAD" && strings.Contains(err.Error(), "405") {
				resp, err = c.client.Do(ctx, "GET", currentURL, opts.UserAgent)
			}

			if err != nil {
				result.ErrorType, result.ErrorMessage = ClassifyError(err)
				result.TotalMs = time.Since(startTime).Milliseconds()
				sendEvent(ctx, events, "error", result.ErrorMessage, result)
				return
			}
		}

		lastResp = resp

		// Emit timing events immediately after request completes
		if resp.Timings != nil {
			timings := ExtractTimings(resp.Timings)

			if timings.DNSMs > 0 {
				sendEvent(ctx, events, "dns", "DNS resolved", map[string]interface{}{
					"dns_ms": timings.DNSMs,
				})
			}

			if timings.ConnectMs > 0 {
				sendEvent(ctx, events, "tcp", "Connected", map[string]interface{}{
					"connect_ms": timings.ConnectMs,
				})
			}

			if timings.TLSMs > 0 {
				sendEvent(ctx, events, "tls", "TLS handshake complete", map[string]interface{}{
					"tls_ms": timings.TLSMs,
				})
			}

			if timings.TTFBMs > 0 {
				sendEvent(ctx, events, "response", "Got response", map[string]interface{}{
					"ttfb_ms": timings.TTFBMs,
					"status":  resp.StatusCode,
				})
			}
		}

		// Check if it's a redirect
		if opts.FollowRedirects && resp.StatusCode >= 300 && resp.StatusCode < 400 {
			location := resp.Header.Get("Location")
			if location == "" {
				break
			}

			// Emit redirect event
			redirectChain = append(redirectChain, RedirectHop{
				URL:      currentURL,
				Status:   resp.StatusCode,
				Location: location,
			})

			sendEvent(ctx, events, "redirect", "Following redirect...", map[string]interface{}{
				"hop":      redirectCount + 1,
				"status":   resp.StatusCode,
				"location": location,
			})

			redirectCount++
			if redirectCount > opts.MaxRedirects {
				result.Status = resp.StatusCode
				result.ErrorType = ErrorHTTP
				result.ErrorMessage = fmt.Sprintf("too many redirects (max: %d)", opts.MaxRedirects)
				result.TotalMs = time.Since(startTime).Milliseconds()
				sendEvent(ctx, events, "error", result.ErrorMessage, result)
				return
			}

			// Parse location
			locationURL, err := url.Parse(location)
			if err != nil {
				result.ErrorType = ErrorInvalidURL
				result.ErrorMessage = "invalid redirect location"
				result.TotalMs = time.Since(startTime).Milliseconds()
				sendEvent(ctx, events, "error", result.ErrorMessage, result)
				return
			}

			currentParsed, _ := url.Parse(currentURL)
			currentURL = currentParsed.ResolveReference(locationURL).String()
			continue
		}

		break
	}

	// Build final result
	result.Status = lastResp.StatusCode
	result.FinalURL = currentURL
	result.RedirectCount = redirectCount
	if len(redirectChain) > 0 {
		result.RedirectChain = redirectChain
	}
	result.TotalMs = time.Since(startTime).Milliseconds()

	if strings.HasPrefix(lastResp.Proto, "HTTP/") {
		result.HTTPVersion = strings.TrimPrefix(lastResp.Proto, "HTTP/")
	}

	timings := ExtractTimings(lastResp.Timings)
	result.DNSMs = timings.DNSMs
	result.ConnectMs = timings.ConnectMs
	result.TLSMs = timings.TLSMs
	result.TTFBMs = timings.TTFBMs
	result.SpeedClass = ClassifySpeed(result.TotalMs)

	if tlsInfo := ExtractTLSInfo(lastResp.TLS); tlsInfo != nil {
		result.TLSVersion = tlsInfo.TLSVersion
		result.CertValid = tlsInfo.CertValid
		result.CertExpiresAt = tlsInfo.CertExpiresAt
		result.CertDaysRemaining = tlsInfo.CertDaysRemaining
		result.CertExpiringSoon = tlsInfo.CertExpiringSoon
		result.CertIssuer = tlsInfo.CertIssuer
	}

	if contentType := lastResp.Header.Get("Content-Type"); contentType != "" {
		result.ContentType = contentType
	}
	if contentLength := lastResp.Header.Get("Content-Length"); contentLength != "" {
		if size, err := strconv.ParseInt(contentLength, 10, 64); err == nil {
			result.SizeBytes = size
		}
	}

	// Wait for ScamGuard with timeout (if running)
	if c.scamGuardClient != nil {
		select {
		case <-scamGuardDone:
			// ScamGuard completed normally
		case <-ctx.Done():
			// Request cancelled
			if scamGuardResult == nil {
				scamGuardResult = &ScamGuardResult{
					Error: "Request cancelled",
				}
			}
		case <-time.After(10 * time.Second):
			// ScamGuard timeout - continue without it
			if scamGuardResult == nil {
				scamGuardResult = &ScamGuardResult{
					Error: "Scan timeout",
				}
			}
		}

		// Attach ScamGuard result to main result
		result.ScamGuard = scamGuardResult
	}

	// Determine if OK
	if result.Status >= 200 && result.Status < 400 {
		result.OK = true
		sendEvent(ctx, events, "complete", "Check complete", result)
	} else {
		result.ErrorType = ErrorHTTP
		result.ErrorMessage = fmt.Sprintf("HTTP %d", result.Status)
		sendEvent(ctx, events, "error", result.ErrorMessage, result)
	}
}

// sendEvent is a helper to safely send events with context cancellation support
func sendEvent(ctx context.Context, events chan<- StreamEvent, stage, message string, data interface{}) {
	select {
	case events <- StreamEvent{
		Stage:   stage,
		Message: message,
		Data:    data,
	}:
	case <-ctx.Done():
	}
}
