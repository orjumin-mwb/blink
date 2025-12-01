package checker

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/olegrjumin/blink/internal/httpclient"
	"github.com/olegrjumin/blink/internal/mwbapi"
)

// Checker performs URL checks
type Checker struct {
	client    *httpclient.Client
	mwbClient *mwbapi.Client
}

// New creates a new Checker instance
func New(client *httpclient.Client, mwbClient *mwbapi.Client) *Checker {
	return &Checker{
		client:    client,
		mwbClient: mwbClient,
	}
}

// CheckURL performs a check on a single URL with the given options
// Returns a CheckResult with status, timing, and error information
func (c *Checker) CheckURL(ctx context.Context, rawURL string, opts CheckOptions) *CheckResult {
	startTime := time.Now()

	// Initialize result with the original URL
	result := &CheckResult{
		URL:           rawURL,
		OK:            false,
		Status:        0,
		ErrorType:     ErrorNone,
		RedirectCount: 0,
	}

	// Step 1: Validate and parse the URL
	parsedURL, err := url.Parse(rawURL)
	if err != nil || parsedURL.Scheme == "" || parsedURL.Host == "" {
		result.ErrorType = ErrorInvalidURL
		result.ErrorMessage = "invalid URL format"
		result.TotalMs = time.Since(startTime).Milliseconds()
		return result
	}

	// Ensure scheme is http or https
	if parsedURL.Scheme != "http" && parsedURL.Scheme != "https" {
		result.ErrorType = ErrorInvalidURL
		result.ErrorMessage = "URL must use http or https"
		result.TotalMs = time.Since(startTime).Milliseconds()
		return result
	}

	// Set protocol
	result.Protocol = parsedURL.Scheme

	// Step 2: Perform HTTP request with redirect handling
	currentURL := rawURL
	redirectCount := 0
	var lastResp *httpclient.Response
	redirectChain := make([]RedirectHop, 0, opts.MaxRedirects)

	for {
		// Perform the request
		resp, err := c.client.Do(ctx, opts.Method, currentURL, opts.UserAgent)
		if err != nil {
			// If HEAD failed with 405 Method Not Allowed, try GET
			if opts.Method == "HEAD" && strings.Contains(err.Error(), "405") {
				resp, err = c.client.Do(ctx, "GET", currentURL, opts.UserAgent)
			}

			// If still error, classify and return
			if err != nil {
				result.ErrorType, result.ErrorMessage = ClassifyError(err)
				result.TotalMs = time.Since(startTime).Milliseconds()
				return result
			}
		}

		lastResp = resp

		// Check if it's a redirect (3xx)
		if opts.FollowRedirects && resp.StatusCode >= 300 && resp.StatusCode < 400 {
			// Get Location header
			location := resp.Header.Get("Location")
			if location == "" {
				// No location header, stop here
				break
			}

			// Capture redirect hop
			redirectChain = append(redirectChain, RedirectHop{
				URL:      currentURL,
				Status:   resp.StatusCode,
				Location: location,
			})

			// Check redirect limit
			redirectCount++
			if redirectCount > opts.MaxRedirects {
				result.Status = resp.StatusCode
				result.ErrorType = ErrorHTTP
				result.ErrorMessage = fmt.Sprintf("too many redirects (max: %d)", opts.MaxRedirects)
				result.TotalMs = time.Since(startTime).Milliseconds()
				return result
			}

			// Parse the location (might be relative)
			locationURL, err := url.Parse(location)
			if err != nil {
				result.ErrorType = ErrorInvalidURL
				result.ErrorMessage = "invalid redirect location"
				result.TotalMs = time.Since(startTime).Milliseconds()
				return result
			}

			// If relative, resolve against current URL
			currentParsed, _ := url.Parse(currentURL)
			currentURL = currentParsed.ResolveReference(locationURL).String()

			// Continue to follow redirect
			continue
		}

		// Not a redirect or not following redirects, stop here
		break
	}

	// Step 3: Process the final response
	result.Status = lastResp.StatusCode
	result.FinalURL = currentURL
	result.RedirectCount = redirectCount
	if len(redirectChain) > 0 {
		result.RedirectChain = redirectChain
	}
	result.TotalMs = time.Since(startTime).Milliseconds()

	// Extract HTTP version (e.g., "HTTP/2.0" -> "2")
	if strings.HasPrefix(lastResp.Proto, "HTTP/") {
		result.HTTPVersion = strings.TrimPrefix(lastResp.Proto, "HTTP/")
	}

	// Extract detailed timings
	timings := ExtractTimings(lastResp.Timings)
	result.DNSMs = timings.DNSMs
	result.ConnectMs = timings.ConnectMs
	result.TLSMs = timings.TLSMs
	result.TTFBMs = timings.TTFBMs

	// Classify speed
	result.SpeedClass = ClassifySpeed(result.TotalMs)

	// Extract TLS/certificate information (Phase 5)
	if tlsInfo := ExtractTLSInfo(lastResp.TLS); tlsInfo != nil {
		result.TLSVersion = tlsInfo.TLSVersion
		result.CertValid = tlsInfo.CertValid
		result.CertExpiresAt = tlsInfo.CertExpiresAt
		result.CertDaysRemaining = tlsInfo.CertDaysRemaining
		result.CertExpiringSoon = tlsInfo.CertExpiringSoon
		result.CertIssuer = tlsInfo.CertIssuer
	}

	// Extract response metadata (Phase 5)
	if contentType := lastResp.Header.Get("Content-Type"); contentType != "" {
		result.ContentType = contentType
	}
	if contentLength := lastResp.Header.Get("Content-Length"); contentLength != "" {
		// Parse Content-Length as int64
		if size, err := strconv.ParseInt(contentLength, 10, 64); err == nil {
			result.SizeBytes = size
		}
	}

	// Call MWB API to check if URL is malicious
	// Use the original URL for the MWB check, not the final URL after redirects
	isMalicious, err := c.mwbClient.CheckURL(ctx, rawURL)
	if err != nil {
		// If MWB API fails, log but don't fail the whole check
		// Set to false as fallback
		result.MWBURLChecker = false
	} else {
		result.MWBURLChecker = isMalicious
	}

	// Determine if the link is "OK"
	// 2xx and 3xx status codes are considered successful
	if result.Status >= 200 && result.Status < 400 {
		result.OK = true
	} else {
		// For 4xx and 5xx errors, classify as http_error
		result.ErrorType = ErrorHTTP
		result.ErrorMessage = fmt.Sprintf("HTTP %d", result.Status)
	}

	return result
}

// DeepCheckURL performs a deep check on a URL, including HTML analysis
func (c *Checker) DeepCheckURL(ctx context.Context, rawURL string, opts CheckOptions) *DeepCheckResult {
	// Start with a basic check
	basicResult := c.CheckURL(ctx, rawURL, opts)

	// Create deep result with embedded basic result
	result := &DeepCheckResult{
		CheckResult: *basicResult,
	}

	// If basic check failed or non-200, return early
	if !basicResult.OK || basicResult.Status != 200 {
		return result
	}

	// Use FinalURL to avoid re-redirecting
	urlToFetch := basicResult.FinalURL
	if urlToFetch == "" {
		urlToFetch = rawURL
	}

	// Fetch HTML body with GET request
	startTime := time.Now()
	resp, body, err := c.client.DoWithBody(ctx, "GET", urlToFetch, opts.UserAgent)
	if err != nil {
		// If we can't fetch body, return basic result
		return result
	}
	defer body.Close()

	// Read body with 5MB size limit
	const maxBodySize = 5 * 1024 * 1024 // 5MB
	bodyReader := io.LimitReader(body, maxBodySize)
	bodyBytes, err := io.ReadAll(bodyReader)

	if err != nil {
		// If we can't read body, return basic result
		return result
	}

	// Parse HTML
	htmlParser, err := NewHTMLParser(urlToFetch)
	if err == nil {
		parseResult, err := htmlParser.Parse(bytes.NewReader(bodyBytes))
		if err == nil && parseResult != nil {
			result.OutgoingLinks = parseResult.Links
			result.HTMLMetadata = parseResult.Metadata
		}
	}

	// Detect technologies
	techDetector := NewTechDetector()
	result.Technologies = techDetector.Detect(resp.Header, string(bodyBytes))

	// Update total time to include deep analysis
	result.TotalMs = time.Since(startTime).Milliseconds()

	return result
}

// NormalizeURL ensures the URL has a scheme and is properly formatted
// Helper function for future use
func NormalizeURL(rawURL string) string {
	// If URL doesn't have a scheme, add https://
	if !strings.HasPrefix(rawURL, "http://") && !strings.HasPrefix(rawURL, "https://") {
		return "https://" + rawURL
	}
	return rawURL
}
