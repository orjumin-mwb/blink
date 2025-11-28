package httpclient

import (
	"context"
	"crypto/tls"
	"net/http"
	"net/http/httptrace"
	"time"
)

// Client wraps http.Client and provides methods for making traced requests
type Client struct {
	httpClient *http.Client
}

// TimingInfo holds performance timing information for a request
type TimingInfo struct {
	DNSStart      time.Time
	DNSDone       time.Time
	ConnectStart  time.Time
	ConnectDone   time.Time
	TLSStart      time.Time
	TLSDone       time.Time
	GotFirstByte  time.Time
	RequestStart  time.Time
	RequestDone   time.Time
}

// Response holds the HTTP response along with timing information
type Response struct {
	StatusCode int
	Proto      string // e.g., "HTTP/2.0"
	Header     http.Header
	TLS        *tls.ConnectionState
	Timings    *TimingInfo
}

// NewClient creates a new HTTP client with the configured transport
func NewClient() *Client {
	return &Client{
		httpClient: &http.Client{
			Transport: NewTransport(),
			// Don't follow redirects automatically - we'll handle this in the checker
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
	}
}

// Do performs an HTTP request with tracing enabled
// Returns the response, timing info, and any error
func (c *Client) Do(ctx context.Context, method, url, userAgent string) (*Response, error) {
	// Create timing info to capture performance metrics
	timings := &TimingInfo{
		RequestStart: time.Now(),
	}

	// Create HTTP trace to capture timing events
	trace := &httptrace.ClientTrace{
		DNSStart: func(_ httptrace.DNSStartInfo) {
			timings.DNSStart = time.Now()
		},
		DNSDone: func(_ httptrace.DNSDoneInfo) {
			timings.DNSDone = time.Now()
		},
		ConnectStart: func(_, _ string) {
			timings.ConnectStart = time.Now()
		},
		ConnectDone: func(_, _ string, _ error) {
			timings.ConnectDone = time.Now()
		},
		TLSHandshakeStart: func() {
			timings.TLSStart = time.Now()
		},
		TLSHandshakeDone: func(_ tls.ConnectionState, _ error) {
			timings.TLSDone = time.Now()
		},
		GotFirstResponseByte: func() {
			timings.GotFirstByte = time.Now()
		},
	}

	// Create request with trace
	req, err := http.NewRequestWithContext(
		httptrace.WithClientTrace(ctx, trace),
		method,
		url,
		nil,
	)
	if err != nil {
		return nil, err
	}

	// Set User-Agent header
	if userAgent != "" {
		req.Header.Set("User-Agent", userAgent)
	} else {
		req.Header.Set("User-Agent", "blink-checker/1.0")
	}

	// Perform the request
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	// Record when request completed
	timings.RequestDone = time.Now()

	// Build response object
	response := &Response{
		StatusCode: resp.StatusCode,
		Proto:      resp.Proto,
		Header:     resp.Header,
		TLS:        resp.TLS,
		Timings:    timings,
	}

	return response, nil
}
