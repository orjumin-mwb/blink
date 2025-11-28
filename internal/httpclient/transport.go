package httpclient

import (
	"net/http"
	"time"
)

// NewTransport creates a configured HTTP transport optimized for performance
// The transport is reused across requests for connection pooling
func NewTransport() *http.Transport {
	return &http.Transport{
		// Maximum number of idle connections across all hosts
		MaxIdleConns: 100,

		// Maximum number of idle connections per host
		MaxIdleConnsPerHost: 10,

		// How long an idle connection stays in the pool
		IdleConnTimeout: 90 * time.Second,

		// Timeout for TLS handshake
		TLSHandshakeTimeout: 10 * time.Second,

		// Timeout for expecting response headers after request is sent
		ResponseHeaderTimeout: 10 * time.Second,

		// Enable HTTP/2 support
		ForceAttemptHTTP2: true,
	}
}
