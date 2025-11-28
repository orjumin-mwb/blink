package checker

import (
	"context"
	"net"
	"strings"
)

// Error type constants
const (
	ErrorNone       = "none"
	ErrorInvalidURL = "invalid_url"
	ErrorTimeout    = "timeout"
	ErrorDNS        = "dns_error"
	ErrorTLS        = "tls_error"
	ErrorNetwork    = "network_error"
	ErrorHTTP       = "http_error"
)

// ClassifyError determines the error type from a Go error
// Returns the error type constant and a human-readable message
func ClassifyError(err error) (string, string) {
	if err == nil {
		return ErrorNone, ""
	}

	errMsg := err.Error()

	// Check for timeout errors
	if err == context.DeadlineExceeded {
		return ErrorTimeout, "request timeout"
	}

	// Check if it's a network error with Timeout() method
	if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
		return ErrorTimeout, "request timeout"
	}

	// Check for DNS errors
	if _, ok := err.(*net.DNSError); ok {
		return ErrorDNS, "DNS lookup failed"
	}

	// Check for TLS/certificate errors
	if strings.Contains(errMsg, "tls") || strings.Contains(errMsg, "TLS") {
		return ErrorTLS, "TLS handshake failed"
	}
	if strings.Contains(errMsg, "certificate") || strings.Contains(errMsg, "x509") {
		return ErrorTLS, "certificate error"
	}

	// Check for connection refused and similar network errors
	if strings.Contains(errMsg, "connection refused") {
		return ErrorNetwork, "connection refused"
	}
	if strings.Contains(errMsg, "connection reset") {
		return ErrorNetwork, "connection reset"
	}
	if strings.Contains(errMsg, "no such host") {
		return ErrorDNS, "host not found"
	}
	if strings.Contains(errMsg, "network is unreachable") {
		return ErrorNetwork, "network unreachable"
	}

	// Default to network error for other cases
	return ErrorNetwork, errMsg
}
