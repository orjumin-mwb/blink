package checker

// RedirectHop represents a single redirect in the chain
type RedirectHop struct {
	URL      string `json:"url"`      // The URL that redirected
	Status   int    `json:"status"`   // HTTP status (301, 302, 307, 308)
	Location string `json:"location"` // Value of Location header
}

// ScamGuardResult holds the result of a ScamGuard scan
type ScamGuardResult struct {
	Verdict        string  `json:"verdict"`                   // "malicious" | "suspicious" | "safe" | "unknown"
	Analysis       string  `json:"analysis,omitempty"`        // Natural language explanation from AI
	DestinationURL string  `json:"destination_url,omitempty"` // Final URL after redirects (from ScamGuard)
	Reachable      bool    `json:"reachable"`                 // Whether URL was reachable
	ResponseID     string  `json:"response_id,omitempty"`     // ScamGuard response ID for tracing
	ThreadID       string  `json:"thread_id,omitempty"`       // ScamGuard thread ID for tracing
	Error          string  `json:"error,omitempty"`           // If scan failed

	// Enhanced verdict fields (from text analysis)
	EnhancedVerdict string  `json:"enhanced_verdict,omitempty"` // Enhanced verdict from text parsing
	Confidence      float64 `json:"confidence,omitempty"`       // Confidence in the verdict (0.0-1.0)
	Score           int     `json:"score,omitempty"`            // Score out of 30 for ScamGuard portion
	Reason          string  `json:"reason,omitempty"`           // Brief explanation of verdict
}

// CheckResult holds the result of a URL check
// Complete version for Phase 5 with TLS/certificate info
type CheckResult struct {
	// Core fields
	URL          string `json:"url"`           // Original URL that was checked
	OK           bool   `json:"ok"`            // True if the link is working (2xx/3xx status)
	Status       int    `json:"status"`        // HTTP status code (0 if no response)
	ErrorType    string `json:"error_type"`    // Error type constant (none, timeout, dns_error, etc.)
	ErrorMessage string `json:"error_message,omitempty"` // Human-readable error message

	// Redirect info
	FinalURL      string         `json:"final_url,omitempty"`      // URL after redirects
	RedirectCount int            `json:"redirect_count"`           // Number of redirects
	RedirectChain []RedirectHop `json:"redirect_chain,omitempty"` // Detailed redirect chain

	// Performance - Basic
	TotalMs int64 `json:"total_ms"` // Total time in milliseconds

	// Performance - Detailed timings (Phase 4)
	DNSMs     int64  `json:"dns_ms,omitempty"`     // DNS lookup time
	ConnectMs int64  `json:"connect_ms,omitempty"` // TCP connect time
	TLSMs     int64  `json:"tls_ms,omitempty"`     // TLS handshake time
	TTFBMs    int64  `json:"ttfb_ms,omitempty"`    // Time to first byte
	SpeedClass string `json:"speed_class,omitempty"` // "fast", "ok", or "slow"

	// Protocol (Phase 4 - enhanced)
	Protocol    string `json:"protocol,omitempty"`     // "http" or "https"
	HTTPVersion string `json:"http_version,omitempty"` // e.g., "1.1" or "2"

	// TLS / Certificate (Phase 5)
	TLSVersion        string `json:"tls_version,omitempty"`         // e.g., "TLS1.2", "TLS1.3"
	CertValid         bool   `json:"cert_valid,omitempty"`          // Certificate is currently valid
	CertExpiresAt     string `json:"cert_expires_at,omitempty"`     // ISO8601 timestamp
	CertDaysRemaining int    `json:"cert_days_remaining,omitempty"` // Days until expiry
	CertExpiringSoon  bool   `json:"cert_expiring_soon,omitempty"`  // true if < 30 days
	CertIssuer        string `json:"cert_issuer,omitempty"`         // Certificate issuer

	// Response metadata (Phase 5)
	ContentType string `json:"content_type,omitempty"` // Content-Type header
	SizeBytes   int64  `json:"size_bytes,omitempty"`   // Content-Length header

	// MWB specific field
	MWBURLChecker bool `json:"mwb_url_checker"` // MWB URL checker flag

	// ScamGuard field
	ScamGuard *ScamGuardResult `json:"scamguard,omitempty"` // ScamGuard analysis result (nil if not enabled or failed)
}
