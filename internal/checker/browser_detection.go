package checker

// DetectedAPI represents a browser API that was detected in JavaScript code
type DetectedAPI struct {
	Name        string   `json:"name"`        // e.g., "navigator.geolocation"
	Category    string   `json:"category"`    // e.g., "Location Services"
	Usage       []string `json:"usage"`       // Code snippets showing usage
	RiskLevel   string   `json:"risk_level"`  // "low", "medium", "high"
	Description string   `json:"description"` // What this API does
	FoundIn     string   `json:"found_in"`    // "inline" or URL of external script
}

// DeviceCapability represents detected device access capabilities
type DeviceCapability struct {
	Type        string `json:"type"`         // e.g., "camera", "microphone", "accelerometer"
	APIUsed     string `json:"api_used"`     // e.g., "getUserMedia", "DeviceOrientationEvent"
	Detected    bool   `json:"detected"`
	CodeContext string `json:"code_context"` // Surrounding code context
	FoundIn     string `json:"found_in"`     // Where it was found
}

// PrivacyRisk represents a privacy concern identified in the code
type PrivacyRisk struct {
	Type        string   `json:"type"`        // e.g., "location_tracking", "fingerprinting"
	Severity    string   `json:"severity"`    // "low", "medium", "high", "critical"
	Description string   `json:"description"`
	APIs        []string `json:"apis"`        // Related APIs
	Mitigation  string   `json:"mitigation"`  // How users can protect themselves
}

// FingerprintAnalysis represents browser fingerprinting detection results
type FingerprintAnalysis struct {
	Score       int      `json:"score"`        // 0-100 fingerprinting likelihood
	Techniques  []string `json:"techniques"`   // Detected techniques
	Entropy     float64  `json:"entropy"`      // Information entropy
	UniqueAPIs  int      `json:"unique_apis"`  // Number of unique APIs accessed
}

// JSLibrary represents a detected JavaScript library
type JSLibrary struct {
	Name    string `json:"name"`
	Version string `json:"version,omitempty"`
	CDN     string `json:"cdn,omitempty"`
	Purpose string `json:"purpose,omitempty"`
}

// DetectedTracker represents a third-party tracking script
type DetectedTracker struct {
	Name        string `json:"name"`         // e.g., "Google Analytics"
	Category    string `json:"category"`     // e.g., "Analytics", "Advertising", "Social"
	Domain      string `json:"domain"`       // e.g., "www.googletagmanager.com"
	Purpose     string `json:"purpose"`      // What data it collects
	PrivacyRisk string `json:"privacy_risk"` // "low", "medium", "high"
	DetectedAt  string `json:"detected_at,omitempty"` // "static" or "runtime"
}

// StreamEvent represents a progressive event during deep check analysis
type DeepCheckStreamEvent struct {
	Type string      `json:"type"` // "analysis_started", "api_detected", "tracker_found", etc.
	Data interface{} `json:"data"`
}