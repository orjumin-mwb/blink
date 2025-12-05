package checker

// DeepCheckResult - Unified deep-check analysis result
type DeepCheckResult struct {
	// Basic info
	URL              string `json:"url"`
	Timestamp        string `json:"timestamp"`
	AnalysisDuration string `json:"analysis_duration"`

	// Main analysis sections
	Tracking     *TrackingAnalysis    `json:"tracking"`
	APIUsage     *APIAnalysis         `json:"api_usage"`
	Technologies *TechnologyAnalysis  `json:"technologies"`
	Security     *SecurityAnalysis    `json:"security"`
	Privacy      *PrivacyAnalysis     `json:"privacy"`
	Payment      *PaymentAnalysis     `json:"payment,omitempty"`
	PageInfo     *PageInfo            `json:"page_info"`
	Network      *NetworkData         `json:"network,omitempty"`
}

// TrackingAnalysis contains all tracking/analytics services
type TrackingAnalysis struct {
	Services []*UnifiedTracker      `json:"services"`
	Summary  map[string]interface{} `json:"summary"`
}

// APIAnalysis contains browser API usage information
type APIAnalysis struct {
	Detected       []*UnifiedAPI          `json:"detected"`
	Fingerprinting *FingerprintingAnalysis `json:"fingerprinting,omitempty"`
}

// FingerprintingAnalysis analyzes fingerprinting techniques
type FingerprintingAnalysis struct {
	Detected     bool     `json:"detected"`
	Techniques   []string `json:"techniques,omitempty"`
	EntropyScore float64  `json:"entropy_score"`
}

// TechnologyAnalysis contains detected technology stack
type TechnologyAnalysis struct {
	Stack   []*UnifiedTechnology  `json:"stack"`
	Summary map[string][]string   `json:"summary"`
}

// SecurityAnalysis contains security vulnerabilities and headers
type SecurityAnalysis struct {
	Score   int             `json:"score"`
	Issues  SecurityIssues  `json:"issues"`
	Headers SecurityHeaders `json:"headers"`
}

// SecurityIssues groups issues by severity
type SecurityIssues struct {
	Critical []SecurityIssue `json:"critical,omitempty"`
	High     []SecurityIssue `json:"high,omitempty"`
	Medium   []SecurityIssue `json:"medium,omitempty"`
	Low      []SecurityIssue `json:"low,omitempty"`
}

// SecurityHeaders tracks missing/misconfigured headers
type SecurityHeaders struct {
	Missing       []string `json:"missing,omitempty"`
	Misconfigured []string `json:"misconfigured,omitempty"`
}

// SecurityIssue represents a security vulnerability
type SecurityIssue struct {
	Type        string   `json:"type"`
	Title       string   `json:"title"`
	Description string   `json:"description"`
	Severity    string   `json:"severity"`
	Evidence    []string `json:"evidence,omitempty"`
	Impact      string   `json:"impact"`
	Remediation string   `json:"remediation"`
	Verified    bool     `json:"verified,omitempty"`
	CVE         string   `json:"cve,omitempty"`
}

// PrivacyAnalysis contains privacy risk assessment
type PrivacyAnalysis struct {
	RiskLevel string           `json:"risk_level"`
	Score     int              `json:"score"`
	Concerns  []PrivacyConcern `json:"concerns,omitempty"`
}

// PrivacyConcern represents a privacy issue
type PrivacyConcern struct {
	Type        string   `json:"type"`
	Severity    string   `json:"severity"`
	Description string   `json:"description"`
	Affected    []string `json:"affected,omitempty"`
	Mitigation  string   `json:"mitigation"`
}

// PageInfo contains page metadata and resources
type PageInfo struct {
	Metadata  *HTMLMetadata  `json:"metadata"`
	Resources *PageResources `json:"resources"`
}

// PageResources contains script, image, and link info
type PageResources struct {
	Scripts *ScriptInfo `json:"scripts"`
	Images  *ImageInfo  `json:"images"`
	Links   *LinkInfo   `json:"links"`
}

// ScriptInfo contains script analysis
type ScriptInfo struct {
	Inline       int      `json:"inline"`
	External     int      `json:"external"`
	ExternalURLs []string `json:"external_urls,omitempty"`
}

// ImageInfo contains image analysis
type ImageInfo struct {
	Total       int            `json:"total"`
	LazyLoaded  int            `json:"lazy_loaded"`
	MissingAlt  int            `json:"missing_alt"`
	Formats     map[string]int `json:"formats,omitempty"`
	Images      []Image        `json:"images,omitempty"`
}

// LinkInfo contains link analysis
type LinkInfo struct {
	Internal        int            `json:"internal"`
	External        int            `json:"external"`
	ExternalDomains []string       `json:"external_domains,omitempty"`
	Links           []OutgoingLink `json:"links,omitempty"`
}

// NetworkData contains network request information
type NetworkData struct {
	Requests        []NetworkRequest `json:"requests,omitempty"`
	ExternalDomains []string         `json:"external_domains,omitempty"`
}

// NetworkRequest represents a network request
type NetworkRequest struct {
	URL      string            `json:"url"`
	Method   string            `json:"method"`
	Type     string            `json:"type"`
	Status   int               `json:"status,omitempty"`
	Headers  map[string]string `json:"headers,omitempty"`
}

// HTMLMetadata holds HTML meta information
type HTMLMetadata struct {
	Title       string            `json:"title,omitempty"`
	Description string            `json:"description,omitempty"`
	Keywords    string            `json:"keywords,omitempty"`
	Author      string            `json:"author,omitempty"`
	Canonical   string            `json:"canonical,omitempty"`
	OpenGraph   map[string]string `json:"open_graph,omitempty"`
	TwitterCard map[string]string `json:"twitter_card,omitempty"`
}

// Supporting types for backward compatibility with existing detectors

// Image represents an extracted image from HTML (used internally)
type Image struct {
	Src         string `json:"src"`
	AbsoluteURL string `json:"absolute_url"`
	Alt         string `json:"alt,omitempty"`
	Title       string `json:"title,omitempty"`
	Width       int    `json:"width,omitempty"`
	Height      int    `json:"height,omitempty"`
	Loading     string `json:"loading,omitempty"`
	Format      string `json:"format,omitempty"`
	SourceType  string `json:"source_type"`
}

// OutgoingLink represents a link found in the HTML (used internally)
type OutgoingLink struct {
	Href        string `json:"href"`
	AbsoluteURL string `json:"absolute_url"`
	Text        string `json:"text,omitempty"`
	Rel         string `json:"rel,omitempty"`
}

// HTMLParseResult holds parsing results (internal use)
type HTMLParseResult struct {
	Links    []OutgoingLink
	Metadata *HTMLMetadata
	Images   []Image
}

// Legacy types for compatibility during transition

// SecurityCheckResult - legacy security check format
type SecurityCheckResult struct {
	Critical        []SecurityIssue    `json:"critical,omitempty"`
	High            []SecurityIssue    `json:"high,omitempty"`
	Medium          []SecurityIssue    `json:"medium,omitempty"`
	Low             []SecurityIssue    `json:"low,omitempty"`
	FormsSummary    *SecuritySummary   `json:"forms_summary,omitempty"`
	CookiesSummary  *SecuritySummary   `json:"cookies_summary,omitempty"`
	HeadersSummary  *SecuritySummary   `json:"headers_summary,omitempty"`
	CORSSummary     *SecuritySummary   `json:"cors_summary,omitempty"`
	Verifications   []VerificationResult `json:"verifications,omitempty"`
	SecurityScore   int                `json:"security_score"`
	TotalIssues     int                `json:"total_issues"`
	CriticalCount   int                `json:"critical_count"`
	HighCount       int                `json:"high_count"`
	MediumCount     int                `json:"medium_count"`
	LowCount        int                `json:"low_count"`
}

// SecuritySummary provides a category-level summary
type SecuritySummary struct {
	TotalIssues   int      `json:"total_issues"`
	CriticalCount int      `json:"critical_count"`
	HighCount     int      `json:"high_count"`
	MediumCount   int      `json:"medium_count"`
	LowCount      int      `json:"low_count"`
	TopIssues     []string `json:"top_issues,omitempty"`
}

// VerificationResult contains results of safe vulnerability verification
type VerificationResult struct {
	Issue     string `json:"issue"`
	Method    string `json:"method"`
	Confirmed bool   `json:"confirmed"`
	Details   string `json:"details"`
	Timestamp string `json:"timestamp"`
}

// Technology - legacy technology format (still used by detector)
type Technology struct {
	Name       string   `json:"name"`
	Category   string   `json:"category"`
	Version    string   `json:"version,omitempty"`
	Confidence string   `json:"confidence,omitempty"`
	Evidence   []string `json:"evidence,omitempty"`
}

// ImageAnalysis - legacy image analysis format
type ImageAnalysis struct {
	TotalImages        int            `json:"total_images"`
	MissingAlt         []string       `json:"missing_alt,omitempty"`
	LazyLoadedCount    int            `json:"lazy_loaded_count"`
	MissingSizes       []string       `json:"missing_sizes,omitempty"`
	WebPUsage          int            `json:"webp_usage"`
	Formats            map[string]int `json:"formats"`
	AccessibilityScore int            `json:"accessibility_score"`
}

// PaymentAnalysis contains detected payment methods and providers
type PaymentAnalysis struct {
	Providers      []DetectedProvider   `json:"providers,omitempty"`
	Methods        []string             `json:"methods,omitempty"`
	CheckoutFlow   *CheckoutFlow        `json:"checkout_flow,omitempty"`
	Compliance     *ComplianceAnalysis  `json:"compliance,omitempty"`
	RiskAssessment *PaymentRiskAnalysis `json:"risk_assessment,omitempty"`
	Summary        *PaymentSummary      `json:"summary,omitempty"`
}

// PaymentSummary provides high-level payment detection summary
type PaymentSummary struct {
	TotalProviders   int      `json:"total_providers"`
	PrimaryProvider  string   `json:"primary_provider,omitempty"`
	HasCreditCard    bool     `json:"has_credit_card"`
	HasWallets       bool     `json:"has_wallets"`
	HasBNPL          bool     `json:"has_bnpl"`
	HasCrypto        bool     `json:"has_crypto"`
	IsSecure         bool     `json:"is_secure"`
	ConfidenceLevel  string   `json:"confidence_level"`
}
