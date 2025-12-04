package checker

import (
	"net/http"
	"strings"
	"time"
)

// ResponseBuilder assembles the unified deep-check response
type ResponseBuilder struct {
	aggregator       *DetectionAggregator
	url              string
	timestamp        time.Time
	analysisDuration time.Duration

	// Additional data
	securityIssues   *SecurityCheckResult
	privacyData      *PrivacyAnalysis
	pageInfo         *PageInfo
	networkData      *NetworkData

	// Context for scoring
	siteContext      *SiteContext
	headers          http.Header
	html             string
	forms            []FormInfo
	hasSecurityTxt   bool
}

// NewResponseBuilder creates a new response builder
func NewResponseBuilder(url string) *ResponseBuilder {
	return &ResponseBuilder{
		aggregator: NewDetectionAggregator(),
		url:        url,
		timestamp:  time.Now(),
	}
}

// SetAnalysisDuration sets the total analysis duration
func (rb *ResponseBuilder) SetAnalysisDuration(duration time.Duration) {
	rb.analysisDuration = duration
}

// SetSecurityIssues sets the security check results
func (rb *ResponseBuilder) SetSecurityIssues(issues *SecurityCheckResult) {
	rb.securityIssues = issues
}

// SetPrivacyData sets privacy analysis data
func (rb *ResponseBuilder) SetPrivacyData(privacy *PrivacyAnalysis) {
	rb.privacyData = privacy
}

// SetPageInfo sets page metadata and resources
func (rb *ResponseBuilder) SetPageInfo(info *PageInfo) {
	rb.pageInfo = info
}

// SetNetworkData sets network analysis data
func (rb *ResponseBuilder) SetNetworkData(network *NetworkData) {
	rb.networkData = network
}

// SetContextData sets context data for scoring
func (rb *ResponseBuilder) SetContextData(headers http.Header, html string, forms []FormInfo) {
	rb.headers = headers
	rb.html = html
	rb.forms = forms
	rb.siteContext = DetectSiteContext(rb.url, html, forms)
}

// SetSecurityTxt sets whether security.txt was found
func (rb *ResponseBuilder) SetSecurityTxt(hasIt bool) {
	rb.hasSecurityTxt = hasIt
}

// GetAggregator returns the detection aggregator for adding detections
func (rb *ResponseBuilder) GetAggregator() *DetectionAggregator {
	return rb.aggregator
}

// Build assembles the final unified response
func (rb *ResponseBuilder) Build() *DeepCheckResult {
	trackerSummary, techSummary := rb.aggregator.GenerateSummaries()

	result := &DeepCheckResult{
		URL:              rb.url,
		Timestamp:        rb.timestamp.Format(time.RFC3339),
		AnalysisDuration: rb.analysisDuration.String(),

		Tracking: &TrackingAnalysis{
			Services: rb.aggregator.GetTrackers(),
			Summary:  trackerSummary,
		},

		APIUsage: &APIAnalysis{
			Detected: rb.aggregator.GetAPIs(),
		},

		Technologies: &TechnologyAnalysis{
			Stack:   rb.aggregator.GetTechnologies(),
			Summary: techSummary,
		},
	}

	// Add security data
	if rb.securityIssues != nil {
		result.Security = rb.buildSecuritySection()
	}

	// Add privacy data
	if rb.privacyData != nil {
		result.Privacy = rb.privacyData
	} else {
		result.Privacy = rb.derivePrivacyFromDetections()
	}

	// Add page info
	if rb.pageInfo != nil {
		result.PageInfo = rb.pageInfo
	}

	// Add network data
	if rb.networkData != nil {
		result.Network = rb.networkData
	}

	// Calculate fingerprinting analysis
	result.APIUsage.Fingerprinting = rb.calculateFingerprinting()

	return result
}

// buildSecuritySection converts SecurityCheckResult to the new format with improved scoring
func (rb *ResponseBuilder) buildSecuritySection() *SecurityAnalysis {
	// New scoring algorithm:
	// - Start at 70 (base score)
	// - Deduct points for issues (reduced penalties)
	// - Add bonus points for good practices (up to 30)
	// - Context-aware severity adjustment

	baseScore := 70
	score := baseScore

	// Adjust issue severities based on context
	adjustedIssues := rb.adjustIssuesForContext()

	// Apply penalties (reduced from original)
	if rb.securityIssues != nil {
		score -= len(adjustedIssues.Critical) * 15  // was 25
		score -= len(adjustedIssues.High) * 5       // was 10
		score -= len(adjustedIssues.Medium) * 2     // was 5
		score -= len(adjustedIssues.Low) * 1        // was 1 (kept same for int math)

		// Floor at 0
		if score < 0 {
			score = 0
		}
	}

	// Calculate bonus points for good practices
	bonusPoints := rb.calculateBonusPoints(adjustedIssues)
	score += bonusPoints

	// Cap at 100
	if score > 100 {
		score = 100
	}

	security := &SecurityAnalysis{
		Score: score,
		Issues: SecurityIssues{
			Critical: adjustedIssues.Critical,
			High:     adjustedIssues.High,
			Medium:   adjustedIssues.Medium,
			Low:      adjustedIssues.Low,
		},
		Headers: SecurityHeaders{
			Missing:       []string{},
			Misconfigured: []string{},
		},
	}

	// Extract header issues from security checks
	for _, issue := range adjustedIssues.High {
		if issue.Type == "missing_security_header" || issue.Type == "header" {
			security.Headers.Missing = append(security.Headers.Missing, issue.Title)
		}
	}
	for _, issue := range adjustedIssues.Medium {
		if issue.Type == "misconfigured_header" || issue.Type == "header" {
			security.Headers.Misconfigured = append(security.Headers.Misconfigured, issue.Title)
		}
	}

	return security
}

// adjustIssuesForContext adjusts issue severities based on site context and third-party sources
func (rb *ResponseBuilder) adjustIssuesForContext() SecurityCheckResult {
	if rb.securityIssues == nil || rb.siteContext == nil {
		if rb.securityIssues == nil {
			return SecurityCheckResult{}
		}
		return *rb.securityIssues
	}

	adjusted := SecurityCheckResult{
		Critical: []SecurityIssue{},
		High:     []SecurityIssue{},
		Medium:   []SecurityIssue{},
		Low:      []SecurityIssue{},
	}

	// Helper function to categorize by adjusted severity
	categorizeIssue := func(issue SecurityIssue, severity string) {
		issue.Severity = severity
		switch severity {
		case "critical":
			adjusted.Critical = append(adjusted.Critical, issue)
		case "high":
			adjusted.High = append(adjusted.High, issue)
		case "medium":
			adjusted.Medium = append(adjusted.Medium, issue)
		case "low":
			adjusted.Low = append(adjusted.Low, issue)
		}
	}

	// Process all issues
	allIssues := append([]SecurityIssue{}, rb.securityIssues.Critical...)
	allIssues = append(allIssues, rb.securityIssues.High...)
	allIssues = append(allIssues, rb.securityIssues.Medium...)
	allIssues = append(allIssues, rb.securityIssues.Low...)

	for _, issue := range allIssues {
		adjustedSeverity := issue.Severity

		// Apply third-party trust level adjustments
		adjustedSeverity = rb.applyThirdPartyAdjustment(issue, adjustedSeverity)

		// Apply context-based adjustments
		adjustedSeverity = AdjustSeverityForContext(issue, rb.siteContext)

		// Categorize with adjusted severity
		categorizeIssue(issue, adjustedSeverity)
	}

	return adjusted
}

// applyThirdPartyAdjustment reduces severity for issues in trusted third-party code
func (rb *ResponseBuilder) applyThirdPartyAdjustment(issue SecurityIssue, severity string) string {
	// Check if issue is related to third-party code
	if issue.Type == "client-xss" || issue.Type == "sri" {
		// Check evidence for third-party URLs
		for _, evidence := range issue.Evidence {
			// Look for URLs in evidence
			if strings.Contains(evidence, "http") {
				// Extract potential URLs and check if trusted
				words := strings.Fields(evidence)
				for _, word := range words {
					if strings.HasPrefix(word, "http") && IsFromTrustedProvider(word) {
						// Reduce severity for trusted third-party issues
						return ReduceSeverity(severity)
					}
				}
			}
		}

		// For eval detection, reduce severity if likely from third-party
		if issue.Type == "client-xss" && strings.Contains(issue.Title, "eval") {
			// Most eval usage is from third-party analytics/optimization tools
			// Reduce from high to medium
			if severity == "high" {
				return "medium"
			}
		}
	}

	// SRI missing on scripts - check if they're from trusted CDNs
	if issue.Type == "sri" && strings.Contains(issue.Description, "scripts") {
		// Reduce severity as most scripts are from trusted providers
		// and SRI is not widely adopted
		if severity == "high" {
			return "medium"
		}
	}

	return severity
}

// calculateBonusPoints awards bonus points for good security practices
func (rb *ResponseBuilder) calculateBonusPoints(issues SecurityCheckResult) int {
	if rb.headers == nil {
		return 0
	}

	// Collect all issues for bonus calculation
	allIssues := append([]SecurityIssue{}, issues.Critical...)
	allIssues = append(allIssues, issues.High...)
	allIssues = append(allIssues, issues.Medium...)
	allIssues = append(allIssues, issues.Low...)

	bonusPoints := CalculateBonusPoints(rb.headers, allIssues, rb.hasSecurityTxt)
	return bonusPoints.Total()
}

// derivePrivacyFromDetections calculates privacy analysis from detected trackers and APIs
func (rb *ResponseBuilder) derivePrivacyFromDetections() *PrivacyAnalysis {
	trackers := rb.aggregator.GetTrackers()
	apis := rb.aggregator.GetAPIs()

	// Calculate risk based on trackers and APIs
	riskLevel := "low"
	riskScore := 0

	// Count high-risk trackers
	highRiskTrackers := 0
	for _, tracker := range trackers {
		if tracker.RiskLevel == "high" {
			highRiskTrackers++
			riskScore += 15
		} else if tracker.RiskLevel == "medium" {
			riskScore += 8
		} else {
			riskScore += 3
		}
	}

	// Count high-risk APIs
	for _, api := range apis {
		if api.Executed && api.RiskLevel == "high" {
			riskScore += 10
		}
	}

	// Determine overall risk level
	if riskScore >= 50 {
		riskLevel = "high"
	} else if riskScore >= 25 {
		riskLevel = "medium"
	}

	concerns := []PrivacyConcern{}
	if len(trackers) > 3 {
		concerns = append(concerns, PrivacyConcern{
			Type:        "excessive_tracking",
			Severity:    "high",
			Description: "Multiple tracking services detected",
			Affected:    extractTrackerNames(trackers),
			Mitigation:  "Consider privacy-focused alternatives",
		})
	}

	return &PrivacyAnalysis{
		RiskLevel: riskLevel,
		Score:     riskScore,
		Concerns:  concerns,
	}
}

// calculateFingerprinting analyzes fingerprinting techniques
func (rb *ResponseBuilder) calculateFingerprinting() *FingerprintingAnalysis {
	apis := rb.aggregator.GetAPIs()

	fingerprintingAPIs := []string{
		"canvas api", "webgl api", "audio api", "font api",
		"battery api", "device memory api", "hardware concurrency api",
	}

	detected := false
	techniques := []string{}
	entropy := 0.0

	for _, api := range apis {
		if api.Executed {
			apiLower := stringToLower(api.Name)
			for _, fpAPI := range fingerprintingAPIs {
				if contains(apiLower, fpAPI) {
					detected = true
					techniques = append(techniques, api.Name)
					entropy += 3.5
					break
				}
			}
		}
	}

	return &FingerprintingAnalysis{
		Detected:     detected,
		Techniques:   techniques,
		EntropyScore: entropy,
	}
}

// Helper functions

func extractTrackerNames(trackers []*UnifiedTracker) []string {
	names := make([]string, len(trackers))
	for i, tracker := range trackers {
		names[i] = tracker.Name
	}
	return names
}

func stringToLower(s string) string {
	return strings.ToLower(s)
}

func contains(s, substr string) bool {
	return strings.Contains(s, substr)
}
