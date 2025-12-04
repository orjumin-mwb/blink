package checker

import (
	"net/http"
	"net/url"
	"strings"
)

// SiteContext provides context about the site for context-aware scoring
type SiteContext struct {
	IsSensitiveSite bool // Banking, healthcare, government
	HasUserAuth     bool // Has login/registration
	HasPayment      bool // Processes payments
	HasPersonalData bool // Collects PII
	IsAPIEndpoint   bool // Is an API endpoint
}

// SecurityBonusPoints tracks bonus points for good security practices
type SecurityBonusPoints struct {
	// Security Headers (max 10 points)
	StrongCSP            int // +3
	HSTSWithPreload      int // +2
	FrameProtection      int // +2
	SecurityTxt          int // +1
	PermissionsPolicy    int // +1
	ReferrerPolicy       int // +1

	// Best Practices (max 10 points)
	SRICoverage          int // +3
	HTTPSEverywhere      int // +2
	SecureCookies        int // +2
	CSRFProtection       int // +2
	NoMixedContent       int // +1

	// Advanced Security (max 10 points)
	DNSSEC               int // +3
	CAARecords           int // +2
	RateLimiting         int // +2
	NoDangerousEval      int // +2
	SecureAuth           int // +1
}

// TrustedThirdPartyProvider represents a known trusted CDN or service
var TrustedThirdPartyProviders = []string{
	"googleapis.com",
	"googletagmanager.com",
	"google-analytics.com",
	"gstatic.com",
	"cloudflare.com",
	"cloudflareinsights.com",
	"cloudfront.net",
	"unpkg.com",
	"jsdelivr.net",
	"cdnjs.cloudflare.com",
	"bootstrapcdn.com",
	"jquery.com",
	"fontawesome.com",
	"fonts.gstatic.com",
	"polyfill.io",
	"akamaized.net",
	"fastly.net",
	"jsdelivr.net",
	"visualwebsiteoptimizer.com", // VWO
	"plausible.io",
	"cookielaw.org", // OneTrust
	"onetrust.com",
}

// SensitiveDomainKeywords indicates domains that should have higher security standards
var SensitiveDomainKeywords = []string{
	"bank", "banking", "credit", "loan", "mortgage",
	"health", "medical", "hospital", "patient", "clinic",
	"gov", "government", "military", "defense",
	"insurance", "payment", "pay", "checkout", "wallet",
	"invest", "trading", "brokerage", "crypto",
	"tax", "irs", "revenue",
}

// AuthenticationKeywords indicates pages with authentication
var AuthenticationKeywords = []string{
	"login", "signin", "sign-in", "auth", "authenticate",
	"register", "signup", "sign-up", "account",
	"password", "reset", "forgot",
	"oauth", "sso",
}

// PaymentKeywords indicates payment processing
var PaymentKeywords = []string{
	"checkout", "payment", "pay", "cart", "order",
	"billing", "invoice", "purchase", "subscribe",
	"stripe", "paypal", "square",
}

// DetectSiteContext analyzes the URL and content to determine site context
func DetectSiteContext(pageURL string, html string, forms []FormInfo) *SiteContext {
	context := &SiteContext{}

	parsedURL, err := url.Parse(pageURL)
	if err != nil {
		return context
	}

	domain := strings.ToLower(parsedURL.Hostname())
	path := strings.ToLower(parsedURL.Path)
	htmlLower := strings.ToLower(html)

	// Check if sensitive site
	context.IsSensitiveSite = isSensitiveDomain(domain, path)

	// Check for authentication
	context.HasUserAuth = hasAuthentication(path, htmlLower, forms)

	// Check for payment processing
	context.HasPayment = hasPaymentProcessing(path, htmlLower, forms)

	// Check for personal data collection
	context.HasPersonalData = hasPersonalDataCollection(forms)

	// Check if API endpoint
	context.IsAPIEndpoint = isAPIEndpoint(path)

	return context
}

// isSensitiveDomain checks if the domain/path indicates a sensitive site
func isSensitiveDomain(domain, path string) bool {
	combined := domain + path

	for _, keyword := range SensitiveDomainKeywords {
		if strings.Contains(combined, keyword) {
			return true
		}
	}

	return false
}

// hasAuthentication checks for authentication pages
func hasAuthentication(path, html string, forms []FormInfo) bool {
	// Check URL path
	for _, keyword := range AuthenticationKeywords {
		if strings.Contains(path, keyword) {
			return true
		}
	}

	// Check HTML content
	for _, keyword := range AuthenticationKeywords {
		if strings.Contains(html, keyword) {
			return true
		}
	}

	// Check for password fields in forms
	for _, form := range forms {
		if form.HasPasswordField {
			return true
		}
	}

	return false
}

// hasPaymentProcessing checks for payment processing
func hasPaymentProcessing(path, html string, forms []FormInfo) bool {
	// Check URL path
	for _, keyword := range PaymentKeywords {
		if strings.Contains(path, keyword) {
			return true
		}
	}

	// Check HTML content
	for _, keyword := range PaymentKeywords {
		if strings.Contains(html, keyword) {
			return true
		}
	}

	// Check hidden fields for payment-related names
	for _, form := range forms {
		for _, hidden := range form.HiddenFields {
			name := strings.ToLower(hidden.Name)
			if strings.Contains(name, "card") || strings.Contains(name, "cvv") ||
				strings.Contains(name, "ccv") || strings.Contains(name, "cvc") ||
				strings.Contains(name, "payment") || strings.Contains(name, "stripe") {
				return true
			}
		}
	}

	return false
}

// hasPersonalDataCollection checks if forms collect PII
func hasPersonalDataCollection(forms []FormInfo) bool {
	// Check if forms have sensitive fields
	for _, form := range forms {
		if form.HasSensitiveField {
			return true
		}

		// Check hidden field names for PII indicators
		piiFields := []string{
			"email", "phone", "address", "ssn", "social",
			"firstname", "lastname", "name", "dob", "birthdate",
		}

		for _, hidden := range form.HiddenFields {
			name := strings.ToLower(hidden.Name)
			for _, piiField := range piiFields {
				if strings.Contains(name, piiField) {
					return true
				}
			}
		}
	}

	return false
}

// isAPIEndpoint checks if the URL is an API endpoint
func isAPIEndpoint(path string) bool {
	apiIndicators := []string{"/api/", "/v1/", "/v2/", "/v3/", "/graphql", "/rest/"}

	for _, indicator := range apiIndicators {
		if strings.Contains(path, indicator) {
			return true
		}
	}

	return false
}

// IsFromTrustedProvider checks if a URL is from a trusted third-party provider
func IsFromTrustedProvider(resourceURL string) bool {
	parsedURL, err := url.Parse(resourceURL)
	if err != nil {
		return false
	}

	hostname := strings.ToLower(parsedURL.Hostname())

	for _, provider := range TrustedThirdPartyProviders {
		if strings.Contains(hostname, provider) || strings.HasSuffix(hostname, provider) {
			return true
		}
	}

	return false
}

// ReduceSeverity reduces the severity level by one step
func ReduceSeverity(severity string) string {
	switch severity {
	case "critical":
		return "high"
	case "high":
		return "medium"
	case "medium":
		return "low"
	case "low":
		return "info"
	default:
		return severity
	}
}

// AdjustSeverityForContext adjusts severity based on site context
func AdjustSeverityForContext(issue SecurityIssue, context *SiteContext) string {
	severity := issue.Severity

	// Increase severity for sensitive sites
	if context.IsSensitiveSite {
		switch issue.Type {
		case "client-xss", "csrf", "auth", "cookie", "data-exposure":
			// Don't reduce severity for security-critical issues on sensitive sites
			return severity
		}
	}

	// Increase severity for auth pages
	if context.HasUserAuth {
		switch issue.Type {
		case "csrf", "auth", "cookie", "session", "clickjacking":
			// These are critical on auth pages
			if severity == "medium" {
				return "high"
			}
		}
	}

	// Increase severity for payment pages
	if context.HasPayment {
		switch issue.Type {
		case "csrf", "client-xss", "data-exposure", "cookie":
			if severity == "medium" {
				return "high"
			}
		}
	}

	return severity
}

// CalculateBonusPoints calculates bonus points based on detected security features
func CalculateBonusPoints(headers http.Header, issues []SecurityIssue, hasSecurityTxt bool) SecurityBonusPoints {
	bonus := SecurityBonusPoints{}

	// Security Headers (max 10 points)
	csp := headers.Get("Content-Security-Policy")
	if csp != "" {
		// Check for strong CSP
		if strings.Contains(csp, "default-src") && !strings.Contains(csp, "unsafe-inline") {
			bonus.StrongCSP = 3
		}
	}

	hsts := headers.Get("Strict-Transport-Security")
	if hsts != "" {
		if strings.Contains(hsts, "preload") && strings.Contains(hsts, "includeSubDomains") {
			bonus.HSTSWithPreload = 2
		}
	}

	xFrameOptions := headers.Get("X-Frame-Options")
	if xFrameOptions != "" || strings.Contains(csp, "frame-ancestors") {
		bonus.FrameProtection = 2
	}

	if hasSecurityTxt {
		bonus.SecurityTxt = 1
	}

	permissionsPolicy := headers.Get("Permissions-Policy")
	if permissionsPolicy != "" {
		bonus.PermissionsPolicy = 1
	}

	referrerPolicy := headers.Get("Referrer-Policy")
	if referrerPolicy != "" {
		bonus.ReferrerPolicy = 1
	}

	// Best Practices (max 10 points)
	hasSRIIssue := false
	hasMixedContentIssue := false
	hasInsecureCookieIssue := false
	hasNoCSRFIssue := false

	for _, issue := range issues {
		switch issue.Type {
		case "sri":
			hasSRIIssue = true
		case "mixed-content":
			hasMixedContentIssue = true
		case "cookie":
			if strings.Contains(strings.ToLower(issue.Title), "secure") {
				hasInsecureCookieIssue = true
			}
		case "csrf":
			hasNoCSRFIssue = true
		}
	}

	// Award points for absence of issues
	if !hasSRIIssue {
		bonus.SRICoverage = 3
	}

	if !hasMixedContentIssue {
		bonus.HTTPSEverywhere = 2
		bonus.NoMixedContent = 1
	}

	if !hasInsecureCookieIssue {
		bonus.SecureCookies = 2
	}

	if !hasNoCSRFIssue {
		bonus.CSRFProtection = 2
	}

	// Advanced Security would be calculated elsewhere (DNS checks, etc.)

	return bonus
}

// TotalBonusPoints returns the total bonus points
func (b SecurityBonusPoints) Total() int {
	return b.StrongCSP + b.HSTSWithPreload + b.FrameProtection +
		b.SecurityTxt + b.PermissionsPolicy + b.ReferrerPolicy +
		b.SRICoverage + b.HTTPSEverywhere + b.SecureCookies +
		b.CSRFProtection + b.NoMixedContent +
		b.DNSSEC + b.CAARecords + b.RateLimiting +
		b.NoDangerousEval + b.SecureAuth
}
