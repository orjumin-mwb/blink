package checker

import (
	"fmt"
	"net/http"
	"net/url"
	"strings"
)

// SecurityCORSDetector analyzes CORS configuration for security issues
type SecurityCORSDetector struct {
	sensitiveEndpoints []string
}

// NewSecurityCORSDetector creates a new CORS security detector
func NewSecurityCORSDetector() *SecurityCORSDetector {
	return &SecurityCORSDetector{
		sensitiveEndpoints: []string{
			"api", "auth", "login", "admin", "user",
			"account", "profile", "settings", "payment",
			"checkout", "order", "transaction",
		},
	}
}

// Detect analyzes CORS headers for security issues
func (d *SecurityCORSDetector) Detect(pageURL string, headers http.Header) []SecurityIssue {
	issues := []SecurityIssue{}

	// Get CORS headers
	allowOrigin := d.getHeaderValue(headers, "Access-Control-Allow-Origin")
	allowCredentials := d.getHeaderValue(headers, "Access-Control-Allow-Credentials")
	allowMethods := d.getHeaderValue(headers, "Access-Control-Allow-Methods")
	allowHeaders := d.getHeaderValue(headers, "Access-Control-Allow-Headers")
	exposeHeaders := d.getHeaderValue(headers, "Access-Control-Expose-Headers")
	maxAge := d.getHeaderValue(headers, "Access-Control-Max-Age")

	// If no CORS headers, no CORS issues to report
	if allowOrigin == "" && allowCredentials == "" && allowMethods == "" {
		return issues
	}

	// Check for wildcard origin with credentials
	if allowOrigin == "*" && strings.ToLower(allowCredentials) == "true" {
		issues = append(issues, SecurityIssue{
			Type:        "cors",
			Title:       "CORS wildcard origin with credentials",
			Description: "Access-Control-Allow-Origin is set to * with credentials enabled",
			Severity:    "critical",
			Evidence:    []string{"Access-Control-Allow-Origin: *", "Access-Control-Allow-Credentials: true"},
			Impact:      "Any website can make authenticated requests to this endpoint",
			Remediation: "Never use wildcard origin with credentials. Specify exact allowed origins",
			Verified:    true,
		})
	}

	// Check for wildcard origin without credentials (still risky for sensitive endpoints)
	if allowOrigin == "*" && d.isSensitiveEndpoint(pageURL) {
		issues = append(issues, SecurityIssue{
			Type:        "cors",
			Title:       "CORS wildcard on sensitive endpoint",
			Description: "Sensitive endpoint allows requests from any origin",
			Severity:    "high",
			Evidence:    []string{"Access-Control-Allow-Origin: *", fmt.Sprintf("URL: %s", pageURL)},
			Impact:      "Sensitive data may be accessible from any website",
			Remediation: "Restrict CORS to specific trusted origins for sensitive endpoints",
			Verified:    true,
		})
	}

	// Check for null origin
	if strings.ToLower(allowOrigin) == "null" {
		issues = append(issues, SecurityIssue{
			Type:        "cors",
			Title:       "CORS allows null origin",
			Description: "Access-Control-Allow-Origin is set to null",
			Severity:    "high",
			Evidence:    []string{"Access-Control-Allow-Origin: null"},
			Impact:      "Requests from sandboxed iframes and data: URIs are allowed",
			Remediation: "Avoid allowing 'null' origin unless specifically required",
			Verified:    true,
		})
	}

	// Check for reflected origin (potential vulnerability if not validated)
	if allowOrigin != "" && allowOrigin != "*" && !strings.HasPrefix(allowOrigin, "http") {
		// This might be a reflected origin from request
		issues = append(issues, SecurityIssue{
			Type:        "cors",
			Title:       "Potential reflected CORS origin",
			Description: "CORS origin may be reflected from request without validation",
			Severity:    "medium",
			Evidence:    []string{fmt.Sprintf("Access-Control-Allow-Origin: %s", allowOrigin)},
			Impact:      "If origin is reflected without validation, any site can bypass CORS",
			Remediation: "Validate origin against whitelist before reflecting in response",
			Verified:    false,
		})
	}

	// Check for overly permissive methods
	if allowMethods != "" {
		methods := strings.ToUpper(allowMethods)
		if strings.Contains(methods, "PUT") || strings.Contains(methods, "DELETE") || strings.Contains(methods, "PATCH") {
			if allowOrigin == "*" || (allowOrigin != "" && allowCredentials == "true") {
				issues = append(issues, SecurityIssue{
					Type:        "cors",
					Title:       "CORS allows dangerous HTTP methods",
					Description: "CORS configuration allows state-changing methods from cross-origin",
					Severity:    "high",
					Evidence:    []string{fmt.Sprintf("Access-Control-Allow-Methods: %s", allowMethods)},
					Impact:      "Cross-origin requests can modify data",
					Remediation: "Restrict dangerous methods or tighten origin restrictions",
					Verified:    true,
				})
			}
		}
	}

	// Check for sensitive headers exposure
	if exposeHeaders != "" {
		sensitiveHeaders := []string{
			"authorization", "x-api-key", "x-auth-token",
			"x-csrf-token", "cookie", "set-cookie",
		}

		exposeLower := strings.ToLower(exposeHeaders)
		for _, sensitive := range sensitiveHeaders {
			if strings.Contains(exposeLower, sensitive) {
				issues = append(issues, SecurityIssue{
					Type:        "cors",
					Title:       "CORS exposes sensitive headers",
					Description: fmt.Sprintf("Sensitive header '%s' exposed to cross-origin requests", sensitive),
					Severity:    "high",
					Evidence:    []string{fmt.Sprintf("Access-Control-Expose-Headers: %s", exposeHeaders)},
					Impact:      "Sensitive information exposed to cross-origin JavaScript",
					Remediation: "Remove sensitive headers from Access-Control-Expose-Headers",
					Verified:    true,
				})
				break
			}
		}
	}

	// Check for overly permissive allowed headers
	if allowHeaders == "*" {
		issues = append(issues, SecurityIssue{
			Type:        "cors",
			Title:       "CORS allows all request headers",
			Description: "Access-Control-Allow-Headers set to wildcard",
			Severity:    "medium",
			Evidence:    []string{"Access-Control-Allow-Headers: *"},
			Impact:      "Any custom headers can be sent in cross-origin requests",
			Remediation: "Specify exact headers needed instead of wildcard",
			Verified:    true,
		})
	}

	// Check for missing or excessive max-age
	if maxAge != "" {
		maxAgeInt := 0
		fmt.Sscanf(maxAge, "%d", &maxAgeInt)

		if maxAgeInt > 86400 { // More than 24 hours
			issues = append(issues, SecurityIssue{
				Type:        "cors",
				Title:       "Excessive CORS preflight cache duration",
				Description: fmt.Sprintf("CORS preflight cached for %d seconds", maxAgeInt),
				Severity:    "low",
				Evidence:    []string{fmt.Sprintf("Access-Control-Max-Age: %s", maxAge)},
				Impact:      "CORS policy changes take long time to propagate",
				Remediation: "Consider reducing Access-Control-Max-Age to 86400 or less",
				Verified:    true,
			})
		}
	}

	// Check for credentials without specific origin
	if allowCredentials == "true" && (allowOrigin == "" || allowOrigin == "*") {
		issues = append(issues, SecurityIssue{
			Type:        "cors",
			Title:       "Credentials allowed without specific origin",
			Description: "Access-Control-Allow-Credentials set without restricting origin",
			Severity:    "critical",
			Evidence:    []string{"Access-Control-Allow-Credentials: true"},
			Impact:      "Authentication cookies/headers sent with cross-origin requests",
			Remediation: "Always specify exact origins when allowing credentials",
			Verified:    true,
		})
	}

	// Check for multiple origins (potential misconfiguration)
	if strings.Contains(allowOrigin, " ") || strings.Contains(allowOrigin, ",") {
		issues = append(issues, SecurityIssue{
			Type:        "cors",
			Title:       "Invalid CORS origin format",
			Description: "Multiple origins in Access-Control-Allow-Origin",
			Severity:    "medium",
			Evidence:    []string{fmt.Sprintf("Access-Control-Allow-Origin: %s", allowOrigin)},
			Impact:      "CORS may not work as expected",
			Remediation: "Only one origin should be specified per response",
			Verified:    true,
		})
	}

	// Check for subdomain wildcards with credentials
	if strings.Contains(allowOrigin, "*.") && allowCredentials == "true" {
		issues = append(issues, SecurityIssue{
			Type:        "cors",
			Title:       "Subdomain wildcard with credentials",
			Description: "CORS allows subdomain wildcard with credentials",
			Severity:    "high",
			Evidence:    []string{fmt.Sprintf("Access-Control-Allow-Origin: %s", allowOrigin), "Credentials: true"},
			Impact:      "Any subdomain can make authenticated requests",
			Remediation: "Avoid subdomain wildcards with credentials or validate subdomains",
			Verified:    true,
		})
	}

	// Verify safe configuration patterns
	if len(issues) == 0 && allowOrigin != "" {
		// Safe verification: properly configured CORS
		parsedURL, err := url.Parse(pageURL)
		if err == nil && allowOrigin == fmt.Sprintf("%s://%s", parsedURL.Scheme, parsedURL.Host) {
			// Same-origin CORS (redundant but safe)
			issues = append(issues, SecurityIssue{
				Type:        "cors",
				Title:       "Redundant same-origin CORS",
				Description: "CORS header allows same origin (unnecessary)",
				Severity:    "low",
				Evidence:    []string{fmt.Sprintf("Access-Control-Allow-Origin: %s", allowOrigin)},
				Impact:      "No security impact but header is redundant",
				Remediation: "CORS headers not needed for same-origin requests",
				Verified:    true,
			})
		}
	}

	return issues
}

// isSensitiveEndpoint checks if URL appears to be a sensitive endpoint
func (d *SecurityCORSDetector) isSensitiveEndpoint(pageURL string) bool {
	urlLower := strings.ToLower(pageURL)

	for _, endpoint := range d.sensitiveEndpoints {
		if strings.Contains(urlLower, endpoint) {
			return true
		}
	}

	// Check for API endpoints
	if strings.Contains(urlLower, "/api/") || strings.Contains(urlLower, "/v1/") || strings.Contains(urlLower, "/v2/") {
		return true
	}

	return false
}

// getHeaderValue gets a header value (case-insensitive)
func (d *SecurityCORSDetector) getHeaderValue(headers http.Header, name string) string {
	for key, values := range headers {
		if strings.EqualFold(key, name) && len(values) > 0 {
			return values[0]
		}
	}
	return ""
}