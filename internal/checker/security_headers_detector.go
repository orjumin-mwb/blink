package checker

import (
	"fmt"
	"net/http"
	"regexp"
	"strings"
)

// SecurityHeadersDetector analyzes HTTP headers for security issues
type SecurityHeadersDetector struct {
	cspDirectives map[string]bool
}

// NewSecurityHeadersDetector creates a new security headers detector
func NewSecurityHeadersDetector() *SecurityHeadersDetector {
	return &SecurityHeadersDetector{
		cspDirectives: map[string]bool{
			"default-src":     true,
			"script-src":      true,
			"style-src":       true,
			"img-src":         true,
			"connect-src":     true,
			"font-src":        true,
			"object-src":      true,
			"media-src":       true,
			"frame-src":       true,
			"child-src":       true,
			"form-action":     true,
			"frame-ancestors": true,
			"base-uri":        true,
			"upgrade-insecure-requests": true,
		},
	}
}

// Detect analyzes HTTP headers for security issues
func (d *SecurityHeadersDetector) Detect(pageURL string, headers http.Header) []SecurityIssue {
	issues := []SecurityIssue{}

	isHTTPS := strings.HasPrefix(pageURL, "https://")

	// Check for Content-Security-Policy
	csp := d.getHeaderValue(headers, "Content-Security-Policy")
	if csp == "" {
		issues = append(issues, SecurityIssue{
			Type:        "header",
			Title:       "Missing Content-Security-Policy header",
			Description: "No Content-Security-Policy header found",
			Severity:    "medium",
			Evidence:    []string{"Content-Security-Policy header not present"},
			Impact:      "No protection against XSS and injection attacks",
			Remediation: "Implement a Content-Security-Policy header with appropriate directives",
			Verified:    true,
		})
	} else {
		// Analyze CSP directives
		cspIssues := d.analyzeCSP(csp)
		issues = append(issues, cspIssues...)
	}

	// Check for X-Frame-Options
	xfo := d.getHeaderValue(headers, "X-Frame-Options")
	if xfo == "" {
		issues = append(issues, SecurityIssue{
			Type:        "header",
			Title:       "Missing X-Frame-Options header",
			Description: "No protection against clickjacking attacks",
			Severity:    "medium",
			Evidence:    []string{"X-Frame-Options header not present"},
			Impact:      "Page can be embedded in iframes (clickjacking risk)",
			Remediation: "Set X-Frame-Options to DENY or SAMEORIGIN",
			Verified:    true,
		})
	} else if strings.ToUpper(xfo) == "ALLOW-FROM" {
		issues = append(issues, SecurityIssue{
			Type:        "header",
			Title:       "Deprecated X-Frame-Options value",
			Description: "ALLOW-FROM is deprecated and not supported by modern browsers",
			Severity:    "low",
			Evidence:    []string{fmt.Sprintf("X-Frame-Options: %s", xfo)},
			Impact:      "Clickjacking protection may not work in all browsers",
			Remediation: "Use Content-Security-Policy frame-ancestors instead",
			Verified:    true,
		})
	}

	// Check for X-Content-Type-Options
	xcto := d.getHeaderValue(headers, "X-Content-Type-Options")
	if xcto == "" {
		issues = append(issues, SecurityIssue{
			Type:        "header",
			Title:       "Missing X-Content-Type-Options header",
			Description: "No protection against MIME type sniffing",
			Severity:    "low",
			Evidence:    []string{"X-Content-Type-Options header not present"},
			Impact:      "Browser may interpret files as different MIME types",
			Remediation: "Set X-Content-Type-Options: nosniff",
			Verified:    true,
		})
	} else if strings.ToLower(xcto) != "nosniff" {
		issues = append(issues, SecurityIssue{
			Type:        "header",
			Title:       "Invalid X-Content-Type-Options value",
			Description: fmt.Sprintf("X-Content-Type-Options should be 'nosniff', got '%s'", xcto),
			Severity:    "low",
			Evidence:    []string{fmt.Sprintf("X-Content-Type-Options: %s", xcto)},
			Impact:      "MIME type sniffing protection not properly configured",
			Remediation: "Set X-Content-Type-Options: nosniff",
			Verified:    true,
		})
	}

	// Check for Strict-Transport-Security (HSTS) on HTTPS
	if isHTTPS {
		hsts := d.getHeaderValue(headers, "Strict-Transport-Security")
		if hsts == "" {
			issues = append(issues, SecurityIssue{
				Type:        "header",
				Title:       "Missing Strict-Transport-Security header",
				Description: "HTTPS site lacks HSTS protection",
				Severity:    "high",
				Evidence:    []string{"Strict-Transport-Security header not present"},
				Impact:      "Users can be downgraded to HTTP through attacks",
				Remediation: "Implement HSTS with appropriate max-age",
				Verified:    true,
			})
		} else {
			// Check HSTS configuration
			hstsIssues := d.analyzeHSTS(hsts)
			issues = append(issues, hstsIssues...)
		}
	}

	// Check for X-XSS-Protection
	xxss := d.getHeaderValue(headers, "X-XSS-Protection")
	if xxss == "" {
		// Note: This header is deprecated but still worth checking
		issues = append(issues, SecurityIssue{
			Type:        "header",
			Title:       "Missing X-XSS-Protection header",
			Description: "No browser XSS filter configuration",
			Severity:    "low",
			Evidence:    []string{"X-XSS-Protection header not present"},
			Impact:      "Browser XSS filter may not be enabled",
			Remediation: "Set X-XSS-Protection: 1; mode=block (or rely on CSP)",
			Verified:    true,
		})
	} else if xxss == "0" {
		issues = append(issues, SecurityIssue{
			Type:        "header",
			Title:       "XSS protection disabled",
			Description: "X-XSS-Protection explicitly disables browser XSS filter",
			Severity:    "medium",
			Evidence:    []string{"X-XSS-Protection: 0"},
			Impact:      "Browser XSS filter is disabled",
			Remediation: "Enable XSS protection or remove header and use CSP",
			Verified:    true,
		})
	}

	// Check for Referrer-Policy
	rp := d.getHeaderValue(headers, "Referrer-Policy")
	if rp == "" {
		issues = append(issues, SecurityIssue{
			Type:        "header",
			Title:       "Missing Referrer-Policy header",
			Description: "No control over referrer information leakage",
			Severity:    "low",
			Evidence:    []string{"Referrer-Policy header not present"},
			Impact:      "Sensitive URLs may be leaked through referrer",
			Remediation: "Set appropriate Referrer-Policy",
			Verified:    true,
		})
	} else if strings.Contains(strings.ToLower(rp), "unsafe-url") {
		issues = append(issues, SecurityIssue{
			Type:        "header",
			Title:       "Unsafe Referrer-Policy",
			Description: "Referrer-Policy set to unsafe-url",
			Severity:    "medium",
			Evidence:    []string{fmt.Sprintf("Referrer-Policy: %s", rp)},
			Impact:      "Full URLs including sensitive data sent as referrer",
			Remediation: "Use safer Referrer-Policy like 'strict-origin-when-cross-origin'",
			Verified:    true,
		})
	}

	// Check for Permissions-Policy (formerly Feature-Policy)
	pp := d.getHeaderValue(headers, "Permissions-Policy")
	fp := d.getHeaderValue(headers, "Feature-Policy")
	if pp == "" && fp == "" {
		issues = append(issues, SecurityIssue{
			Type:        "header",
			Title:       "Missing Permissions-Policy header",
			Description: "No restrictions on browser features",
			Severity:    "low",
			Evidence:    []string{"Permissions-Policy header not present"},
			Impact:      "No control over powerful browser features",
			Remediation: "Implement Permissions-Policy to restrict features",
			Verified:    true,
		})
	}

	// Check for information disclosure headers
	serverHeader := d.getHeaderValue(headers, "Server")
	if serverHeader != "" && d.containsVersionInfo(serverHeader) {
		issues = append(issues, SecurityIssue{
			Type:        "header",
			Title:       "Server version disclosure",
			Description: fmt.Sprintf("Server header reveals version information: %s", serverHeader),
			Severity:    "low",
			Evidence:    []string{fmt.Sprintf("Server: %s", serverHeader)},
			Impact:      "Attackers can target known vulnerabilities",
			Remediation: "Remove or obfuscate server version information",
			Verified:    true,
		})
	}

	xPoweredBy := d.getHeaderValue(headers, "X-Powered-By")
	if xPoweredBy != "" {
		issues = append(issues, SecurityIssue{
			Type:        "header",
			Title:       "Technology disclosure via X-Powered-By",
			Description: fmt.Sprintf("X-Powered-By reveals technology: %s", xPoweredBy),
			Severity:    "low",
			Evidence:    []string{fmt.Sprintf("X-Powered-By: %s", xPoweredBy)},
			Impact:      "Reveals technology stack to potential attackers",
			Remediation: "Remove X-Powered-By header",
			Verified:    true,
		})
	}

	// Check for X-AspNet-Version
	xAspNet := d.getHeaderValue(headers, "X-AspNet-Version")
	if xAspNet != "" {
		issues = append(issues, SecurityIssue{
			Type:        "header",
			Title:       "ASP.NET version disclosure",
			Description: fmt.Sprintf("X-AspNet-Version reveals version: %s", xAspNet),
			Severity:    "low",
			Evidence:    []string{fmt.Sprintf("X-AspNet-Version: %s", xAspNet)},
			Impact:      "Reveals ASP.NET version to potential attackers",
			Remediation: "Remove X-AspNet-Version header",
			Verified:    true,
		})
	}

	return issues
}

// analyzeCSP analyzes Content-Security-Policy directives
func (d *SecurityHeadersDetector) analyzeCSP(csp string) []SecurityIssue {
	issues := []SecurityIssue{}

	cspLower := strings.ToLower(csp)

	// Check for unsafe-inline in script-src
	if strings.Contains(cspLower, "'unsafe-inline'") && strings.Contains(cspLower, "script-src") {
		issues = append(issues, SecurityIssue{
			Type:        "header",
			Title:       "CSP allows unsafe-inline scripts",
			Description: "Content-Security-Policy allows inline JavaScript execution",
			Severity:    "high",
			Evidence:    []string{"script-src contains 'unsafe-inline'"},
			Impact:      "Inline script injection (XSS) attacks are not prevented",
			Remediation: "Remove 'unsafe-inline' and use nonces or hashes for inline scripts",
			Verified:    true,
		})
	}

	// Check for unsafe-eval
	if strings.Contains(cspLower, "'unsafe-eval'") {
		issues = append(issues, SecurityIssue{
			Type:        "header",
			Title:       "CSP allows unsafe-eval",
			Description: "Content-Security-Policy allows eval() and similar functions",
			Severity:    "high",
			Evidence:    []string{"CSP contains 'unsafe-eval'"},
			Impact:      "Dynamic code execution vulnerabilities",
			Remediation: "Remove 'unsafe-eval' from CSP",
			Verified:    true,
		})
	}

	// Check for wildcard sources
	if strings.Contains(csp, "*") && !strings.Contains(csp, "*.") {
		// Wildcard without domain prefix
		issues = append(issues, SecurityIssue{
			Type:        "header",
			Title:       "CSP with wildcard source",
			Description: "Content-Security-Policy contains unrestricted wildcard (*)",
			Severity:    "medium",
			Evidence:    []string{"CSP contains wildcard source (*)"},
			Impact:      "Resources can be loaded from any origin",
			Remediation: "Specify explicit allowed sources instead of wildcards",
			Verified:    true,
		})
	}

	// Check for missing default-src
	if !strings.Contains(cspLower, "default-src") {
		issues = append(issues, SecurityIssue{
			Type:        "header",
			Title:       "CSP missing default-src",
			Description: "Content-Security-Policy lacks default-src directive",
			Severity:    "medium",
			Evidence:    []string{"No default-src directive found"},
			Impact:      "No fallback policy for unspecified resource types",
			Remediation: "Add default-src directive as baseline policy",
			Verified:    true,
		})
	}

	// Check for data: URIs in script-src
	if strings.Contains(cspLower, "script-src") && strings.Contains(cspLower, "data:") {
		issues = append(issues, SecurityIssue{
			Type:        "header",
			Title:       "CSP allows data: URIs for scripts",
			Description: "Script execution from data: URIs is allowed",
			Severity:    "high",
			Evidence:    []string{"script-src contains data:"},
			Impact:      "Scripts can be injected via data: URIs",
			Remediation: "Remove data: from script-src directive",
			Verified:    true,
		})
	}

	// Check for missing frame-ancestors
	if !strings.Contains(cspLower, "frame-ancestors") {
		issues = append(issues, SecurityIssue{
			Type:        "header",
			Title:       "CSP missing frame-ancestors",
			Description: "No clickjacking protection via CSP frame-ancestors",
			Severity:    "low",
			Evidence:    []string{"No frame-ancestors directive"},
			Impact:      "Page can be embedded in frames",
			Remediation: "Add frame-ancestors directive to CSP",
			Verified:    true,
		})
	}

	return issues
}

// analyzeHSTS analyzes Strict-Transport-Security configuration
func (d *SecurityHeadersDetector) analyzeHSTS(hsts string) []SecurityIssue {
	issues := []SecurityIssue{}

	hstsLower := strings.ToLower(hsts)

	// Extract max-age
	maxAgePattern := regexp.MustCompile(`max-age=(\d+)`)
	matches := maxAgePattern.FindStringSubmatch(hstsLower)

	if len(matches) < 2 {
		issues = append(issues, SecurityIssue{
			Type:        "header",
			Title:       "HSTS missing max-age",
			Description: "Strict-Transport-Security lacks max-age directive",
			Severity:    "high",
			Evidence:    []string{fmt.Sprintf("HSTS: %s", hsts)},
			Impact:      "HSTS not properly configured",
			Remediation: "Add max-age directive to HSTS header",
			Verified:    true,
		})
	} else {
		maxAge := matches[1]
		if maxAge == "0" {
			issues = append(issues, SecurityIssue{
				Type:        "header",
				Title:       "HSTS disabled",
				Description: "HSTS max-age set to 0",
				Severity:    "high",
				Evidence:    []string{"max-age=0"},
				Impact:      "HSTS protection is disabled",
				Remediation: "Set appropriate max-age value (e.g., 31536000)",
				Verified:    true,
			})
		} else if len(maxAge) < 7 { // Less than 1000000 seconds (~11 days)
			issues = append(issues, SecurityIssue{
				Type:        "header",
				Title:       "HSTS max-age too short",
				Description: fmt.Sprintf("HSTS max-age is only %s seconds", maxAge),
				Severity:    "medium",
				Evidence:    []string{fmt.Sprintf("max-age=%s", maxAge)},
				Impact:      "Short HSTS duration provides limited protection",
				Remediation: "Increase max-age to at least 31536000 (1 year)",
				Verified:    true,
			})
		}
	}

	// Check for includeSubDomains
	if !strings.Contains(hstsLower, "includesubdomains") {
		issues = append(issues, SecurityIssue{
			Type:        "header",
			Title:       "HSTS without includeSubDomains",
			Description: "HSTS doesn't protect subdomains",
			Severity:    "low",
			Evidence:    []string{"includeSubDomains not present"},
			Impact:      "Subdomains not protected by HSTS",
			Remediation: "Add includeSubDomains to HSTS header",
			Verified:    true,
		})
	}

	// Check for preload
	if !strings.Contains(hstsLower, "preload") {
		// This is informational, not a vulnerability
		issues = append(issues, SecurityIssue{
			Type:        "header",
			Title:       "HSTS not preloaded",
			Description: "Site not eligible for HSTS preload list",
			Severity:    "low",
			Evidence:    []string{"preload directive not present"},
			Impact:      "First visit not protected by HSTS",
			Remediation: "Consider adding preload directive and submitting to preload list",
			Verified:    true,
		})
	}

	return issues
}

// getHeaderValue gets a header value (case-insensitive)
func (d *SecurityHeadersDetector) getHeaderValue(headers http.Header, name string) string {
	for key, values := range headers {
		if strings.EqualFold(key, name) && len(values) > 0 {
			return values[0]
		}
	}
	return ""
}

// containsVersionInfo checks if a string contains version information
func (d *SecurityHeadersDetector) containsVersionInfo(s string) bool {
	// Check for common version patterns
	versionPattern := regexp.MustCompile(`\d+\.\d+`)
	return versionPattern.MatchString(s)
}