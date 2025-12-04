package checker

import (
	"fmt"
	"net/http"
	"regexp"
	"strings"
)

// SecurityCookieDetector analyzes cookies for security vulnerabilities
type SecurityCookieDetector struct {
	sessionPatterns   []string
	trackingPatterns  []string
	javascriptPattern *regexp.Regexp
}

// NewSecurityCookieDetector creates a new cookie security detector
func NewSecurityCookieDetector() *SecurityCookieDetector {
	return &SecurityCookieDetector{
		sessionPatterns: []string{
			"session", "sess", "sid", "jsessionid", "phpsessid",
			"asp.net_sessionid", "aspsessionid", "token", "auth",
			"authorization", "jwt", "access_token", "refresh_token",
		},
		trackingPatterns: []string{
			"_ga", "_gid", "_gat", "_utm", "fbp", "fbc",
			"_hjid", "_hjtld", "_clck", "_clsk",
			"optimizely", "segment", "mixpanel", "amplitude",
		},
		javascriptPattern: regexp.MustCompile(`(?i)document\.cookie`),
	}
}

// Detect analyzes cookies and JavaScript for cookie security issues
func (d *SecurityCookieDetector) Detect(html string, pageURL string, headers http.Header, cookies []*http.Cookie) []SecurityIssue {
	issues := []SecurityIssue{}

	isHTTPS := strings.HasPrefix(pageURL, "https://")

	// Analyze Set-Cookie headers
	setCookieHeaders := headers["Set-Cookie"]
	for _, cookieHeader := range setCookieHeaders {
		cookieIssues := d.analyzeCookieHeader(cookieHeader, isHTTPS)
		issues = append(issues, cookieIssues...)
	}

	// Analyze cookies from Cookie header or response
	for _, cookie := range cookies {
		cookieIssues := d.analyzeCookie(cookie, isHTTPS)
		issues = append(issues, cookieIssues...)
	}

	// Check for JavaScript cookie access
	if d.javascriptPattern.MatchString(html) {
		hasHttpOnlyCookies := false
		for _, cookie := range cookies {
			if d.isSessionCookie(cookie.Name) && !cookie.HttpOnly {
				hasHttpOnlyCookies = true
				break
			}
		}

		if hasHttpOnlyCookies {
			issues = append(issues, SecurityIssue{
				Type:        "cookie",
				Title:       "Session cookies accessible to JavaScript",
				Description: "Session cookies lack HttpOnly flag and page contains JavaScript cookie access",
				Severity:    "high",
				Evidence:    []string{"document.cookie usage detected", "Session cookies without HttpOnly"},
				Impact:      "Session cookies can be stolen via XSS attacks",
				Remediation: "Set HttpOnly flag on all session cookies",
				Verified:    true,
			})
		}
	}

	// Check for third-party tracking cookies
	trackingCookies := d.findTrackingCookies(cookies)
	if len(trackingCookies) > 0 {
		issues = append(issues, SecurityIssue{
			Type:        "cookie",
			Title:       "Third-party tracking cookies detected",
			Description: fmt.Sprintf("Found %d tracking cookies that may compromise user privacy", len(trackingCookies)),
			Severity:    "low",
			Evidence:    trackingCookies,
			Impact:      "User behavior may be tracked across websites",
			Remediation: "Review and minimize use of third-party tracking cookies",
			Verified:    true,
		})
	}

	return issues
}

// analyzeCookieHeader parses and analyzes a Set-Cookie header
func (d *SecurityCookieDetector) analyzeCookieHeader(cookieHeader string, isHTTPS bool) []SecurityIssue {
	issues := []SecurityIssue{}

	// Parse cookie attributes
	attrs := d.parseCookieAttributes(cookieHeader)

	// Get cookie name
	parts := strings.Split(cookieHeader, ";")
	if len(parts) == 0 {
		return issues
	}

	nameValue := strings.TrimSpace(parts[0])
	cookieName := ""
	if idx := strings.Index(nameValue, "="); idx > 0 {
		cookieName = nameValue[:idx]
	}

	isSession := d.isSessionCookie(cookieName)

	// Check Secure flag on HTTPS sites
	if isHTTPS && !attrs.Secure {
		severity := "medium"
		title := "Cookie missing Secure flag"
		if isSession {
			severity = "high"
			title = "Session cookie missing Secure flag"
		}

		issues = append(issues, SecurityIssue{
			Type:        "cookie",
			Title:       title,
			Description: fmt.Sprintf("Cookie '%s' lacks Secure flag on HTTPS site", cookieName),
			Severity:    severity,
			Evidence:    []string{fmt.Sprintf("Cookie: %s", cookieName)},
			Impact:      "Cookie may be transmitted over insecure HTTP connections",
			Remediation: "Set Secure flag for all cookies on HTTPS sites",
			Verified:    true,
		})
	}

	// Check HttpOnly flag for session cookies
	if isSession && !attrs.HttpOnly {
		issues = append(issues, SecurityIssue{
			Type:        "cookie",
			Title:       "Session cookie missing HttpOnly flag",
			Description: fmt.Sprintf("Session cookie '%s' is accessible to JavaScript", cookieName),
			Severity:    "high",
			Evidence:    []string{fmt.Sprintf("Cookie: %s", cookieName)},
			Impact:      "Cookie can be stolen via XSS attacks",
			Remediation: "Set HttpOnly flag for all session cookies",
			Verified:    true,
		})
	}

	// Check SameSite attribute
	if attrs.SameSite == "" {
		severity := "low"
		if isSession {
			severity = "medium"
		}

		issues = append(issues, SecurityIssue{
			Type:        "cookie",
			Title:       "Cookie missing SameSite attribute",
			Description: fmt.Sprintf("Cookie '%s' lacks SameSite attribute", cookieName),
			Severity:    severity,
			Evidence:    []string{fmt.Sprintf("Cookie: %s", cookieName)},
			Impact:      "Cookie may be sent with cross-site requests (CSRF risk)",
			Remediation: "Set SameSite=Lax or SameSite=Strict for cookies",
			Verified:    true,
		})
	} else if strings.ToLower(attrs.SameSite) == "none" && !attrs.Secure {
		issues = append(issues, SecurityIssue{
			Type:        "cookie",
			Title:       "SameSite=None without Secure flag",
			Description: fmt.Sprintf("Cookie '%s' has SameSite=None but lacks Secure flag", cookieName),
			Severity:    "high",
			Evidence:    []string{fmt.Sprintf("Cookie: %s", cookieName), "SameSite=None"},
			Impact:      "Cookie configuration is invalid and may not work as expected",
			Remediation: "SameSite=None requires Secure flag to be set",
			Verified:    true,
		})
	}

	// Check for cookies set over HTTP on HTTPS page
	if !isHTTPS && isSession {
		issues = append(issues, SecurityIssue{
			Type:        "cookie",
			Title:       "Session cookie set over HTTP",
			Description: fmt.Sprintf("Session cookie '%s' is being set over insecure HTTP", cookieName),
			Severity:    "critical",
			Evidence:    []string{fmt.Sprintf("Cookie: %s", cookieName), "Protocol: HTTP"},
			Impact:      "Session cookies transmitted without encryption",
			Remediation: "Always use HTTPS for setting session cookies",
			Verified:    true,
		})
	}

	// Check for weak SameSite on auth endpoints
	if isSession && strings.Contains(strings.ToLower(cookieName), "auth") &&
	   strings.ToLower(attrs.SameSite) != "strict" {
		issues = append(issues, SecurityIssue{
			Type:        "cookie",
			Title:       "Authentication cookie with weak SameSite",
			Description: fmt.Sprintf("Authentication cookie '%s' should use SameSite=Strict", cookieName),
			Severity:    "medium",
			Evidence:    []string{fmt.Sprintf("Cookie: %s", cookieName), fmt.Sprintf("SameSite: %s", attrs.SameSite)},
			Impact:      "Authentication cookie may be sent with cross-site requests",
			Remediation: "Use SameSite=Strict for authentication cookies",
			Verified:    true,
		})
	}

	return issues
}

// analyzeCookie analyzes an http.Cookie struct
func (d *SecurityCookieDetector) analyzeCookie(cookie *http.Cookie, isHTTPS bool) []SecurityIssue {
	issues := []SecurityIssue{}

	isSession := d.isSessionCookie(cookie.Name)

	// Check Secure flag
	if isHTTPS && !cookie.Secure {
		severity := "medium"
		if isSession {
			severity = "high"
		}

		issues = append(issues, SecurityIssue{
			Type:        "cookie",
			Title:       "Cookie missing Secure flag",
			Description: fmt.Sprintf("Cookie '%s' lacks Secure flag on HTTPS site", cookie.Name),
			Severity:    severity,
			Evidence:    []string{fmt.Sprintf("Cookie: %s", cookie.Name)},
			Impact:      "Cookie may be transmitted over insecure connections",
			Remediation: "Set Secure flag for all cookies on HTTPS sites",
			Verified:    true,
		})
	}

	// Check HttpOnly flag
	if isSession && !cookie.HttpOnly {
		issues = append(issues, SecurityIssue{
			Type:        "cookie",
			Title:       "Session cookie accessible to JavaScript",
			Description: fmt.Sprintf("Session cookie '%s' lacks HttpOnly flag", cookie.Name),
			Severity:    "high",
			Evidence:    []string{fmt.Sprintf("Cookie: %s", cookie.Name)},
			Impact:      "Cookie can be stolen via XSS attacks",
			Remediation: "Set HttpOnly flag for session cookies",
			Verified:    true,
		})
	}

	// Check SameSite
	sameSiteStr := ""
	switch cookie.SameSite {
	case http.SameSiteNoneMode:
		sameSiteStr = "None"
	case http.SameSiteLaxMode:
		sameSiteStr = "Lax"
	case http.SameSiteStrictMode:
		sameSiteStr = "Strict"
	default:
		sameSiteStr = ""
	}

	if sameSiteStr == "" {
		severity := "low"
		if isSession {
			severity = "medium"
		}

		issues = append(issues, SecurityIssue{
			Type:        "cookie",
			Title:       "Cookie missing SameSite attribute",
			Description: fmt.Sprintf("Cookie '%s' lacks SameSite attribute", cookie.Name),
			Severity:    severity,
			Evidence:    []string{fmt.Sprintf("Cookie: %s", cookie.Name)},
			Impact:      "Cookie may be sent with cross-site requests",
			Remediation: "Set appropriate SameSite attribute",
			Verified:    true,
		})
	}

	return issues
}

// CookieAttributes holds parsed cookie attributes
type CookieAttributes struct {
	Secure   bool
	HttpOnly bool
	SameSite string
	Domain   string
	Path     string
}

// parseCookieAttributes extracts attributes from a Set-Cookie header
func (d *SecurityCookieDetector) parseCookieAttributes(cookieHeader string) CookieAttributes {
	attrs := CookieAttributes{}

	parts := strings.Split(cookieHeader, ";")
	for i, part := range parts {
		if i == 0 {
			continue // Skip name=value part
		}

		part = strings.TrimSpace(strings.ToLower(part))

		if part == "secure" {
			attrs.Secure = true
		} else if part == "httponly" {
			attrs.HttpOnly = true
		} else if strings.HasPrefix(part, "samesite=") {
			attrs.SameSite = strings.TrimPrefix(part, "samesite=")
		} else if strings.HasPrefix(part, "domain=") {
			attrs.Domain = strings.TrimPrefix(part, "domain=")
		} else if strings.HasPrefix(part, "path=") {
			attrs.Path = strings.TrimPrefix(part, "path=")
		}
	}

	return attrs
}

// isSessionCookie checks if a cookie name indicates a session cookie
func (d *SecurityCookieDetector) isSessionCookie(name string) bool {
	nameLower := strings.ToLower(name)
	for _, pattern := range d.sessionPatterns {
		if strings.Contains(nameLower, pattern) {
			return true
		}
	}
	return false
}

// findTrackingCookies identifies tracking cookies
func (d *SecurityCookieDetector) findTrackingCookies(cookies []*http.Cookie) []string {
	tracking := []string{}

	for _, cookie := range cookies {
		nameLower := strings.ToLower(cookie.Name)
		for _, pattern := range d.trackingPatterns {
			if strings.Contains(nameLower, pattern) {
				tracking = append(tracking, cookie.Name)
				break
			}
		}
	}

	return tracking
}