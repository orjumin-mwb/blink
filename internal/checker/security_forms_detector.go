package checker

import (
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strings"
)

// SecurityFormsDetector analyzes forms for security vulnerabilities
type SecurityFormsDetector struct {
	patterns map[string]*regexp.Regexp
}

// NewSecurityFormsDetector creates a new forms security detector
func NewSecurityFormsDetector() *SecurityFormsDetector {
	detector := &SecurityFormsDetector{
		patterns: make(map[string]*regexp.Regexp),
	}
	detector.initPatterns()
	return detector
}

// initPatterns initializes regex patterns for form detection
func (d *SecurityFormsDetector) initPatterns() {
	// Form patterns
	d.patterns["form"] = regexp.MustCompile(`(?i)<form[^>]*>`)
	d.patterns["formAction"] = regexp.MustCompile(`(?i)action\s*=\s*["']([^"']+)["']`)
	d.patterns["formMethod"] = regexp.MustCompile(`(?i)method\s*=\s*["']([^"']+)["']`)

	// Input patterns
	d.patterns["passwordField"] = regexp.MustCompile(`(?i)<input[^>]*type\s*=\s*["']password["'][^>]*>`)
	d.patterns["inputName"] = regexp.MustCompile(`(?i)name\s*=\s*["']([^"']+)["']`)
	d.patterns["autocomplete"] = regexp.MustCompile(`(?i)autocomplete\s*=\s*["']([^"']+)["']`)

	// Sensitive field patterns
	d.patterns["creditCard"] = regexp.MustCompile(`(?i)(credit[_-]?card|card[_-]?number|ccnum|cc[_-]?num)`)
	d.patterns["ssn"] = regexp.MustCompile(`(?i)(ssn|social[_-]?security)`)
	d.patterns["cvv"] = regexp.MustCompile(`(?i)(cvv|cvc|security[_-]?code)`)

	// CSRF token patterns
	d.patterns["csrfToken"] = regexp.MustCompile(`(?i)(csrf[_-]?token|authenticity[_-]?token|xsrf[_-]?token|_token)`)
	d.patterns["hiddenInput"] = regexp.MustCompile(`(?i)<input[^>]*type\s*=\s*["']hidden["'][^>]*>`)
}

// Detect analyzes HTML for form security issues
func (d *SecurityFormsDetector) Detect(html string, pageURL string, headers http.Header) []SecurityIssue {
	issues := []SecurityIssue{}

	// Parse the page URL
	parsedURL, err := url.Parse(pageURL)
	if err != nil {
		return issues
	}

	// Find all forms
	forms := d.extractForms(html)

	for _, form := range forms {
		// Check for password fields over HTTP
		if strings.HasPrefix(pageURL, "http://") && form.HasPasswordField {
			issues = append(issues, SecurityIssue{
				Type:        "form",
				Title:       "Password transmitted over HTTP",
				Description: fmt.Sprintf("Form at %s contains password field but uses HTTP protocol", pageURL),
				Severity:    "critical",
				Evidence:    []string{form.Action, "Password field found in form"},
				Impact:      "Credentials can be intercepted by attackers on the network",
				Remediation: "Use HTTPS for all pages containing password fields",
				Verified:    true,
			})
		}

		// Check for GET method with password fields
		if strings.ToUpper(form.Method) == "GET" && form.HasPasswordField {
			issues = append(issues, SecurityIssue{
				Type:        "form",
				Title:       "Password transmitted via GET method",
				Description: "Form uses GET method for password submission, exposing credentials in URL",
				Severity:    "critical",
				Evidence:    []string{fmt.Sprintf("Form action: %s", form.Action), "Method: GET"},
				Impact:      "Passwords will be visible in browser history, server logs, and referrer headers",
				Remediation: "Always use POST method for forms containing passwords",
				Verified:    true,
			})
		}

		// Check for cross-domain form posts
		if form.Action != "" && !strings.HasPrefix(form.Action, "/") && !strings.HasPrefix(form.Action, "#") {
			actionURL, err := url.Parse(form.Action)
			if err == nil && actionURL.Host != "" && actionURL.Host != parsedURL.Host {
				severity := "medium"
				if form.HasPasswordField || form.HasSensitiveField {
					severity = "high"
				}

				issues = append(issues, SecurityIssue{
					Type:        "form",
					Title:       "Cross-domain form submission",
					Description: fmt.Sprintf("Form submits to different domain: %s", actionURL.Host),
					Severity:    severity,
					Evidence:    []string{fmt.Sprintf("Form action: %s", form.Action), fmt.Sprintf("Page domain: %s", parsedURL.Host)},
					Impact:      "Potential CSRF vulnerability or data leakage to third-party",
					Remediation: "Ensure forms only submit to trusted domains and implement CSRF tokens",
					Verified:    true,
				})
			}
		}

		// Check for missing CSRF protection
		if form.Method == "POST" && !form.HasCSRFToken && !strings.Contains(pageURL, "login") && !strings.Contains(pageURL, "signin") {
			issues = append(issues, SecurityIssue{
				Type:        "form",
				Title:       "Missing CSRF protection",
				Description: "POST form lacks CSRF token protection",
				Severity:    "medium",
				Evidence:    []string{fmt.Sprintf("Form action: %s", form.Action), "No CSRF token detected"},
				Impact:      "Form may be vulnerable to Cross-Site Request Forgery attacks",
				Remediation: "Implement CSRF tokens for all state-changing forms",
				Verified:    false,
			})
		}

		// Check for autocomplete on sensitive fields
		if form.HasPasswordField && form.AutocompleteEnabled {
			issues = append(issues, SecurityIssue{
				Type:        "form",
				Title:       "Autocomplete enabled on password field",
				Description: "Password field allows browser autocomplete",
				Severity:    "low",
				Evidence:    []string{"autocomplete not set to 'off' or 'new-password'"},
				Impact:      "Passwords may be stored in browser autocomplete cache",
				Remediation: "Set autocomplete='new-password' or 'off' for password fields",
				Verified:    true,
			})
		}

		// Check for sensitive data in hidden fields
		if len(form.HiddenFields) > 0 {
			for _, field := range form.HiddenFields {
				if d.isSensitiveFieldName(field.Name) || d.containsSensitiveValue(field.Value) {
					issues = append(issues, SecurityIssue{
						Type:        "form",
						Title:       "Sensitive data in hidden field",
						Description: fmt.Sprintf("Hidden field '%s' may contain sensitive data", field.Name),
						Severity:    "medium",
						Evidence:    []string{fmt.Sprintf("Field name: %s", field.Name)},
						Impact:      "Sensitive data exposed in HTML source",
						Remediation: "Avoid storing sensitive data in hidden form fields",
						Verified:    true,
					})
				}
			}
		}
	}

	// Check for forms submitting to HTTP from HTTPS
	if strings.HasPrefix(pageURL, "https://") {
		for _, form := range forms {
			if strings.HasPrefix(form.Action, "http://") && !strings.HasPrefix(form.Action, "https://") {
				issues = append(issues, SecurityIssue{
					Type:        "form",
					Title:       "Mixed content: HTTPS to HTTP form submission",
					Description: "Secure page contains form submitting to insecure HTTP endpoint",
					Severity:    "high",
					Evidence:    []string{fmt.Sprintf("Form action: %s", form.Action)},
					Impact:      "Form data will be transmitted without encryption",
					Remediation: "Ensure all form actions use HTTPS on secure pages",
					Verified:    true,
				})
			}
		}
	}

	return issues
}

// FormInfo holds information about a detected form
type FormInfo struct {
	Action              string
	Method              string
	HasPasswordField    bool
	HasSensitiveField   bool
	HasCSRFToken        bool
	AutocompleteEnabled bool
	HiddenFields        []HiddenField
}

// HiddenField represents a hidden input field
type HiddenField struct {
	Name  string
	Value string
}

// extractForms finds and analyzes all forms in HTML
func (d *SecurityFormsDetector) extractForms(html string) []FormInfo {
	forms := []FormInfo{}

	// Find all form tags
	formMatches := d.patterns["form"].FindAllStringIndex(html, -1)

	for _, match := range formMatches {
		// Find the closing form tag
		endIndex := strings.Index(html[match[1]:], "</form>")
		if endIndex == -1 {
			continue
		}

		formHTML := html[match[0] : match[1]+endIndex]

		form := FormInfo{
			Method:              "GET", // Default method
			AutocompleteEnabled: true,  // Default is enabled
		}

		// Extract action
		if actionMatch := d.patterns["formAction"].FindStringSubmatch(formHTML); len(actionMatch) > 1 {
			form.Action = actionMatch[1]
		}

		// Extract method
		if methodMatch := d.patterns["formMethod"].FindStringSubmatch(formHTML); len(methodMatch) > 1 {
			form.Method = strings.ToUpper(methodMatch[1])
		}

		// Check for password fields
		if d.patterns["passwordField"].MatchString(formHTML) {
			form.HasPasswordField = true

			// Check autocomplete on password field
			passwordFields := d.patterns["passwordField"].FindAllString(formHTML, -1)
			for _, field := range passwordFields {
				if autoMatch := d.patterns["autocomplete"].FindStringSubmatch(field); len(autoMatch) > 1 {
					autocompleteValue := strings.ToLower(autoMatch[1])
					if autocompleteValue == "off" || autocompleteValue == "new-password" {
						form.AutocompleteEnabled = false
					}
				}
			}
		}

		// Check for sensitive fields
		if d.patterns["creditCard"].MatchString(formHTML) ||
		   d.patterns["ssn"].MatchString(formHTML) ||
		   d.patterns["cvv"].MatchString(formHTML) {
			form.HasSensitiveField = true
		}

		// Check for CSRF tokens
		if d.patterns["csrfToken"].MatchString(formHTML) {
			form.HasCSRFToken = true
		}

		// Extract hidden fields
		hiddenMatches := d.patterns["hiddenInput"].FindAllString(formHTML, -1)
		for _, hiddenField := range hiddenMatches {
			field := HiddenField{}

			if nameMatch := d.patterns["inputName"].FindStringSubmatch(hiddenField); len(nameMatch) > 1 {
				field.Name = nameMatch[1]
			}

			// Extract value (simplified - doesn't handle all cases)
			valuePattern := regexp.MustCompile(`(?i)value\s*=\s*["']([^"']+)["']`)
			if valueMatch := valuePattern.FindStringSubmatch(hiddenField); len(valueMatch) > 1 {
				field.Value = valueMatch[1]
			}

			if field.Name != "" {
				form.HiddenFields = append(form.HiddenFields, field)
			}
		}

		forms = append(forms, form)
	}

	return forms
}

// isSensitiveFieldName checks if a field name indicates sensitive data
func (d *SecurityFormsDetector) isSensitiveFieldName(name string) bool {
	sensitivePatterns := []string{
		"password", "passwd", "pwd",
		"secret", "token", "api",
		"credit", "card", "cvv", "cvc",
		"ssn", "social",
		"account", "pin",
	}

	nameLower := strings.ToLower(name)
	for _, pattern := range sensitivePatterns {
		if strings.Contains(nameLower, pattern) {
			return true
		}
	}

	return false
}

// containsSensitiveValue checks if a value might contain sensitive data
func (d *SecurityFormsDetector) containsSensitiveValue(value string) bool {
	// Check for patterns that look like tokens, API keys, etc.
	if len(value) > 20 && regexp.MustCompile(`^[a-zA-Z0-9_\-]+$`).MatchString(value) {
		return true
	}

	// Check for credit card patterns (simplified)
	if regexp.MustCompile(`^\d{13,19}$`).MatchString(strings.ReplaceAll(value, " ", "")) {
		return true
	}

	return false
}