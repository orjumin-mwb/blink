package checker

import (
	"fmt"
	"regexp"
	"strings"
)

// SecurityDataExposureDetector detects sensitive data exposure vulnerabilities
type SecurityDataExposureDetector struct {
	apiKeyPatterns    map[string]*regexp.Regexp
	credentialPatterns map[string]*regexp.Regexp
	piiPatterns       map[string]*regexp.Regexp
	debugPatterns     []*regexp.Regexp
}

// NewSecurityDataExposureDetector creates a new data exposure detector
func NewSecurityDataExposureDetector() *SecurityDataExposureDetector {
	return &SecurityDataExposureDetector{
		apiKeyPatterns: map[string]*regexp.Regexp{
			"AWS Access Key":       regexp.MustCompile(`(?i)AKIA[0-9A-Z]{16}`),
			"AWS Secret Key":       regexp.MustCompile(`(?i)aws[_-]?secret[_-]?(?:access[_-]?)?key['"]\s*[:=]\s*['"][0-9a-zA-Z/+=]{40}['"]`),
			"Google API Key":       regexp.MustCompile(`(?i)AIza[0-9A-Za-z\-_]{35}`),
			"Google OAuth":         regexp.MustCompile(`(?i)[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com`),
			"GitHub Token":         regexp.MustCompile(`(?i)(?:github|gh)[_-]?(?:token|pat)['"]\s*[:=]\s*['"](?:ghp_|gho_|ghu_|ghs_|ghr_)[a-zA-Z0-9]{36,}['"]`),
			"Slack Token":          regexp.MustCompile(`(?i)xox[baprs]-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24,}`),
			"Stripe Key":           regexp.MustCompile(`(?i)(?:sk|pk)_(?:test|live)_[0-9a-zA-Z]{24,}`),
			"Twilio API Key":       regexp.MustCompile(`(?i)(?:twilio|SK)['":\s]+SK[a-z0-9]{32}`),
			"PayPal/Braintree":     regexp.MustCompile(`(?i)access_token\$production\$[a-z0-9]{16}\$[a-f0-9]{32}`),
			"Square Access Token":  regexp.MustCompile(`(?i)sq0atp-[0-9A-Za-z\-_]{22}`),
			"Square OAuth Secret":  regexp.MustCompile(`(?i)sq0csp-[0-9A-Za-z\-_]{43}`),
			"Firebase URL":         regexp.MustCompile(`(?i)[a-z0-9-]+\.firebaseio\.com`),
			"RSA Private Key":      regexp.MustCompile(`(?i)-----BEGIN (?:RSA )?PRIVATE KEY-----`),
			"SSH Private Key":      regexp.MustCompile(`(?i)-----BEGIN OPENSSH PRIVATE KEY-----`),
			"PGP Private Key":      regexp.MustCompile(`(?i)-----BEGIN PGP PRIVATE KEY BLOCK-----`),
			"Generic API Key":      regexp.MustCompile(`(?i)(?:api[_-]?key|apikey|api[_-]?secret)['"]\s*[:=]\s*['"][a-zA-Z0-9_\-]{20,}['"]`),
			"Generic Secret":       regexp.MustCompile(`(?i)(?:secret|password|passwd|pwd)['"]\s*[:=]\s*['"][^'"]{8,}['"]`),
			"JWT Token":            regexp.MustCompile(`eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}`),
			"Bearer Token":         regexp.MustCompile(`(?i)bearer\s+[a-zA-Z0-9_\-\.=]{20,}`),
		},
		credentialPatterns: map[string]*regexp.Regexp{
			"Username/Password": regexp.MustCompile(`(?i)(?:username|user|login)['"]\s*[:=]\s*['"][^'"]+['"][\s\S]{0,50}(?:password|passwd|pwd)['"]\s*[:=]\s*['"][^'"]+['"]`),
			"Database URL":      regexp.MustCompile(`(?i)(?:postgres|mysql|mongodb|redis)://[^:]+:[^@]+@[^/\s]+`),
			"JDBC Connection":   regexp.MustCompile(`(?i)jdbc:[^:]+://[^:]+:[^@]+@`),
			"FTP Credentials":   regexp.MustCompile(`(?i)ftp://[^:]+:[^@]+@`),
		},
		piiPatterns: map[string]*regexp.Regexp{
			"Email Address":     regexp.MustCompile(`[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}`),
			"Credit Card":       regexp.MustCompile(`\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|3(?:0[0-5]|[68][0-9])[0-9]{11}|6(?:011|5[0-9]{2})[0-9]{12})\b`),
			"SSN":               regexp.MustCompile(`\b\d{3}-\d{2}-\d{4}\b`),
			"Phone Number":      regexp.MustCompile(`\b(?:\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b`),
			"IP Address":        regexp.MustCompile(`\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b`),
			"IPv6 Address":      regexp.MustCompile(`(?i)\b(?:[0-9a-f]{1,4}:){7}[0-9a-f]{1,4}\b`),
		},
		debugPatterns: []*regexp.Regexp{
			regexp.MustCompile(`(?i)console\.(?:log|debug|info|warn|error)\s*\(`),
			regexp.MustCompile(`(?i)debugger\s*;`),
			regexp.MustCompile(`(?i)<!--\s*DEBUG|TODO|FIXME|HACK|XXX`),
			regexp.MustCompile(`(?i)printStackTrace|print_r|var_dump|dd\(`),
		},
	}
}

// Detect analyzes content for sensitive data exposure
func (d *SecurityDataExposureDetector) Detect(html string, scripts []string, externalScripts []string) []SecurityIssue {
	issues := []SecurityIssue{}

	// Combine all content for analysis
	allContent := html
	for _, script := range scripts {
		allContent += "\n" + script
	}

	// Check for API keys and tokens
	issues = append(issues, d.detectAPIKeys(allContent)...)

	// Check for hardcoded credentials
	issues = append(issues, d.detectCredentials(allContent)...)

	// Check for PII exposure
	issues = append(issues, d.detectPII(allContent)...)

	// Check for debug information
	issues = append(issues, d.detectDebugInfo(allContent)...)

	// Check for internal paths/URLs
	issues = append(issues, d.detectInternalPaths(allContent)...)

	// Check for comments with sensitive information
	issues = append(issues, d.detectSensitiveComments(allContent)...)

	// Check for environment variables exposure
	issues = append(issues, d.detectEnvironmentVariables(allContent)...)

	// Check for stack traces
	issues = append(issues, d.detectStackTraces(allContent)...)

	// Check external scripts for suspicious URLs
	issues = append(issues, d.detectSuspiciousScripts(externalScripts)...)

	return issues
}

// detectAPIKeys finds exposed API keys and tokens
func (d *SecurityDataExposureDetector) detectAPIKeys(content string) []SecurityIssue {
	issues := []SecurityIssue{}
	foundKeys := make(map[string][]string)

	for keyType, pattern := range d.apiKeyPatterns {
		matches := pattern.FindAllString(content, -1)
		if len(matches) > 0 {
			// Filter out false positives
			validMatches := []string{}
			for _, match := range matches {
				// Skip if it's in a URL query parameter (contains ??, =, &)
				if strings.Contains(match, "??") || strings.Count(match, "=") > 2 {
					continue
				}
				// Skip if it looks like base64 in a URL (very long, contains URL characters)
				if len(match) > 100 && (strings.Contains(match, "/") || strings.Contains(match, "+")) {
					continue
				}
				validMatches = append(validMatches, match)
			}

			if len(validMatches) > 0 {
				// Mask the keys for evidence
				maskedMatches := []string{}
				for _, match := range validMatches {
					if len(match) > 10 {
						maskedMatches = append(maskedMatches, match[:6]+"..."+match[len(match)-4:])
					} else {
						maskedMatches = append(maskedMatches, match[:3]+"...")
					}
				}
				foundKeys[keyType] = maskedMatches
			}
		}
	}

	for keyType, matches := range foundKeys {
		severity := "critical"
		if keyType == "Generic Secret" || keyType == "Firebase URL" {
			severity = "high"
		}

		issues = append(issues, SecurityIssue{
			Type:        "data-exposure",
			Title:       fmt.Sprintf("%s exposed in code", keyType),
			Description: fmt.Sprintf("Found %d instances of %s in JavaScript/HTML", len(matches), keyType),
			Severity:    severity,
			Evidence:    matches,
			Impact:      "API keys can be stolen and misused",
			Remediation: "Move API keys to server-side environment variables",
			Verified:    true,
		})
	}

	return issues
}

// detectCredentials finds hardcoded credentials
func (d *SecurityDataExposureDetector) detectCredentials(content string) []SecurityIssue {
	issues := []SecurityIssue{}

	for credType, pattern := range d.credentialPatterns {
		if pattern.MatchString(content) {
			issues = append(issues, SecurityIssue{
				Type:        "credentials",
				Title:       fmt.Sprintf("%s exposed", credType),
				Description: fmt.Sprintf("Hardcoded %s found in code", credType),
				Severity:    "critical",
				Evidence:    []string{credType + " detected"},
				Impact:      "Full system compromise possible",
				Remediation: "Remove hardcoded credentials, use environment variables",
				Verified:    true,
			})
		}
	}

	// Check for default/common passwords
	commonPasswords := []string{"password", "admin", "123456", "default", "root", "test"}
	for _, pwd := range commonPasswords {
		pwdPattern := regexp.MustCompile(`(?i)(?:password|passwd|pwd)['"]\s*[:=]\s*['"]` + pwd + `['"]`)
		if pwdPattern.MatchString(content) {
			issues = append(issues, SecurityIssue{
				Type:        "credentials",
				Title:       "Default/weak password detected",
				Description: fmt.Sprintf("Default password '%s' found in code", pwd),
				Severity:    "critical",
				Evidence:    []string{fmt.Sprintf("Password: %s", pwd)},
				Impact:      "Easy to guess credentials leading to unauthorized access",
				Remediation: "Use strong, unique passwords and environment variables",
				Verified:    true,
			})
			break
		}
	}

	return issues
}

// detectPII finds personally identifiable information
func (d *SecurityDataExposureDetector) detectPII(content string) []SecurityIssue {
	issues := []SecurityIssue{}
	foundPII := make(map[string]int)

	for piiType, pattern := range d.piiPatterns {
		matches := pattern.FindAllString(content, -1)
		if len(matches) > 0 {
			// Filter out common false positives
			validMatches := d.filterPIIFalsePositives(piiType, matches)
			if len(validMatches) > 0 {
				foundPII[piiType] = len(validMatches)
			}
		}
	}

	if emailCount, exists := foundPII["Email Address"]; exists && emailCount > 5 {
		issues = append(issues, SecurityIssue{
			Type:        "pii",
			Title:       "Multiple email addresses exposed",
			Description: fmt.Sprintf("Found %d email addresses in HTML/JavaScript", emailCount),
			Severity:    "medium",
			Evidence:    []string{fmt.Sprintf("%d email addresses", emailCount)},
			Impact:      "Email addresses can be harvested for spam",
			Remediation: "Obfuscate email addresses or use contact forms",
			Verified:    true,
		})
	}

	if ccCount, exists := foundPII["Credit Card"]; exists {
		issues = append(issues, SecurityIssue{
			Type:        "pii",
			Title:       "Credit card numbers detected",
			Description: fmt.Sprintf("Found %d potential credit card numbers", ccCount),
			Severity:    "critical",
			Evidence:    []string{fmt.Sprintf("%d credit card patterns", ccCount)},
			Impact:      "PCI DSS violation, financial fraud risk",
			Remediation: "Never expose credit card numbers in client-side code",
			Verified:    false,
		})
	}

	if ssnCount, exists := foundPII["SSN"]; exists {
		issues = append(issues, SecurityIssue{
			Type:        "pii",
			Title:       "Social Security Numbers detected",
			Description: fmt.Sprintf("Found %d potential SSN patterns", ssnCount),
			Severity:    "critical",
			Evidence:    []string{fmt.Sprintf("%d SSN patterns", ssnCount)},
			Impact:      "Identity theft, severe privacy violation",
			Remediation: "Never expose SSNs in client-side code",
			Verified:    false,
		})
	}

	if ipCount, exists := foundPII["IP Address"]; exists && ipCount > 3 {
		issues = append(issues, SecurityIssue{
			Type:        "info-disclosure",
			Title:       "Internal IP addresses exposed",
			Description: fmt.Sprintf("Found %d IP addresses in code", ipCount),
			Severity:    "low",
			Evidence:    []string{fmt.Sprintf("%d IP addresses", ipCount)},
			Impact:      "Internal network topology disclosure",
			Remediation: "Remove internal IP addresses from client-side code",
			Verified:    false,
		})
	}

	return issues
}

// filterPIIFalsePositives removes common false positives
func (d *SecurityDataExposureDetector) filterPIIFalsePositives(piiType string, matches []string) []string {
	valid := []string{}

	for _, match := range matches {
		switch piiType {
		case "Email Address":
			// Filter out common non-email patterns
			if !strings.Contains(match, "example.com") &&
			   !strings.Contains(match, "test.com") &&
			   !strings.Contains(match, "localhost") &&
			   !strings.Contains(match, "0.0.0.0") {
				valid = append(valid, match)
			}
		case "IP Address":
			// Filter out common non-private IPs
			if !strings.HasPrefix(match, "0.0.0.") &&
			   !strings.HasPrefix(match, "127.0.0.") &&
			   match != "255.255.255.255" {
				valid = append(valid, match)
			}
		default:
			valid = append(valid, match)
		}
	}

	return valid
}

// detectDebugInfo finds debug information leakage
func (d *SecurityDataExposureDetector) detectDebugInfo(content string) []SecurityIssue {
	issues := []SecurityIssue{}

	debugCount := 0
	for _, pattern := range d.debugPatterns {
		matches := pattern.FindAllString(content, -1)
		debugCount += len(matches)
	}

	if debugCount > 10 {
		issues = append(issues, SecurityIssue{
			Type:        "debug",
			Title:       "Debug code in production",
			Description: fmt.Sprintf("Found %d debug statements (console.log, debugger, etc.)", debugCount),
			Severity:    "low",
			Evidence:    []string{fmt.Sprintf("%d debug statements", debugCount)},
			Impact:      "Information disclosure, performance impact",
			Remediation: "Remove debug code from production builds",
			Verified:    true,
		})
	}

	// Check for error messages with details
	errorPattern := regexp.MustCompile(`(?i)(?:error|exception|stack\s*trace|traceback):\s*[^\s]{20,}`)
	if errorPattern.MatchString(content) {
		issues = append(issues, SecurityIssue{
			Type:        "error-disclosure",
			Title:       "Detailed error messages exposed",
			Description: "Error messages with stack traces found in code",
			Severity:    "medium",
			Evidence:    []string{"Detailed error messages"},
			Impact:      "Internal application structure revealed",
			Remediation: "Use generic error messages in production",
			Verified:    true,
		})
	}

	return issues
}

// detectInternalPaths finds exposed internal paths and URLs
func (d *SecurityDataExposureDetector) detectInternalPaths(content string) []SecurityIssue {
	issues := []SecurityIssue{}

	// Check for file system paths
	pathPatterns := []*regexp.Regexp{
		regexp.MustCompile(`(?i)[C-Z]:\\[^\s"'<>]{10,}`),                        // Windows paths
		regexp.MustCompile(`(?i)/(?:home|users|var|etc|usr|opt)/[^\s"'<>]{10,}`), // Unix paths
		regexp.MustCompile(`(?i)\\\\[^\s"'\\]{3,}\\[^\s"'\\]{3,}`),              // UNC paths
	}

	pathCount := 0
	for _, pattern := range pathPatterns {
		matches := pattern.FindAllString(content, -1)
		pathCount += len(matches)
	}

	if pathCount > 0 {
		issues = append(issues, SecurityIssue{
			Type:        "path-disclosure",
			Title:       "Internal file paths exposed",
			Description: fmt.Sprintf("Found %d internal file system paths", pathCount),
			Severity:    "low",
			Evidence:    []string{fmt.Sprintf("%d file paths", pathCount)},
			Impact:      "Internal structure disclosure",
			Remediation: "Remove file paths from client-side code",
			Verified:    true,
		})
	}

	// Check for internal URLs
	internalURLPattern := regexp.MustCompile(`(?i)(?:http|https)://(?:localhost|127\.0\.0\.1|192\.168\.|10\.|172\.(?:1[6-9]|2[0-9]|3[0-1])\.)[^\s"'<>]+`)
	internalURLs := internalURLPattern.FindAllString(content, -1)
	if len(internalURLs) > 0 {
		issues = append(issues, SecurityIssue{
			Type:        "url-disclosure",
			Title:       "Internal URLs exposed",
			Description: fmt.Sprintf("Found %d internal/localhost URLs", len(internalURLs)),
			Severity:    "medium",
			Evidence:    []string{fmt.Sprintf("%d internal URLs", len(internalURLs))},
			Impact:      "Internal infrastructure disclosure",
			Remediation: "Remove internal URLs from production code",
			Verified:    true,
		})
	}

	return issues
}

// detectSensitiveComments finds sensitive information in comments
func (d *SecurityDataExposureDetector) detectSensitiveComments(content string) []SecurityIssue {
	issues := []SecurityIssue{}

	// Extract comments
	htmlCommentPattern := regexp.MustCompile(`<!--[\s\S]*?-->`)
	jsCommentPattern := regexp.MustCompile(`//[^\n]*|/\*[\s\S]*?\*/`)

	comments := htmlCommentPattern.FindAllString(content, -1)
	comments = append(comments, jsCommentPattern.FindAllString(content, -1)...)

	sensitiveKeywords := []string{
		"password", "secret", "api key", "token", "credential",
		"username", "admin", "root", "database", "connection string",
		"TODO", "FIXME", "HACK", "BUG", "XXX",
	}

	sensitiveCount := 0
	for _, comment := range comments {
		commentLower := strings.ToLower(comment)
		for _, keyword := range sensitiveKeywords {
			if strings.Contains(commentLower, keyword) {
				sensitiveCount++
				break
			}
		}
	}

	if sensitiveCount > 5 {
		issues = append(issues, SecurityIssue{
			Type:        "comments",
			Title:       "Sensitive information in comments",
			Description: fmt.Sprintf("Found %d comments with potentially sensitive information", sensitiveCount),
			Severity:    "low",
			Evidence:    []string{fmt.Sprintf("%d sensitive comments", sensitiveCount)},
			Impact:      "Information leakage through comments",
			Remediation: "Remove sensitive comments from production code",
			Verified:    true,
		})
	}

	return issues
}

// detectEnvironmentVariables finds exposed environment variables
func (d *SecurityDataExposureDetector) detectEnvironmentVariables(content string) []SecurityIssue {
	issues := []SecurityIssue{}

	envVarPattern := regexp.MustCompile(`(?i)(?:process\.env|env\.|ENV\[)['"]\w+['"]`)
	matches := envVarPattern.FindAllString(content, -1)

	if len(matches) > 5 {
		issues = append(issues, SecurityIssue{
			Type:        "env-vars",
			Title:       "Environment variables referenced in client code",
			Description: fmt.Sprintf("Found %d environment variable references", len(matches)),
			Severity:    "medium",
			Evidence:    []string{fmt.Sprintf("%d env var references", len(matches))},
			Impact:      "May expose configuration details",
			Remediation: "Use build-time variable replacement instead of runtime env vars",
			Verified:    true,
		})
	}

	return issues
}

// detectStackTraces finds exposed stack traces
func (d *SecurityDataExposureDetector) detectStackTraces(content string) []SecurityIssue {
	issues := []SecurityIssue{}

	stackTracePatterns := []*regexp.Regexp{
		regexp.MustCompile(`(?i)at\s+[\w.]+\s*\([^)]*:\d+:\d+\)`),
		regexp.MustCompile(`(?i)Traceback\s*\(most recent call last\)`),
		regexp.MustCompile(`(?i)Exception in thread`),
		regexp.MustCompile(`(?i)Fatal error:.*in\s+/`),
	}

	for _, pattern := range stackTracePatterns {
		if pattern.MatchString(content) {
			issues = append(issues, SecurityIssue{
				Type:        "stack-trace",
				Title:       "Stack trace exposed",
				Description: "Stack trace with file paths and line numbers found",
				Severity:    "medium",
				Evidence:    []string{"Stack trace detected"},
				Impact:      "Reveals internal application structure and paths",
				Remediation: "Handle errors gracefully without exposing stack traces",
				Verified:    true,
			})
			break
		}
	}

	return issues
}

// detectSuspiciousScripts checks external script URLs for suspicious patterns
func (d *SecurityDataExposureDetector) detectSuspiciousScripts(externalScripts []string) []SecurityIssue {
	issues := []SecurityIssue{}

	suspiciousPatterns := []struct{
		pattern *regexp.Regexp
		name    string
	}{
		{regexp.MustCompile(`(?i)\.tk/|\.ga/|\.ml/|\.cf/|\.gq/`), "Suspicious TLD"},
		{regexp.MustCompile(`(?i)\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}`), "IP address URL"},
		{regexp.MustCompile(`(?i)eval|base64|atob|btoa`), "Obfuscation indicators"},
	}

	suspiciousScripts := []string{}
	for _, scriptURL := range externalScripts {
		for _, sp := range suspiciousPatterns {
			if sp.pattern.MatchString(scriptURL) {
				suspiciousScripts = append(suspiciousScripts, scriptURL)
				break
			}
		}
	}

	if len(suspiciousScripts) > 0 {
		issues = append(issues, SecurityIssue{
			Type:        "suspicious-script",
			Title:       "Suspicious external scripts detected",
			Description: fmt.Sprintf("Found %d scripts from suspicious sources", len(suspiciousScripts)),
			Severity:    "high",
			Evidence:    suspiciousScripts,
			Impact:      "Potential malicious script injection",
			Remediation: "Review and verify all external script sources",
			Verified:    true,
		})
	}

	return issues
}