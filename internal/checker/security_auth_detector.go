package checker

import (
	"fmt"
	"regexp"
	"strings"
)

// SecurityAuthDetector detects authentication and session security issues
type SecurityAuthDetector struct {
	loginURLPatterns  []*regexp.Regexp
	authHeaderPatterns map[string]*regexp.Regexp
	sessionPatterns   []*regexp.Regexp
}

// NewSecurityAuthDetector creates a new authentication security detector
func NewSecurityAuthDetector() *SecurityAuthDetector {
	return &SecurityAuthDetector{
		loginURLPatterns: []*regexp.Regexp{
			regexp.MustCompile(`(?i)/login|/signin|/authenticate|/auth`),
			regexp.MustCompile(`(?i)/register|/signup|/sign-up`),
			regexp.MustCompile(`(?i)/account|/profile|/user`),
			regexp.MustCompile(`(?i)/admin|/dashboard|/console`),
		},
		authHeaderPatterns: map[string]*regexp.Regexp{
			"Basic Auth":       regexp.MustCompile(`(?i)authorization:\s*basic\s+[a-zA-Z0-9+/=]+`),
			"Bearer Token":     regexp.MustCompile(`(?i)authorization:\s*bearer\s+[a-zA-Z0-9_\-\.]+`),
			"API Key Header":   regexp.MustCompile(`(?i)(?:x-api-key|api-key|apikey):\s*[a-zA-Z0-9_\-]+`),
		},
		sessionPatterns: []*regexp.Regexp{
			regexp.MustCompile(`(?i)session[_-]?id|sessionid|jsessionid|phpsessid`),
			regexp.MustCompile(`(?i)auth[_-]?token|access[_-]?token|refresh[_-]?token`),
		},
	}
}

// Detect analyzes authentication and session security
func (d *SecurityAuthDetector) Detect(html string, pageURL string, forms []FormInfo, scripts []string) []SecurityIssue {
	issues := []SecurityIssue{}

	isHTTPS := strings.HasPrefix(pageURL, "https://")
	isLoginPage := d.isLoginPage(pageURL)

	// Check login forms over HTTP
	if !isHTTPS && isLoginPage {
		issues = append(issues, SecurityIssue{
			Type:        "auth",
			Title:       "Login page served over HTTP",
			Description: "Authentication page accessible via insecure HTTP",
			Severity:    "critical",
			Evidence:    []string{pageURL},
			Impact:      "Credentials transmitted in cleartext",
			Remediation: "Enforce HTTPS for all authentication pages",
			Verified:    true,
		})
	}

	// Analyze forms for authentication issues
	for _, form := range forms {
		formIssues := d.analyzeAuthForm(form, isHTTPS, pageURL)
		issues = append(issues, formIssues...)
	}

	// Combine all content for analysis
	allContent := html
	for _, script := range scripts {
		allContent += "\n" + script
	}

	// Check for hardcoded credentials in auth code
	issues = append(issues, d.detectHardcodedAuthCredentials(allContent)...)

	// Check for insecure session management
	issues = append(issues, d.detectInsecureSessionManagement(allContent)...)

	// Check for authentication bypass patterns
	issues = append(issues, d.detectAuthBypass(allContent)...)

	// Check for JWT vulnerabilities
	issues = append(issues, d.detectJWTIssues(allContent)...)

	// Check for OAuth misconfigurations
	issues = append(issues, d.detectOAuthIssues(allContent)...)

	// Check for weak password policies
	issues = append(issues, d.detectWeakPasswordPolicies(allContent)...)

	// Check for session fixation vulnerabilities
	issues = append(issues, d.detectSessionFixation(allContent)...)

	return issues
}

// isLoginPage checks if URL appears to be a login/auth page
func (d *SecurityAuthDetector) isLoginPage(url string) bool {
	urlLower := strings.ToLower(url)
	for _, pattern := range d.loginURLPatterns {
		if pattern.MatchString(urlLower) {
			return true
		}
	}
	return false
}

// analyzeAuthForm checks authentication forms for security issues
func (d *SecurityAuthDetector) analyzeAuthForm(form FormInfo, isHTTPS bool, pageURL string) []SecurityIssue {
	issues := []SecurityIssue{}

	if !form.HasPasswordField {
		return issues
	}

	// Check if form action is HTTP
	if strings.HasPrefix(form.Action, "http://") {
		issues = append(issues, SecurityIssue{
			Type:        "auth",
			Title:       "Login form submits to HTTP",
			Description: fmt.Sprintf("Password form submits to insecure HTTP: %s", form.Action),
			Severity:    "critical",
			Evidence:    []string{form.Action},
			Impact:      "Credentials sent in cleartext over network",
			Remediation: "Use HTTPS for all form actions",
			Verified:    true,
		})
	}

	// Check for GET method on login forms
	if strings.ToUpper(form.Method) == "GET" {
		issues = append(issues, SecurityIssue{
			Type:        "auth",
			Title:       "Login form uses GET method",
			Description: "Password transmitted via GET exposes credentials in logs",
			Severity:    "critical",
			Evidence:    []string{fmt.Sprintf("Method: GET, Action: %s", form.Action)},
			Impact:      "Passwords visible in URL, logs, and browser history",
			Remediation: "Use POST method for login forms",
			Verified:    true,
		})
	}

	// Check for autocomplete on password fields
	if form.AutocompleteEnabled {
		issues = append(issues, SecurityIssue{
			Type:        "auth",
			Title:       "Autocomplete enabled on password field",
			Description: "Password autocomplete increases credential theft risk",
			Severity:    "low",
			Evidence:    []string{"autocomplete not disabled"},
			Impact:      "Passwords may be stored in browser",
			Remediation: "Set autocomplete='new-password' on password fields",
			Verified:    true,
		})
	}

	// Check for missing CSRF protection on login forms
	if !form.HasCSRFToken {
		issues = append(issues, SecurityIssue{
			Type:        "auth",
			Title:       "Login form missing CSRF protection",
			Description: "Authentication form lacks CSRF token",
			Severity:    "high",
			Evidence:    []string{"No CSRF token detected"},
			Impact:      "Login CSRF attacks possible",
			Remediation: "Implement CSRF tokens for login forms",
			Verified:    false,
		})
	}

	return issues
}

// detectHardcodedAuthCredentials finds hardcoded auth credentials
func (d *SecurityAuthDetector) detectHardcodedAuthCredentials(content string) []SecurityIssue {
	issues := []SecurityIssue{}

	// Check for Basic Auth credentials
	basicAuthPattern := regexp.MustCompile(`(?i)(?:basic\s+)?(?:authorization['"]\s*[:=]\s*['"]?basic\s+[a-zA-Z0-9+/=]{20,})`)
	if basicAuthPattern.MatchString(content) {
		issues = append(issues, SecurityIssue{
			Type:        "auth",
			Title:       "Hardcoded Basic Auth credentials",
			Description: "Basic authentication credentials found in client code",
			Severity:    "critical",
			Evidence:    []string{"Basic Auth in code"},
			Impact:      "Authentication credentials exposed",
			Remediation: "Never hardcode authentication credentials",
			Verified:    true,
		})
	}

	// Check for Bearer tokens in code
	bearerPattern := regexp.MustCompile(`(?i)(?:bearer|token)['"]\s*[:=]\s*['"][a-zA-Z0-9_\-\.]{20,}['"]`)
	if bearerPattern.MatchString(content) {
		issues = append(issues, SecurityIssue{
			Type:        "auth",
			Title:       "Hardcoded Bearer token",
			Description: "Bearer token hardcoded in JavaScript",
			Severity:    "critical",
			Evidence:    []string{"Bearer token in code"},
			Impact:      "Authentication bypass possible",
			Remediation: "Retrieve tokens dynamically from secure endpoints",
			Verified:    true,
		})
	}

	return issues
}

// detectInsecureSessionManagement finds session management issues
func (d *SecurityAuthDetector) detectInsecureSessionManagement(content string) []SecurityIssue {
	issues := []SecurityIssue{}

	// Check for session ID in URL
	sessionInURLPattern := regexp.MustCompile(`(?i)(?:session|sid|sessid)[=][a-zA-Z0-9]{10,}`)
	if sessionInURLPattern.MatchString(content) {
		issues = append(issues, SecurityIssue{
			Type:        "session",
			Title:       "Session ID in URL",
			Description: "Session identifier passed in URL parameters",
			Severity:    "high",
			Evidence:    []string{"Session ID in URL"},
			Impact:      "Session hijacking via referer leakage",
			Remediation: "Use httpOnly cookies for session management",
			Verified:    true,
		})
	}

	// Check for session storage of tokens
	sessionStoragePattern := regexp.MustCompile(`(?i)(?:session|local)Storage\.setItem\s*\([^)]*(?:session|token|auth)[^)]*\)`)
	if sessionStoragePattern.MatchString(content) {
		issues = append(issues, SecurityIssue{
			Type:        "session",
			Title:       "Session tokens in browser storage",
			Description: "Authentication tokens stored in localStorage/sessionStorage",
			Severity:    "high",
			Evidence:    []string{"Tokens in storage"},
			Impact:      "Tokens accessible to XSS attacks",
			Remediation: "Use httpOnly cookies for session tokens",
			Verified:    true,
		})
	}

	// Check for lack of session timeout
	timeoutPattern := regexp.MustCompile(`(?i)session[_-]?timeout|max[_-]?age|expires`)
	if !timeoutPattern.MatchString(content) {
		issues = append(issues, SecurityIssue{
			Type:        "session",
			Title:       "No session timeout detected",
			Description: "Session management code doesn't implement timeouts",
			Severity:    "medium",
			Evidence:    []string{"No timeout logic found"},
			Impact:      "Sessions may remain active indefinitely",
			Remediation: "Implement session timeouts and sliding expiration",
			Verified:    false,
		})
	}

	return issues
}

// detectAuthBypass finds authentication bypass vulnerabilities
func (d *SecurityAuthDetector) detectAuthBypass(content string) []SecurityIssue {
	issues := []SecurityIssue{}

	// Check for client-side authentication
	clientAuthPattern := regexp.MustCompile(`(?i)if\s*\([^)]*(?:password|auth|login)[^)]*(?:==|===)[^)]*\)`)
	if clientAuthPattern.MatchString(content) {
		issues = append(issues, SecurityIssue{
			Type:        "auth-bypass",
			Title:       "Client-side authentication detected",
			Description: "Authentication logic implemented in JavaScript",
			Severity:    "critical",
			Evidence:    []string{"Client-side auth check"},
			Impact:      "Authentication easily bypassed",
			Remediation: "Implement authentication server-side only",
			Verified:    true,
		})
	}

	// Check for role-based access control in client code
	rbacPattern := regexp.MustCompile(`(?i)(?:isAdmin|isUser|hasRole|checkPermission)\s*\([^)]*\)`)
	if rbacPattern.MatchString(content) {
		issues = append(issues, SecurityIssue{
			Type:        "auth-bypass",
			Title:       "Client-side authorization checks",
			Description: "Authorization logic found in client-side code",
			Severity:    "high",
			Evidence:    []string{"Client-side RBAC"},
			Impact:      "Authorization can be bypassed",
			Remediation: "Enforce authorization on the server",
			Verified:    false,
		})
	}

	// Check for admin flags in storage
	adminFlagPattern := regexp.MustCompile(`(?i)(?:local|session)Storage\.(?:get|set)Item\s*\([^)]*(?:admin|role|permission)[^)]*\)`)
	if adminFlagPattern.MatchString(content) {
		issues = append(issues, SecurityIssue{
			Type:        "auth-bypass",
			Title:       "Admin/role flags in client storage",
			Description: "User roles or permissions stored client-side",
			Severity:    "critical",
			Evidence:    []string{"Role in localStorage"},
			Impact:      "Users can grant themselves admin privileges",
			Remediation: "Validate permissions server-side on every request",
			Verified:    true,
		})
	}

	return issues
}

// detectJWTIssues finds JWT-related vulnerabilities
func (d *SecurityAuthDetector) detectJWTIssues(content string) []SecurityIssue {
	issues := []SecurityIssue{}

	// Check for JWT in localStorage
	jwtStoragePattern := regexp.MustCompile(`(?i)(?:local|session)Storage\.setItem\s*\([^)]*jwt[^)]*\)`)
	if jwtStoragePattern.MatchString(content) {
		issues = append(issues, SecurityIssue{
			Type:        "jwt",
			Title:       "JWT stored in localStorage",
			Description: "JSON Web Token stored in browser localStorage",
			Severity:    "high",
			Evidence:    []string{"JWT in localStorage"},
			Impact:      "JWT accessible to XSS attacks, persists after logout",
			Remediation: "Use httpOnly cookies for JWTs",
			Verified:    true,
		})
	}

	// Check for JWT algorithm set to 'none'
	jwtNonePattern := regexp.MustCompile(`(?i)["']alg["']\s*:\s*["']none["']`)
	if jwtNonePattern.MatchString(content) {
		issues = append(issues, SecurityIssue{
			Type:        "jwt",
			Title:       "JWT with 'none' algorithm",
			Description: "JWT using 'none' algorithm (no signature)",
			Severity:    "critical",
			Evidence:    []string{"alg: none"},
			Impact:      "JWT can be forged without signature",
			Remediation: "Use secure algorithms (RS256, ES256)",
			Verified:    true,
			CVE:         "CVE-2015-9235",
		})
	}

	// Check for JWT secret in code
	jwtSecretPattern := regexp.MustCompile(`(?i)jwt[_-]?secret|token[_-]?secret`)
	if jwtSecretPattern.MatchString(content) {
		issues = append(issues, SecurityIssue{
			Type:        "jwt",
			Title:       "JWT secret reference in code",
			Description: "JWT secret key referenced in client code",
			Severity:    "critical",
			Evidence:    []string{"JWT secret reference"},
			Impact:      "JWT tokens can be forged",
			Remediation: "Keep JWT secrets server-side only",
			Verified:    false,
		})
	}

	return issues
}

// detectOAuthIssues finds OAuth misconfiguration
func (d *SecurityAuthDetector) detectOAuthIssues(content string) []SecurityIssue {
	issues := []SecurityIssue{}

	// Check for OAuth tokens in URL
	oauthURLPattern := regexp.MustCompile(`(?i)(?:access_token|code)=([a-zA-Z0-9_\-\.]{20,})`)
	if oauthURLPattern.MatchString(content) {
		issues = append(issues, SecurityIssue{
			Type:        "oauth",
			Title:       "OAuth tokens in URL",
			Description: "OAuth access tokens passed via URL parameters",
			Severity:    "high",
			Evidence:    []string{"Token in URL"},
			Impact:      "Tokens leaked via referer and browser history",
			Remediation: "Use authorization code flow with PKCE",
			Verified:    true,
		})
	}

	// Check for missing state parameter
	oauthPattern := regexp.MustCompile(`(?i)oauth|authorize`)
	statePattern := regexp.MustCompile(`(?i)state=`)
	if oauthPattern.MatchString(content) && !statePattern.MatchString(content) {
		issues = append(issues, SecurityIssue{
			Type:        "oauth",
			Title:       "OAuth without state parameter",
			Description: "OAuth flow missing CSRF protection (state parameter)",
			Severity:    "high",
			Evidence:    []string{"No state parameter"},
			Impact:      "CSRF attacks on OAuth flow",
			Remediation: "Always include and validate state parameter",
			Verified:    false,
		})
	}

	// Check for client secret in code
	clientSecretPattern := regexp.MustCompile(`(?i)client[_-]?secret['"]\s*[:=]\s*['"][^'"]{20,}['"]`)
	if clientSecretPattern.MatchString(content) {
		issues = append(issues, SecurityIssue{
			Type:        "oauth",
			Title:       "OAuth client secret exposed",
			Description: "OAuth client secret hardcoded in JavaScript",
			Severity:    "critical",
			Evidence:    []string{"Client secret in code"},
			Impact:      "OAuth application can be impersonated",
			Remediation: "Use PKCE flow for public clients, keep secrets server-side",
			Verified:    true,
		})
	}

	return issues
}

// detectWeakPasswordPolicies finds weak password requirements
func (d *SecurityAuthDetector) detectWeakPasswordPolicies(content string) []SecurityIssue {
	issues := []SecurityIssue{}

	// Check for weak password validation
	weakPasswordPattern := regexp.MustCompile(`(?i)password\.length\s*[<>=]+\s*[1-5]`)
	if weakPasswordPattern.MatchString(content) {
		issues = append(issues, SecurityIssue{
			Type:        "password-policy",
			Title:       "Weak password policy",
			Description: "Password validation allows very short passwords",
			Severity:    "medium",
			Evidence:    []string{"Short password allowed"},
			Impact:      "Weak passwords enable brute-force attacks",
			Remediation: "Enforce minimum 12 character passwords with complexity",
			Verified:    true,
		})
	}

	// Check for lack of password complexity
	complexityPattern := regexp.MustCompile(`(?i)(?:uppercase|lowercase|digit|special|complexity)`)
	passwordPattern := regexp.MustCompile(`(?i)password[_-]?(?:valid|check|strength)`)
	if passwordPattern.MatchString(content) && !complexityPattern.MatchString(content) {
		issues = append(issues, SecurityIssue{
			Type:        "password-policy",
			Title:       "No password complexity requirements",
			Description: "Password validation doesn't enforce complexity",
			Severity:    "medium",
			Evidence:    []string{"No complexity checks"},
			Impact:      "Users may choose easily guessable passwords",
			Remediation: "Require mix of character types or use password strength meter",
			Verified:    false,
		})
	}

	return issues
}

// detectSessionFixation finds session fixation vulnerabilities
func (d *SecurityAuthDetector) detectSessionFixation(content string) []SecurityIssue {
	issues := []SecurityIssue{}

	// Check if session ID is accepted from URL
	sessionAcceptPattern := regexp.MustCompile(`(?i)(?:session|token)[_-]?id\s*=\s*(?:getParameter|URLSearchParams|location\.search)`)
	if sessionAcceptPattern.MatchString(content) {
		issues = append(issues, SecurityIssue{
			Type:        "session-fixation",
			Title:       "Session fixation vulnerability",
			Description: "Session ID accepted from URL parameters",
			Severity:    "high",
			Evidence:    []string{"Session ID from URL"},
			Impact:      "Attacker can fix user's session ID",
			Remediation: "Generate new session ID after authentication",
			Verified:    true,
		})
	}

	// Check for lack of session regeneration
	loginPattern := regexp.MustCompile(`(?i)login|authenticate|signin`)
	regeneratePattern := regexp.MustCompile(`(?i)session\.regenerate|regenerateSession|renewSession`)
	if loginPattern.MatchString(content) && !regeneratePattern.MatchString(content) {
		issues = append(issues, SecurityIssue{
			Type:        "session-fixation",
			Title:       "No session regeneration after login",
			Description: "Session ID not regenerated upon authentication",
			Severity:    "medium",
			Evidence:    []string{"No session regeneration"},
			Impact:      "Session fixation attacks possible",
			Remediation: "Regenerate session ID after successful login",
			Verified:    false,
		})
	}

	return issues
}