package checker

import (
	"fmt"
	"regexp"
	"strings"
)

// SecurityClientDetector detects client-side security vulnerabilities
type SecurityClientDetector struct {
	dangerousSinks    map[string]string
	dangerousJQuery   map[string]string
	openRedirectPats  []*regexp.Regexp
	prototypePollution *regexp.Regexp
	unsafeRegex       *regexp.Regexp
}

// NewSecurityClientDetector creates a new client-side security detector
func NewSecurityClientDetector() *SecurityClientDetector {
	return &SecurityClientDetector{
		dangerousSinks: map[string]string{
			`\.innerHTML\s*=`:                          "innerHTML",
			`\.outerHTML\s*=`:                          "outerHTML",
			`document\.write\s*\(`:                     "document.write",
			`document\.writeln\s*\(`:                   "document.writeln",
			`eval\s*\(`:                                "eval",
			`setTimeout\s*\([^,]*,`:                    "setTimeout with string",
			`setInterval\s*\([^,]*,`:                   "setInterval with string",
			`new\s+Function\s*\(`:                      "Function constructor",
			`\.insertAdjacentHTML\s*\(`:                "insertAdjacentHTML",
			`\.createContextualFragment\s*\(`:          "createContextualFragment",
			`window\.location\s*=`:                     "window.location assignment",
			`window\.location\.href\s*=`:               "window.location.href",
			`window\.location\.replace\s*\(`:           "location.replace",
			`window\.open\s*\(`:                        "window.open",
			`document\.location\s*=`:                   "document.location",
			`document\.domain\s*=`:                     "document.domain",
		},
		dangerousJQuery: map[string]string{
			`\$\([^)]*\)\.html\s*\(`:                  "$.html()",
			`\$\([^)]*\)\.append\s*\(`:                "$.append()",
			`\$\([^)]*\)\.prepend\s*\(`:               "$.prepend()",
			`\$\([^)]*\)\.after\s*\(`:                 "$.after()",
			`\$\([^)]*\)\.before\s*\(`:                "$.before()",
			`\$\([^)]*\)\.replaceWith\s*\(`:           "$.replaceWith()",
			`\$\([^)]*\)\.replaceAll\s*\(`:            "$.replaceAll()",
			`\$\([^)]*\)\.wrap\s*\(`:                  "$.wrap()",
			`\$\([^)]*\)\.wrapAll\s*\(`:               "$.wrapAll()",
			`\$\([^)]*\)\.wrapInner\s*\(`:             "$.wrapInner()",
			`\$\.globalEval\s*\(`:                     "$.globalEval()",
			`\$\.parseHTML\s*\(`:                      "$.parseHTML()",
		},
		openRedirectPats: []*regexp.Regexp{
			regexp.MustCompile(`(?i)window\.location\s*=\s*[^"'\s]+`),
			regexp.MustCompile(`(?i)window\.location\.href\s*=\s*[^"'\s]+`),
			regexp.MustCompile(`(?i)location\.replace\s*\([^"']+\)`),
			regexp.MustCompile(`(?i)location\s*=\s*location\.hash`),
			regexp.MustCompile(`(?i)location\s*=\s*.*\+.*(?:hash|search|param)`),
		},
		prototypePollution: regexp.MustCompile(`(?i)(?:__proto__|constructor|prototype)\s*[\[\.]`),
		unsafeRegex:        regexp.MustCompile(`(?i)new\s+RegExp\s*\([^"']+\)`),
	}
}

// Detect analyzes JavaScript for client-side security vulnerabilities
func (d *SecurityClientDetector) Detect(html string, scripts []string) []SecurityIssue {
	issues := []SecurityIssue{}

	// Combine inline scripts and HTML for analysis
	allContent := html
	for _, script := range scripts {
		allContent += "\n" + script
	}

	// Detect dangerous sinks (DOM XSS)
	issues = append(issues, d.detectDangerousSinks(allContent)...)

	// Detect dangerous jQuery patterns
	issues = append(issues, d.detectDangerousJQuery(allContent)...)

	// Detect open redirect vulnerabilities
	issues = append(issues, d.detectOpenRedirects(allContent)...)

	// Detect prototype pollution
	issues = append(issues, d.detectPrototypePollution(allContent)...)

	// Detect unsafe regular expressions
	issues = append(issues, d.detectUnsafeRegex(allContent)...)

	// Detect postMessage usage without origin verification
	issues = append(issues, d.detectPostMessageIssues(allContent)...)

	// Detect localStorage/sessionStorage of sensitive data
	issues = append(issues, d.detectStorageIssues(allContent)...)

	// Detect JSONP usage
	issues = append(issues, d.detectJSONP(allContent)...)

	// Detect outdated/vulnerable JavaScript libraries
	issues = append(issues, d.detectVulnerableLibraries(allContent)...)

	// Detect WebSocket security issues
	issues = append(issues, d.detectWebSocketIssues(allContent)...)

	return issues
}

// detectDangerousSinks finds dangerous DOM manipulation patterns
func (d *SecurityClientDetector) detectDangerousSinks(content string) []SecurityIssue {
	issues := []SecurityIssue{}
	foundSinks := make(map[string]int)

	for pattern, sinkName := range d.dangerousSinks {
		re := regexp.MustCompile(pattern)
		matches := re.FindAllString(content, -1)
		if len(matches) > 0 {
			foundSinks[sinkName] = len(matches)
		}
	}

	// Check for eval and similar
	evalSinks := []string{"eval", "Function constructor", "setTimeout with string", "setInterval with string"}
	evalCount := 0
	for _, sink := range evalSinks {
		if count, exists := foundSinks[sink]; exists {
			evalCount += count
		}
	}

	if evalCount > 0 {
		issues = append(issues, SecurityIssue{
			Type:        "client-xss",
			Title:       "Dangerous JavaScript evaluation detected",
			Description: fmt.Sprintf("Found %d uses of eval() or similar functions", evalCount),
			Severity:    "high",
			Evidence:    []string{fmt.Sprintf("%d eval patterns", evalCount)},
			Impact:      "Code injection vulnerability if user input reaches these functions",
			Remediation: "Avoid eval(), Function(), and setTimeout/setInterval with strings",
			Verified:    true,
		})
	}

	// Check for innerHTML and similar
	htmlSinks := []string{"innerHTML", "outerHTML", "document.write", "insertAdjacentHTML"}
	htmlCount := 0
	for _, sink := range htmlSinks {
		if count, exists := foundSinks[sink]; exists {
			htmlCount += count
		}
	}

	if htmlCount > 0 {
		severity := "medium"
		if htmlCount > 10 {
			severity = "high"
		}

		issues = append(issues, SecurityIssue{
			Type:        "client-xss",
			Title:       "DOM XSS sink detected",
			Description: fmt.Sprintf("Found %d uses of dangerous DOM manipulation", htmlCount),
			Severity:    severity,
			Evidence:    []string{fmt.Sprintf("%d DOM sinks", htmlCount)},
			Impact:      "Potential DOM-based XSS if user input reaches these sinks",
			Remediation: "Use textContent or createElement instead of innerHTML",
			Verified:    true,
		})
	}

	// Check for location manipulation
	locationSinks := []string{"window.location assignment", "window.location.href", "location.replace", "document.location"}
	locationCount := 0
	for _, sink := range locationSinks {
		if count, exists := foundSinks[sink]; exists {
			locationCount += count
		}
	}

	if locationCount > 0 {
		issues = append(issues, SecurityIssue{
			Type:        "client-redirect",
			Title:       "Client-side redirect manipulation",
			Description: fmt.Sprintf("Found %d location manipulations", locationCount),
			Severity:    "medium",
			Evidence:    []string{fmt.Sprintf("%d location changes", locationCount)},
			Impact:      "Potential open redirect vulnerability",
			Remediation: "Validate URLs before redirecting",
			Verified:    true,
		})
	}

	return issues
}

// detectDangerousJQuery finds dangerous jQuery patterns
func (d *SecurityClientDetector) detectDangerousJQuery(content string) []SecurityIssue {
	issues := []SecurityIssue{}
	foundPatterns := make(map[string]int)

	for pattern, methodName := range d.dangerousJQuery {
		re := regexp.MustCompile(pattern)
		matches := re.FindAllString(content, -1)
		if len(matches) > 0 {
			foundPatterns[methodName] = len(matches)
		}
	}

	if len(foundPatterns) > 0 {
		totalCount := 0
		methods := []string{}
		for method, count := range foundPatterns {
			totalCount += count
			methods = append(methods, method)
		}

		issues = append(issues, SecurityIssue{
			Type:        "client-xss",
			Title:       "Dangerous jQuery methods detected",
			Description: fmt.Sprintf("Found %d uses of potentially dangerous jQuery methods", totalCount),
			Severity:    "medium",
			Evidence:    methods,
			Impact:      "DOM XSS vulnerability if user input is passed to these methods",
			Remediation: "Sanitize input before using jQuery DOM manipulation methods",
			Verified:    true,
		})
	}

	// Check for outdated jQuery
	jqueryVersion := regexp.MustCompile(`jquery[.-](\d+)\.(\d+)\.(\d+)`).FindStringSubmatch(content)
	if len(jqueryVersion) > 3 {
		major := jqueryVersion[1]
		minor := jqueryVersion[2]
		if major < "3" || (major == "3" && minor < "5") {
			issues = append(issues, SecurityIssue{
				Type:        "vulnerable-library",
				Title:       "Outdated jQuery version detected",
				Description: fmt.Sprintf("jQuery %s.%s.%s has known security vulnerabilities", major, minor, jqueryVersion[3]),
				Severity:    "high",
				Evidence:    []string{fmt.Sprintf("jQuery %s.%s.%s", major, minor, jqueryVersion[3])},
				Impact:      "Known XSS vulnerabilities in jQuery < 3.5.0",
				Remediation: "Update jQuery to version 3.5.0 or later",
				Verified:    true,
				CVE:         "CVE-2020-11022, CVE-2020-11023",
			})
		}
	}

	return issues
}

// detectOpenRedirects finds potential open redirect vulnerabilities
func (d *SecurityClientDetector) detectOpenRedirects(content string) []SecurityIssue {
	issues := []SecurityIssue{}

	redirectCount := 0
	for _, pattern := range d.openRedirectPats {
		if pattern.MatchString(content) {
			redirectCount++
		}
	}

	// Check for URL parameter usage in redirects
	urlParamPattern := regexp.MustCompile(`(?i)(?:window\.)?location(?:\.href)?\s*=\s*[^"']*(?:getParameter|URLSearchParams|location\.search)`)
	if urlParamPattern.MatchString(content) {
		issues = append(issues, SecurityIssue{
			Type:        "open-redirect",
			Title:       "Open redirect vulnerability detected",
			Description: "URL parameters used directly in location redirects",
			Severity:    "high",
			Evidence:    []string{"URL parameter in redirect"},
			Impact:      "Users can be redirected to malicious sites",
			Remediation: "Validate and whitelist redirect URLs",
			Verified:    true,
		})
	}

	return issues
}

// detectPrototypePollution finds prototype pollution vulnerabilities
func (d *SecurityClientDetector) detectPrototypePollution(content string) []SecurityIssue {
	issues := []SecurityIssue{}

	matches := d.prototypePollution.FindAllString(content, -1)
	if len(matches) > 0 {
		issues = append(issues, SecurityIssue{
			Type:        "prototype-pollution",
			Title:       "Potential prototype pollution",
			Description: fmt.Sprintf("Found %d references to __proto__, constructor, or prototype", len(matches)),
			Severity:    "medium",
			Evidence:    []string{fmt.Sprintf("%d prototype references", len(matches))},
			Impact:      "Object prototype can be polluted affecting all objects",
			Remediation: "Avoid using __proto__ and validate object merge operations",
			Verified:    false,
		})
	}

	// Check for unsafe object merging
	mergePattern := regexp.MustCompile(`(?i)(?:Object\.assign|\.extend|merge|deepMerge)\s*\([^)]*(?:req\.|body\.|params\.|query\.)`)
	if mergePattern.MatchString(content) {
		issues = append(issues, SecurityIssue{
			Type:        "prototype-pollution",
			Title:       "Unsafe object merging with user input",
			Description: "User input merged directly into objects",
			Severity:    "high",
			Evidence:    []string{"User input in object merge"},
			Impact:      "Prototype pollution leading to RCE or XSS",
			Remediation: "Sanitize objects before merging, use Map instead of objects",
			Verified:    true,
		})
	}

	return issues
}

// detectUnsafeRegex finds potentially vulnerable regular expressions
func (d *SecurityClientDetector) detectUnsafeRegex(content string) []SecurityIssue {
	issues := []SecurityIssue{}

	// Check for RegExp with user input
	if d.unsafeRegex.MatchString(content) {
		issues = append(issues, SecurityIssue{
			Type:        "regex-dos",
			Title:       "Unsafe RegExp construction",
			Description: "RegExp created with dynamic input",
			Severity:    "medium",
			Evidence:    []string{"new RegExp with variables"},
			Impact:      "ReDoS vulnerability causing denial of service",
			Remediation: "Use regex literals or validate input before RegExp construction",
			Verified:    false,
		})
	}

	// Check for catastrophic backtracking patterns
	reDoSPatterns := []string{
		`(\w+)+`,
		`(\d+)+`,
		`(.*)+`,
		`(.+)+`,
		`(\S+)+`,
	}

	for _, pattern := range reDoSPatterns {
		if strings.Contains(content, pattern) {
			issues = append(issues, SecurityIssue{
				Type:        "regex-dos",
				Title:       "ReDoS vulnerable pattern detected",
				Description: fmt.Sprintf("Pattern '%s' vulnerable to catastrophic backtracking", pattern),
				Severity:    "low",
				Evidence:    []string{pattern},
				Impact:      "CPU exhaustion through malicious input",
				Remediation: "Simplify regex patterns to avoid nested quantifiers",
				Verified:    true,
			})
			break
		}
	}

	return issues
}

// detectPostMessageIssues finds insecure postMessage usage
func (d *SecurityClientDetector) detectPostMessageIssues(content string) []SecurityIssue {
	issues := []SecurityIssue{}

	// Check for postMessage without origin check
	postMessagePattern := regexp.MustCompile(`(?i)window\.postMessage\s*\([^,)]*,\s*['"]\*['"]`)
	if postMessagePattern.MatchString(content) {
		issues = append(issues, SecurityIssue{
			Type:        "postmessage",
			Title:       "PostMessage with wildcard origin",
			Description: "postMessage sends to any origin (*)",
			Severity:    "high",
			Evidence:    []string{"postMessage(..., '*')"},
			Impact:      "Sensitive data can be sent to any website",
			Remediation: "Specify exact target origin in postMessage",
			Verified:    true,
		})
	}

	// Check for missing origin verification in message listener
	listenerPattern := regexp.MustCompile(`(?i)addEventListener\s*\(\s*['"]message['"]`)
	originCheckPattern := regexp.MustCompile(`(?i)event\.origin|e\.origin|origin\s*===|origin\s*!==`)

	if listenerPattern.MatchString(content) && !originCheckPattern.MatchString(content) {
		issues = append(issues, SecurityIssue{
			Type:        "postmessage",
			Title:       "Message listener without origin verification",
			Description: "Message event listener doesn't verify sender origin",
			Severity:    "high",
			Evidence:    []string{"No origin check in message listener"},
			Impact:      "Any website can send messages to this listener",
			Remediation: "Always verify event.origin in message listeners",
			Verified:    false,
		})
	}

	return issues
}

// detectStorageIssues finds sensitive data in browser storage
func (d *SecurityClientDetector) detectStorageIssues(content string) []SecurityIssue {
	issues := []SecurityIssue{}

	// Check for JWT/tokens in localStorage
	tokenStoragePattern := regexp.MustCompile(`(?i)localStorage\.setItem\s*\([^)]*(?:token|jwt|session|auth|api[_-]?key)`)
	if tokenStoragePattern.MatchString(content) {
		issues = append(issues, SecurityIssue{
			Type:        "storage",
			Title:       "Sensitive data in localStorage",
			Description: "Authentication tokens stored in localStorage",
			Severity:    "high",
			Evidence:    []string{"Token in localStorage"},
			Impact:      "Tokens accessible to XSS attacks, persist after logout",
			Remediation: "Use httpOnly cookies for sensitive tokens",
			Verified:    true,
		})
	}

	// Check for PII in storage
	piiPattern := regexp.MustCompile(`(?i)(?:local|session)Storage\.setItem\s*\([^)]*(?:email|phone|ssn|credit|password|address)`)
	if piiPattern.MatchString(content) {
		issues = append(issues, SecurityIssue{
			Type:        "storage",
			Title:       "PII in browser storage",
			Description: "Personally identifiable information stored in browser",
			Severity:    "medium",
			Evidence:    []string{"PII in storage"},
			Impact:      "Sensitive user data exposed to XSS attacks",
			Remediation: "Avoid storing PII in browser storage",
			Verified:    false,
		})
	}

	return issues
}

// detectJSONP finds JSONP usage (deprecated and insecure)
func (d *SecurityClientDetector) detectJSONP(content string) []SecurityIssue {
	issues := []SecurityIssue{}

	jsonpPattern := regexp.MustCompile(`(?i)(?:callback=|jsonp=|jsonpCallback)`)
	if jsonpPattern.MatchString(content) {
		issues = append(issues, SecurityIssue{
			Type:        "jsonp",
			Title:       "JSONP usage detected",
			Description: "JSONP is deprecated and inherently insecure",
			Severity:    "medium",
			Evidence:    []string{"JSONP callback parameter"},
			Impact:      "Bypasses same-origin policy, vulnerable to XSS",
			Remediation: "Use CORS instead of JSONP",
			Verified:    true,
		})
	}

	return issues
}

// detectVulnerableLibraries checks for known vulnerable JavaScript libraries
func (d *SecurityClientDetector) detectVulnerableLibraries(content string) []SecurityIssue {
	issues := []SecurityIssue{}

	// Check for vulnerable versions of popular libraries
	vulnerableLibs := map[string]struct{
		pattern *regexp.Regexp
		minSafe string
		cve     string
	}{
		"angular": {
			pattern: regexp.MustCompile(`angular[.-](\d+)\.(\d+)\.(\d+)`),
			minSafe: "1.6.0",
			cve:     "CVE-2019-14863",
		},
		"react": {
			pattern: regexp.MustCompile(`react[.-](\d+)\.(\d+)\.(\d+)`),
			minSafe: "16.4.2",
			cve:     "CVE-2018-6341",
		},
		"vue": {
			pattern: regexp.MustCompile(`vue[.-](\d+)\.(\d+)\.(\d+)`),
			minSafe: "2.5.17",
			cve:     "CVE-2018-14732",
		},
		"lodash": {
			pattern: regexp.MustCompile(`lodash[.-](\d+)\.(\d+)\.(\d+)`),
			minSafe: "4.17.21",
			cve:     "CVE-2021-23337",
		},
		"moment": {
			pattern: regexp.MustCompile(`moment[.-](\d+)\.(\d+)\.(\d+)`),
			minSafe: "2.29.2",
			cve:     "CVE-2022-24785",
		},
	}

	for libName, lib := range vulnerableLibs {
		matches := lib.pattern.FindStringSubmatch(content)
		if len(matches) > 3 {
			version := fmt.Sprintf("%s.%s.%s", matches[1], matches[2], matches[3])
			// Simplified version comparison (would need proper semver in production)
			if version < lib.minSafe {
				issues = append(issues, SecurityIssue{
					Type:        "vulnerable-library",
					Title:       fmt.Sprintf("Vulnerable %s version", libName),
					Description: fmt.Sprintf("%s %s has known vulnerabilities", libName, version),
					Severity:    "high",
					Evidence:    []string{fmt.Sprintf("%s %s", libName, version)},
					Impact:      "Known security vulnerabilities",
					Remediation: fmt.Sprintf("Update %s to %s or later", libName, lib.minSafe),
					Verified:    true,
					CVE:         lib.cve,
				})
			}
		}
	}

	return issues
}

// detectWebSocketIssues finds WebSocket security vulnerabilities
func (d *SecurityClientDetector) detectWebSocketIssues(content string) []SecurityIssue {
	issues := []SecurityIssue{}

	// Detect insecure WebSocket protocol (ws:// instead of wss://)
	insecureWSPattern := regexp.MustCompile(`(?i)new\s+WebSocket\s*\(\s*['"]ws://[^'"]+['"]`)
	insecureMatches := insecureWSPattern.FindAllString(content, -1)

	if len(insecureMatches) > 0 {
		// Extract URLs for evidence
		evidence := []string{}
		urlPattern := regexp.MustCompile(`ws://[^'"]+`)
		for _, match := range insecureMatches {
			if url := urlPattern.FindString(match); url != "" {
				evidence = append(evidence, url)
				if len(evidence) >= 3 {
					break
				}
			}
		}

		issues = append(issues, SecurityIssue{
			Type:        "websocket",
			Title:       "Insecure WebSocket connection",
			Description: fmt.Sprintf("Found %d WebSocket connections using insecure ws:// protocol", len(insecureMatches)),
			Severity:    "high",
			Evidence:    evidence,
			Impact:      "WebSocket traffic transmitted without encryption - can be intercepted and modified",
			Remediation: "Use secure wss:// protocol instead of ws:// for all WebSocket connections",
			Verified:    true,
		})
	}

	// Detect WebSocket message handler without origin validation
	wsPattern := regexp.MustCompile(`(?i)(?:new\s+WebSocket|WebSocket\s*\()`)
	messageHandlerPattern := regexp.MustCompile(`(?i)\.onmessage\s*=|addEventListener\s*\(\s*['"]message['"]`)
	originCheckPattern := regexp.MustCompile(`(?i)(?:event|e|msg)\.origin`)

	hasWebSocket := wsPattern.MatchString(content)
	hasMessageHandler := messageHandlerPattern.MatchString(content)
	hasOriginCheck := originCheckPattern.MatchString(content)

	// Only flag if we have WebSocket with message handler but no origin check
	if hasWebSocket && hasMessageHandler && !hasOriginCheck {
		// Try to find the message handler code for evidence
		messageMatches := messageHandlerPattern.FindAllString(content, -1)
		evidence := []string{}
		if len(messageMatches) > 0 {
			evidence = messageMatches
			if len(evidence) > 3 {
				evidence = evidence[:3]
			}
		} else {
			evidence = []string{"WebSocket message handler detected without origin validation"}
		}

		issues = append(issues, SecurityIssue{
			Type:        "websocket",
			Title:       "WebSocket without origin validation",
			Description: "WebSocket message handler doesn't verify message origin",
			Severity:    "medium",
			Evidence:    evidence,
			Impact:      "Any website can send messages to this WebSocket handler",
			Remediation: "Always validate event.origin in WebSocket message handlers before processing data",
			Verified:    false, // Lower confidence - origin check might be elsewhere
		})
	}

	// Detect WebSocket with user-controlled URL
	wsUserControlPattern := regexp.MustCompile(`(?i)new\s+WebSocket\s*\(\s*(?:location\.search|URLSearchParams|getParameter|window\.location|document\.location)`)
	if wsUserControlPattern.MatchString(content) {
		matches := wsUserControlPattern.FindAllString(content, -1)
		evidence := matches
		if len(evidence) > 3 {
			evidence = evidence[:3]
		}

		issues = append(issues, SecurityIssue{
			Type:        "websocket",
			Title:       "WebSocket with user-controlled URL",
			Description: "WebSocket URL constructed from user input",
			Severity:    "high",
			Evidence:    evidence,
			Impact:      "Attacker can redirect WebSocket to malicious server (WebSocket SSRF)",
			Remediation: "Validate and whitelist WebSocket URLs - never use user input directly",
			Verified:    true,
		})
	}

	return issues
}