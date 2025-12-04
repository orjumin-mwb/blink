package checker

import (
	"fmt"
	"net/url"
	"regexp"
	"strings"
)

// SecurityMixedContentDetector detects mixed content and subresource integrity issues
type SecurityMixedContentDetector struct {
	scriptPattern   *regexp.Regexp
	stylePattern    *regexp.Regexp
	imagePattern    *regexp.Regexp
	iframePattern   *regexp.Regexp
	formPattern     *regexp.Regexp
	anchorPattern   *regexp.Regexp
	mediaPattern    *regexp.Regexp
	trustedCDNs     map[string]bool
}

// NewSecurityMixedContentDetector creates a new mixed content detector
func NewSecurityMixedContentDetector() *SecurityMixedContentDetector {
	return &SecurityMixedContentDetector{
		scriptPattern: regexp.MustCompile(`(?i)<script[^>]*\ssrc\s*=\s*["']([^"']+)["'][^>]*>`),
		stylePattern:  regexp.MustCompile(`(?i)<link[^>]*\shref\s*=\s*["']([^"']+)["'][^>]*rel\s*=\s*["']stylesheet["']|<link[^>]*rel\s*=\s*["']stylesheet["'][^>]*\shref\s*=\s*["']([^"']+)["']`),
		imagePattern:  regexp.MustCompile(`(?i)<img[^>]*\ssrc\s*=\s*["']([^"']+)["']`),
		iframePattern: regexp.MustCompile(`(?i)<iframe[^>]*\ssrc\s*=\s*["']([^"']+)["']`),
		formPattern:   regexp.MustCompile(`(?i)<form[^>]*\saction\s*=\s*["']([^"']+)["']`),
		anchorPattern: regexp.MustCompile(`(?i)<a[^>]*\shref\s*=\s*["']([^"']+)["']`),
		mediaPattern:  regexp.MustCompile(`(?i)<(?:video|audio|source)[^>]*\ssrc\s*=\s*["']([^"']+)["']`),
		trustedCDNs: map[string]bool{
			"cdn.jsdelivr.net":      true,
			"cdnjs.cloudflare.com":  true,
			"unpkg.com":             true,
			"code.jquery.com":       true,
			"stackpath.bootstrapcdn.com": true,
			"fonts.googleapis.com":  true,
			"fonts.gstatic.com":     true,
		},
	}
}

// Detect analyzes HTML for mixed content and subresource integrity issues
func (d *SecurityMixedContentDetector) Detect(html string, pageURL string) []SecurityIssue {
	issues := []SecurityIssue{}

	isHTTPS := strings.HasPrefix(pageURL, "https://")

	// Check for mixed content on HTTPS pages
	if isHTTPS {
		issues = append(issues, d.detectMixedContent(html, pageURL)...)
	}

	// Check for missing Subresource Integrity (SRI)
	issues = append(issues, d.detectMissingSRI(html)...)

	// Check for untrusted CDN usage
	issues = append(issues, d.detectUntrustedCDNs(html)...)

	// Check for protocol-relative URLs (deprecated practice)
	issues = append(issues, d.detectProtocolRelativeURLs(html)...)

	// Check for source map exposure
	issues = append(issues, d.detectSourceMapExposure(html)...)

	return issues
}

// detectMixedContent finds HTTP resources on HTTPS pages
func (d *SecurityMixedContentDetector) detectMixedContent(html string, pageURL string) []SecurityIssue {
	issues := []SecurityIssue{}

	// Check scripts
	scriptMatches := d.scriptPattern.FindAllStringSubmatch(html, -1)
	for _, match := range scriptMatches {
		src := match[1]
		if strings.HasPrefix(src, "http://") {
			issues = append(issues, SecurityIssue{
				Type:        "mixed-content",
				Title:       "Mixed content: Script loaded over HTTP",
				Description: fmt.Sprintf("Script loaded from HTTP URL on HTTPS page: %s", src),
				Severity:    "high",
				Evidence:    []string{src},
				Impact:      "Script can be intercepted and modified by attackers",
				Remediation: "Load all scripts over HTTPS",
				Verified:    true,
			})
		}
	}

	// Check stylesheets
	styleMatches := d.stylePattern.FindAllStringSubmatch(html, -1)
	for _, match := range styleMatches {
		href := match[1]
		if href == "" {
			href = match[2]
		}
		if strings.HasPrefix(href, "http://") {
			issues = append(issues, SecurityIssue{
				Type:        "mixed-content",
				Title:       "Mixed content: Stylesheet loaded over HTTP",
				Description: fmt.Sprintf("Stylesheet loaded from HTTP URL on HTTPS page: %s", href),
				Severity:    "medium",
				Evidence:    []string{href},
				Impact:      "Styles can be modified to inject content or phishing",
				Remediation: "Load all stylesheets over HTTPS",
				Verified:    true,
			})
		}
	}

	// Check images
	imageMatches := d.imagePattern.FindAllStringSubmatch(html, -1)
	httpImages := 0
	for _, match := range imageMatches {
		src := match[1]
		if strings.HasPrefix(src, "http://") {
			httpImages++
		}
	}
	if httpImages > 0 {
		issues = append(issues, SecurityIssue{
			Type:        "mixed-content",
			Title:       "Mixed content: Images loaded over HTTP",
			Description: fmt.Sprintf("Found %d images loaded from HTTP URLs on HTTPS page", httpImages),
			Severity:    "low",
			Evidence:    []string{fmt.Sprintf("%d HTTP images", httpImages)},
			Impact:      "Images can be replaced by attackers, privacy leak",
			Remediation: "Load all images over HTTPS",
			Verified:    true,
		})
	}

	// Check iframes
	iframeMatches := d.iframePattern.FindAllStringSubmatch(html, -1)
	for _, match := range iframeMatches {
		src := match[1]
		if strings.HasPrefix(src, "http://") {
			issues = append(issues, SecurityIssue{
				Type:        "mixed-content",
				Title:       "Mixed content: iframe loaded over HTTP",
				Description: fmt.Sprintf("iframe loaded from HTTP URL on HTTPS page: %s", src),
				Severity:    "high",
				Evidence:    []string{src},
				Impact:      "Entire embedded content can be compromised",
				Remediation: "Load all iframes over HTTPS",
				Verified:    true,
			})
		}
	}

	// Check forms
	formMatches := d.formPattern.FindAllStringSubmatch(html, -1)
	for _, match := range formMatches {
		action := match[1]
		if strings.HasPrefix(action, "http://") {
			issues = append(issues, SecurityIssue{
				Type:        "mixed-content",
				Title:       "Mixed content: Form submits to HTTP",
				Description: fmt.Sprintf("Form action points to HTTP URL: %s", action),
				Severity:    "critical",
				Evidence:    []string{action},
				Impact:      "Form data will be transmitted without encryption",
				Remediation: "Ensure all forms submit to HTTPS endpoints",
				Verified:    true,
			})
		}
	}

	return issues
}

// detectMissingSRI checks for missing Subresource Integrity attributes
func (d *SecurityMixedContentDetector) detectMissingSRI(html string) []SecurityIssue {
	issues := []SecurityIssue{}

	// Check external scripts without integrity attribute
	scriptPattern := regexp.MustCompile(`(?i)<script[^>]*\ssrc\s*=\s*["']([^"']+)["'][^>]*>`)
	integrityPattern := regexp.MustCompile(`(?i)\sintegrity\s*=\s*["'][^"']+["']`)

	scriptMatches := scriptPattern.FindAllString(html, -1)
	scriptsWithoutSRI := 0
	externalScriptsCount := 0

	for _, scriptTag := range scriptMatches {
		srcMatch := regexp.MustCompile(`(?i)src\s*=\s*["']([^"']+)["']`).FindStringSubmatch(scriptTag)
		if len(srcMatch) > 1 {
			src := srcMatch[1]
			// Check if it's an external script
			if strings.HasPrefix(src, "http://") || strings.HasPrefix(src, "https://") || strings.HasPrefix(src, "//") {
				externalScriptsCount++
				if !integrityPattern.MatchString(scriptTag) {
					scriptsWithoutSRI++
				}
			}
		}
	}

	if scriptsWithoutSRI > 0 {
		severity := "medium"
		if float64(scriptsWithoutSRI)/float64(externalScriptsCount) > 0.8 {
			severity = "high"
		}

		issues = append(issues, SecurityIssue{
			Type:        "sri",
			Title:       "Missing Subresource Integrity",
			Description: fmt.Sprintf("%d of %d external scripts lack SRI protection", scriptsWithoutSRI, externalScriptsCount),
			Severity:    severity,
			Evidence:    []string{fmt.Sprintf("%d scripts without SRI", scriptsWithoutSRI)},
			Impact:      "Modified scripts from compromised CDNs can run",
			Remediation: "Add integrity and crossorigin attributes to external scripts",
			Verified:    true,
		})
	}

	// Check external stylesheets without integrity
	linkPattern := regexp.MustCompile(`(?i)<link[^>]*\srel\s*=\s*["']stylesheet["'][^>]*>`)
	linkMatches := linkPattern.FindAllString(html, -1)
	stylesWithoutSRI := 0
	externalStylesCount := 0

	for _, linkTag := range linkMatches {
		hrefMatch := regexp.MustCompile(`(?i)href\s*=\s*["']([^"']+)["']`).FindStringSubmatch(linkTag)
		if len(hrefMatch) > 1 {
			href := hrefMatch[1]
			if strings.HasPrefix(href, "http://") || strings.HasPrefix(href, "https://") || strings.HasPrefix(href, "//") {
				externalStylesCount++
				if !integrityPattern.MatchString(linkTag) {
					stylesWithoutSRI++
				}
			}
		}
	}

	if stylesWithoutSRI > 0 {
		issues = append(issues, SecurityIssue{
			Type:        "sri",
			Title:       "Missing SRI for stylesheets",
			Description: fmt.Sprintf("%d of %d external stylesheets lack SRI protection", stylesWithoutSRI, externalStylesCount),
			Severity:    "low",
			Evidence:    []string{fmt.Sprintf("%d stylesheets without SRI", stylesWithoutSRI)},
			Impact:      "Modified styles from compromised CDNs can be injected",
			Remediation: "Add integrity attribute to external stylesheets",
			Verified:    true,
		})
	}

	return issues
}

// detectUntrustedCDNs checks for resources from untrusted CDNs
func (d *SecurityMixedContentDetector) detectUntrustedCDNs(html string) []SecurityIssue {
	issues := []SecurityIssue{}

	// Extract all external resource URLs
	urlPattern := regexp.MustCompile(`(?i)(?:src|href)\s*=\s*["']([^"']+)["']`)
	matches := urlPattern.FindAllStringSubmatch(html, -1)

	untrustedCDNs := make(map[string]int)

	for _, match := range matches {
		resourceURL := match[1]
		if strings.HasPrefix(resourceURL, "http://") || strings.HasPrefix(resourceURL, "https://") {
			parsedURL, err := url.Parse(resourceURL)
			if err == nil && parsedURL.Host != "" {
				if !d.trustedCDNs[parsedURL.Host] && !strings.Contains(parsedURL.Host, "localhost") {
					// Check if it's a CDN (not same-origin)
					if strings.Contains(parsedURL.Host, "cdn") || strings.Contains(parsedURL.Host, "static") ||
					   strings.Contains(parsedURL.Host, "assets") || strings.Contains(parsedURL.Host, "cloudfront") {
						untrustedCDNs[parsedURL.Host]++
					}
				}
			}
		}
	}

	for cdn, count := range untrustedCDNs {
		issues = append(issues, SecurityIssue{
			Type:        "cdn",
			Title:       "Resources from untrusted CDN",
			Description: fmt.Sprintf("Loading %d resources from potentially untrusted CDN: %s", count, cdn),
			Severity:    "low",
			Evidence:    []string{cdn, fmt.Sprintf("%d resources", count)},
			Impact:      "CDN compromise could affect your site",
			Remediation: "Use trusted CDNs with SRI or host resources locally",
			Verified:    true,
		})
	}

	return issues
}

// detectProtocolRelativeURLs checks for protocol-relative URLs (deprecated)
func (d *SecurityMixedContentDetector) detectProtocolRelativeURLs(html string) []SecurityIssue {
	issues := []SecurityIssue{}

	protocolRelativePattern := regexp.MustCompile(`(?i)(?:src|href|action)\s*=\s*["'](//[^"']+)["']`)
	matches := protocolRelativePattern.FindAllStringSubmatch(html, -1)

	if len(matches) > 0 {
		issues = append(issues, SecurityIssue{
			Type:        "deprecated",
			Title:       "Protocol-relative URLs detected",
			Description: fmt.Sprintf("Found %d protocol-relative URLs (//example.com)", len(matches)),
			Severity:    "low",
			Evidence:    []string{fmt.Sprintf("%d protocol-relative URLs", len(matches))},
			Impact:      "Can lead to mixed content issues",
			Remediation: "Use explicit https:// URLs instead of protocol-relative URLs",
			Verified:    true,
		})
	}

	return issues
}

// detectSourceMapExposure checks for exposed source map files
func (d *SecurityMixedContentDetector) detectSourceMapExposure(html string) []SecurityIssue {
	issues := []SecurityIssue{}

	// Check for sourceMappingURL comments
	sourceMapPattern := regexp.MustCompile(`(?i)//[#@]\s*sourceMappingURL\s*=\s*([^\s]+\.map)`)
	matches := sourceMapPattern.FindAllStringSubmatch(html, -1)

	// Also check script src for .map files
	mapFilePattern := regexp.MustCompile(`(?i)(?:src|href)\s*=\s*["']([^"']+\.map)["']`)
	mapFileMatches := mapFilePattern.FindAllStringSubmatch(html, -1)

	totalMaps := len(matches) + len(mapFileMatches)

	if totalMaps > 0 {
		issues = append(issues, SecurityIssue{
			Type:        "exposure",
			Title:       "Source map files exposed",
			Description: fmt.Sprintf("Found %d source map references that may expose source code", totalMaps),
			Severity:    "medium",
			Evidence:    []string{fmt.Sprintf("%d .map files", totalMaps)},
			Impact:      "Original source code structure exposed to attackers",
			Remediation: "Remove source maps from production or restrict access",
			Verified:    true,
		})
	}

	return issues
}