package checker

import (
	"net/http"
	"regexp"
)

// TechPattern defines a pattern for technology detection
type TechPattern struct {
	Name          string
	Category      string
	HeaderMatches map[string]*regexp.Regexp
	BodyMatches   []*regexp.Regexp
	VersionRegex  *regexp.Regexp
}

// TechDetector detects technologies from HTTP headers and HTML content
type TechDetector struct {
	patterns []TechPattern
}

// NewTechDetector creates a new technology detector with built-in patterns
func NewTechDetector() *TechDetector {
	return &TechDetector{
		patterns: []TechPattern{
			// Web Servers
			{
				Name:     "nginx",
				Category: "Web Server",
				HeaderMatches: map[string]*regexp.Regexp{
					"server": regexp.MustCompile(`(?i)nginx(?:/(\d+\.\d+(?:\.\d+)?))?`),
				},
				VersionRegex: regexp.MustCompile(`(\d+\.\d+(?:\.\d+)?)`),
			},
			{
				Name:     "Apache",
				Category: "Web Server",
				HeaderMatches: map[string]*regexp.Regexp{
					"server": regexp.MustCompile(`(?i)apache(?:/(\d+\.\d+(?:\.\d+)?))?`),
				},
				VersionRegex: regexp.MustCompile(`(\d+\.\d+(?:\.\d+)?)`),
			},
			{
				Name:     "IIS",
				Category: "Web Server",
				HeaderMatches: map[string]*regexp.Regexp{
					"server": regexp.MustCompile(`(?i)microsoft-iis(?:/(\d+\.\d+))?`),
				},
				VersionRegex: regexp.MustCompile(`(\d+\.\d+)`),
			},

			// CDN/Cloud
			{
				Name:     "Cloudflare",
				Category: "CDN",
				HeaderMatches: map[string]*regexp.Regexp{
					"cf-ray": regexp.MustCompile(`.+`),
				},
			},
			{
				Name:     "Fastly",
				Category: "CDN",
				HeaderMatches: map[string]*regexp.Regexp{
					"x-served-by": regexp.MustCompile(`(?i)cache-`),
					"x-fastly":    regexp.MustCompile(`.+`),
				},
			},
			{
				Name:     "Amazon CloudFront",
				Category: "CDN",
				HeaderMatches: map[string]*regexp.Regexp{
					"via": regexp.MustCompile(`(?i)cloudfront`),
				},
			},

			// Hosting Platforms
			{
				Name:     "Vercel",
				Category: "Hosting",
				HeaderMatches: map[string]*regexp.Regexp{
					"x-vercel-id": regexp.MustCompile(`.+`),
				},
			},
			{
				Name:     "Netlify",
				Category: "Hosting",
				HeaderMatches: map[string]*regexp.Regexp{
					"x-nf-request-id": regexp.MustCompile(`.+`),
				},
			},
			{
				Name:     "GitHub Pages",
				Category: "Hosting",
				HeaderMatches: map[string]*regexp.Regexp{
					"x-github-request-id": regexp.MustCompile(`.+`),
				},
			},

			// Frameworks (detected from HTML)
			{
				Name:     "Next.js",
				Category: "JavaScript Framework",
				BodyMatches: []*regexp.Regexp{
					regexp.MustCompile(`<div id="__next"`),
					regexp.MustCompile(`/_next/static/`),
				},
			},
			{
				Name:     "React",
				Category: "JavaScript Library",
				BodyMatches: []*regexp.Regexp{
					regexp.MustCompile(`data-reactroot`),
					regexp.MustCompile(`react(?:\.min)?\.js`),
				},
			},
			{
				Name:     "Vue.js",
				Category: "JavaScript Framework",
				BodyMatches: []*regexp.Regexp{
					regexp.MustCompile(`<div id="app"`),
					regexp.MustCompile(`vue(?:\.min)?\.js`),
				},
			},
			{
				Name:     "Angular",
				Category: "JavaScript Framework",
				BodyMatches: []*regexp.Regexp{
					regexp.MustCompile(`<app-root`),
					regexp.MustCompile(`ng-version="`),
				},
			},

			// CMS
			{
				Name:     "WordPress",
				Category: "CMS",
				BodyMatches: []*regexp.Regexp{
					regexp.MustCompile(`/wp-content/`),
					regexp.MustCompile(`/wp-includes/`),
					regexp.MustCompile(`<meta name="generator" content="WordPress`),
				},
				HeaderMatches: map[string]*regexp.Regexp{
					"x-powered-by": regexp.MustCompile(`(?i)wordpress`),
				},
			},
			{
				Name:     "Drupal",
				Category: "CMS",
				BodyMatches: []*regexp.Regexp{
					regexp.MustCompile(`/sites/default/files/`),
					regexp.MustCompile(`Drupal\.settings`),
				},
				HeaderMatches: map[string]*regexp.Regexp{
					"x-drupal-cache": regexp.MustCompile(`.+`),
				},
			},
			{
				Name:     "Joomla",
				Category: "CMS",
				BodyMatches: []*regexp.Regexp{
					regexp.MustCompile(`/components/com_`),
					regexp.MustCompile(`Joomla!`),
				},
			},

			// Programming Languages
			{
				Name:     "PHP",
				Category: "Programming Language",
				HeaderMatches: map[string]*regexp.Regexp{
					"x-powered-by": regexp.MustCompile(`(?i)php(?:/(\d+\.\d+(?:\.\d+)?))?`),
				},
				VersionRegex: regexp.MustCompile(`(\d+\.\d+(?:\.\d+)?)`),
			},
			{
				Name:     "ASP.NET",
				Category: "Programming Language",
				HeaderMatches: map[string]*regexp.Regexp{
					"x-powered-by":    regexp.MustCompile(`(?i)asp\.net`),
					"x-aspnet-version": regexp.MustCompile(`(\d+\.\d+(?:\.\d+)?)`),
				},
				VersionRegex: regexp.MustCompile(`(\d+\.\d+(?:\.\d+)?)`),
			},
		},
	}
}

// Detect analyzes headers and body content to identify technologies
func (d *TechDetector) Detect(headers http.Header, body string) []Technology {
	var technologies []Technology
	detected := make(map[string]bool) // Prevent duplicates

	for _, pattern := range d.patterns {
		tech := d.detectPattern(pattern, headers, body)
		if tech != nil && !detected[tech.Name] {
			technologies = append(technologies, *tech)
			detected[tech.Name] = true
		}
	}

	return technologies
}

// detectPattern checks if a specific pattern matches
func (d *TechDetector) detectPattern(pattern TechPattern, headers http.Header, body string) *Technology {
	var evidence []string
	var version string
	confidence := "low"

	// Check headers
	for headerName, regex := range pattern.HeaderMatches {
		headerValue := headers.Get(headerName)
		if headerValue != "" && regex.MatchString(headerValue) {
			evidence = append(evidence, "Header: "+headerName)
			confidence = "high"

			// Try to extract version
			if pattern.VersionRegex != nil {
				if matches := pattern.VersionRegex.FindStringSubmatch(headerValue); len(matches) > 1 {
					version = matches[1]
				}
			}
		}
	}

	// Check body patterns
	for _, regex := range pattern.BodyMatches {
		if regex.MatchString(body) {
			evidence = append(evidence, "HTML content")
			if confidence == "low" {
				confidence = "medium"
			}

			// Try to extract version from body if not found in headers
			if version == "" && pattern.VersionRegex != nil {
				if matches := pattern.VersionRegex.FindStringSubmatch(body); len(matches) > 1 {
					version = matches[1]
				}
			}
		}
	}

	// Return nil if no evidence found
	if len(evidence) == 0 {
		return nil
	}

	return &Technology{
		Name:       pattern.Name,
		Category:   pattern.Category,
		Version:    version,
		Confidence: confidence,
		Evidence:   evidence,
	}
}

// DetectFromHeaders detects technologies from headers only (used when body is not available)
func (d *TechDetector) DetectFromHeaders(headers http.Header) []Technology {
	return d.Detect(headers, "")
}