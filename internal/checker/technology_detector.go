package checker

import (
	"net/http"
	"regexp"
	"strings"
)

// TechnologyDetector detects web technologies and their security implications
type TechnologyDetector struct {
	patterns map[string]*TechDetectionPattern
}

// TechDetectionPattern defines patterns to detect a technology
type TechDetectionPattern struct {
	Name         string
	Category     string
	Headers      map[string]*regexp.Regexp
	HTML         []*regexp.Regexp
	Scripts      []*regexp.Regexp
	Meta         map[string]*regexp.Regexp
	Cookies      map[string]*regexp.Regexp
	SecurityInfo *SecurityInfo
}

// SecurityInfo contains security assessment for a technology
type SecurityInfo struct {
	RiskLevel        string   // "low", "medium", "high", "critical"
	CommonVulns      []string // Common vulnerabilities
	SecurityHeaders  []string // Headers this tech should set
	BestPractices    []string // Security best practices
	OutdatedVersions map[string]string // Version -> EOL date or security status
}

// NewTechnologyDetector creates a new technology detector
func NewTechnologyDetector() *TechnologyDetector {
	d := &TechnologyDetector{
		patterns: make(map[string]*TechDetectionPattern),
	}
	d.initializePatterns()
	return d
}

// initializePatterns sets up detection patterns for various technologies
func (d *TechnologyDetector) initializePatterns() {
	// CMS Detection
	d.patterns["wordpress"] = &TechDetectionPattern{
		Name:     "WordPress",
		Category: "CMS",
		HTML: []*regexp.Regexp{
			regexp.MustCompile(`<meta name="generator" content="WordPress`),
			regexp.MustCompile(`/wp-content/`),
			regexp.MustCompile(`/wp-includes/`),
			regexp.MustCompile(`/wp-json/`),
			regexp.MustCompile(`wordpress\.com/css/`),
		},
		Headers: map[string]*regexp.Regexp{
			"link":           regexp.MustCompile(`rel="https://api\.w\.org/"`),
			"x-powered-by":   regexp.MustCompile(`W3 Total Cache`),
		},
		SecurityInfo: &SecurityInfo{
			RiskLevel: "medium",
			CommonVulns: []string{
				"Plugin vulnerabilities",
				"Theme vulnerabilities",
				"XML-RPC attacks",
				"User enumeration",
				"Brute force attacks",
			},
			BestPractices: []string{
				"Keep WordPress core, themes, and plugins updated",
				"Disable XML-RPC if not needed",
				"Use security plugins (Wordfence, Sucuri)",
				"Implement strong password policies",
				"Limit login attempts",
				"Hide WordPress version",
			},
		},
	}

	d.patterns["drupal"] = &TechDetectionPattern{
		Name:     "Drupal",
		Category: "CMS",
		HTML: []*regexp.Regexp{
			regexp.MustCompile(`<meta name="generator" content="Drupal`),
			regexp.MustCompile(`/sites/default/files/`),
			regexp.MustCompile(`Drupal\.settings`),
			regexp.MustCompile(`data-drupal-`),
		},
		Headers: map[string]*regexp.Regexp{
			"x-drupal-cache":     regexp.MustCompile(`.+`),
			"x-drupal-dynamic-cache": regexp.MustCompile(`.+`),
		},
		SecurityInfo: &SecurityInfo{
			RiskLevel: "medium",
			CommonVulns: []string{
				"Drupalgeddon vulnerabilities",
				"Module vulnerabilities",
				"Access bypass issues",
			},
			BestPractices: []string{
				"Regular security updates",
				"Use Security Review module",
				"Implement proper access controls",
				"Enable database encryption",
			},
		},
	}

	d.patterns["joomla"] = &TechDetectionPattern{
		Name:     "Joomla",
		Category: "CMS",
		HTML: []*regexp.Regexp{
			regexp.MustCompile(`<meta name="generator" content="Joomla`),
			regexp.MustCompile(`/components/com_`),
			regexp.MustCompile(`/media/jui/`),
			regexp.MustCompile(`Joomla!`),
		},
		SecurityInfo: &SecurityInfo{
			RiskLevel: "medium",
			CommonVulns: []string{
				"Extension vulnerabilities",
				"SQL injection risks",
				"Privilege escalation",
			},
			BestPractices: []string{
				"Keep Joomla and extensions updated",
				"Use Admin Tools or similar security extensions",
				"Enable two-factor authentication",
			},
		},
	}

	// E-commerce Platforms
	d.patterns["shopify"] = &TechDetectionPattern{
		Name:     "Shopify",
		Category: "E-commerce",
		HTML: []*regexp.Regexp{
			regexp.MustCompile(`cdn\.shopify\.com`),
			regexp.MustCompile(`Shopify\.theme`),
			regexp.MustCompile(`shopify-assets`),
		},
		Headers: map[string]*regexp.Regexp{
			"x-shopify-stage": regexp.MustCompile(`.+`),
			"x-shopid":        regexp.MustCompile(`\d+`),
		},
		SecurityInfo: &SecurityInfo{
			RiskLevel: "low",
			CommonVulns: []string{
				"Third-party app vulnerabilities",
				"Misconfigured permissions",
			},
			BestPractices: []string{
				"Review app permissions carefully",
				"Use Shopify's built-in security features",
				"Enable two-factor authentication",
			},
		},
	}

	d.patterns["woocommerce"] = &TechDetectionPattern{
		Name:     "WooCommerce",
		Category: "E-commerce",
		HTML: []*regexp.Regexp{
			regexp.MustCompile(`woocommerce`),
			regexp.MustCompile(`class="woocommerce`),
			regexp.MustCompile(`WooCommerce`),
			regexp.MustCompile(`/wc-api/`),
		},
		SecurityInfo: &SecurityInfo{
			RiskLevel: "medium",
			CommonVulns: []string{
				"Payment gateway vulnerabilities",
				"Customer data exposure",
				"Plugin conflicts",
			},
			BestPractices: []string{
				"Use SSL for all transactions",
				"Regular security audits",
				"PCI compliance checks",
				"Secure payment gateway integration",
			},
		},
	}

	d.patterns["magento"] = &TechDetectionPattern{
		Name:     "Magento",
		Category: "E-commerce",
		HTML: []*regexp.Regexp{
			regexp.MustCompile(`Mage\.Cookies`),
			regexp.MustCompile(`/skin/frontend/`),
			regexp.MustCompile(`MAGE_MAGENTO`),
			regexp.MustCompile(`Magento`),
		},
		Cookies: map[string]*regexp.Regexp{
			"frontend": regexp.MustCompile(`.+`),
		},
		SecurityInfo: &SecurityInfo{
			RiskLevel: "high",
			CommonVulns: []string{
				"Known security patches required",
				"Admin panel vulnerabilities",
				"Credit card data theft risks",
				"Cryptojacking attacks",
			},
			BestPractices: []string{
				"Apply all security patches immediately",
				"Use Web Application Firewall",
				"Regular security scans",
				"Implement Content Security Policy",
				"Change default admin URL",
			},
		},
	}

	// Frameworks
	d.patterns["react"] = &TechDetectionPattern{
		Name:     "React",
		Category: "JavaScript Framework",
		HTML: []*regexp.Regexp{
			regexp.MustCompile(`data-reactroot`),
			regexp.MustCompile(`data-react-`),
			regexp.MustCompile(`_jsx`),
		},
		Scripts: []*regexp.Regexp{
			regexp.MustCompile(`react(?:\.min)?\.js`),
			regexp.MustCompile(`React\.createElement`),
		},
		SecurityInfo: &SecurityInfo{
			RiskLevel: "low",
			CommonVulns: []string{
				"XSS through dangerouslySetInnerHTML",
				"Component injection",
				"State manipulation",
			},
			BestPractices: []string{
				"Avoid dangerouslySetInnerHTML",
				"Validate all props",
				"Use Content Security Policy",
				"Keep React updated",
			},
		},
	}

	d.patterns["angular"] = &TechDetectionPattern{
		Name:     "Angular",
		Category: "JavaScript Framework",
		HTML: []*regexp.Regexp{
			regexp.MustCompile(`ng-app`),
			regexp.MustCompile(`data-ng-`),
			regexp.MustCompile(`ng-controller`),
			regexp.MustCompile(`\*ngIf`),
			regexp.MustCompile(`\*ngFor`),
		},
		Scripts: []*regexp.Regexp{
			regexp.MustCompile(`angular(?:\.min)?\.js`),
		},
		SecurityInfo: &SecurityInfo{
			RiskLevel: "low",
			CommonVulns: []string{
				"Template injection",
				"Open redirects",
				"CSRF vulnerabilities",
			},
			BestPractices: []string{
				"Use Angular's built-in sanitization",
				"Implement proper CSRF protection",
				"Keep Angular CLI updated",
				"Use strict CSP",
			},
		},
	}

	d.patterns["vue"] = &TechDetectionPattern{
		Name:     "Vue.js",
		Category: "JavaScript Framework",
		HTML: []*regexp.Regexp{
			regexp.MustCompile(`v-for=`),
			regexp.MustCompile(`v-if=`),
			regexp.MustCompile(`v-model=`),
			regexp.MustCompile(`<div id="app"`),
		},
		Scripts: []*regexp.Regexp{
			regexp.MustCompile(`vue(?:\.min)?\.js`),
		},
		SecurityInfo: &SecurityInfo{
			RiskLevel: "low",
			CommonVulns: []string{
				"XSS through v-html",
				"Template compilation risks",
			},
			BestPractices: []string{
				"Avoid v-html with user input",
				"Use computed properties for complex logic",
				"Implement proper input validation",
			},
		},
	}

	// Web Servers
	d.patterns["nginx"] = &TechDetectionPattern{
		Name:     "nginx",
		Category: "Web Server",
		Headers: map[string]*regexp.Regexp{
			"server": regexp.MustCompile(`nginx`),
		},
		SecurityInfo: &SecurityInfo{
			RiskLevel: "low",
			CommonVulns: []string{
				"Misconfiguration issues",
				"Directory traversal",
				"Buffer overflow in old versions",
			},
			BestPractices: []string{
				"Hide version numbers",
				"Implement rate limiting",
				"Use SSL/TLS properly",
				"Restrict access to sensitive directories",
				"Keep nginx updated",
			},
		},
	}

	d.patterns["apache"] = &TechDetectionPattern{
		Name:     "Apache",
		Category: "Web Server",
		Headers: map[string]*regexp.Regexp{
			"server": regexp.MustCompile(`Apache`),
		},
		SecurityInfo: &SecurityInfo{
			RiskLevel: "low",
			CommonVulns: []string{
				".htaccess misconfigurations",
				"mod_security bypasses",
				"Directory listing exposure",
			},
			BestPractices: []string{
				"Disable directory listing",
				"Use mod_security",
				"Implement proper .htaccess rules",
				"Keep Apache updated",
				"Hide version information",
			},
		},
	}

	// Databases
	d.patterns["mysql"] = &TechDetectionPattern{
		Name:     "MySQL",
		Category: "Database",
		Headers: map[string]*regexp.Regexp{
			"x-powered-by": regexp.MustCompile(`MySQL`),
		},
		HTML: []*regexp.Regexp{
			regexp.MustCompile(`MySQL`),
			regexp.MustCompile(`mysql_`),
		},
		SecurityInfo: &SecurityInfo{
			RiskLevel: "medium",
			CommonVulns: []string{
				"SQL injection",
				"Weak authentication",
				"Privilege escalation",
			},
			BestPractices: []string{
				"Use prepared statements",
				"Implement least privilege principle",
				"Enable SSL for connections",
				"Regular security updates",
			},
		},
	}

	d.patterns["mongodb"] = &TechDetectionPattern{
		Name:     "MongoDB",
		Category: "Database",
		HTML: []*regexp.Regexp{
			regexp.MustCompile(`mongodb`),
			regexp.MustCompile(`mongoose`),
		},
		SecurityInfo: &SecurityInfo{
			RiskLevel: "medium",
			CommonVulns: []string{
				"NoSQL injection",
				"Unauthorized access",
				"Data exposure",
			},
			BestPractices: []string{
				"Enable authentication",
				"Use encryption at rest",
				"Implement proper access controls",
				"Regular backups",
			},
		},
	}

	// CDN and Hosting
	d.patterns["cloudflare"] = &TechDetectionPattern{
		Name:     "Cloudflare",
		Category: "CDN",
		Headers: map[string]*regexp.Regexp{
			"cf-ray":    regexp.MustCompile(`.+`),
			"cf-cache-status": regexp.MustCompile(`.+`),
			"server":    regexp.MustCompile(`cloudflare`),
		},
		SecurityInfo: &SecurityInfo{
			RiskLevel: "low",
			CommonVulns: []string{
				"Cache poisoning",
				"Bypass techniques",
			},
			BestPractices: []string{
				"Enable WAF rules",
				"Use rate limiting",
				"Implement DDoS protection",
				"Enable DNSSEC",
			},
		},
	}

	d.patterns["aws"] = &TechDetectionPattern{
		Name:     "Amazon Web Services",
		Category: "Cloud Platform",
		Headers: map[string]*regexp.Regexp{
			"x-amz-request-id": regexp.MustCompile(`.+`),
			"x-amz-id-2":       regexp.MustCompile(`.+`),
		},
		HTML: []*regexp.Regexp{
			regexp.MustCompile(`amazonaws\.com`),
			regexp.MustCompile(`aws-cdn`),
		},
		SecurityInfo: &SecurityInfo{
			RiskLevel: "low",
			CommonVulns: []string{
				"S3 bucket misconfiguration",
				"IAM permission issues",
				"Exposed credentials",
			},
			BestPractices: []string{
				"Use IAM roles properly",
				"Enable MFA",
				"Encrypt data at rest",
				"Regular security audits",
				"Use AWS WAF",
			},
		},
	}

	// Security Tools
	d.patterns["recaptcha"] = &TechDetectionPattern{
		Name:     "reCAPTCHA",
		Category: "Security",
		HTML: []*regexp.Regexp{
			regexp.MustCompile(`google\.com/recaptcha`),
			regexp.MustCompile(`g-recaptcha`),
			regexp.MustCompile(`grecaptcha`),
		},
		SecurityInfo: &SecurityInfo{
			RiskLevel: "low",
			CommonVulns: []string{
				"Bypass attempts",
				"Implementation flaws",
			},
			BestPractices: []string{
				"Implement server-side validation",
				"Use latest version (v3)",
				"Monitor for suspicious patterns",
			},
		},
	}

	// Container/Orchestration
	d.patterns["docker"] = &TechDetectionPattern{
		Name:     "Docker",
		Category: "Container",
		Headers: map[string]*regexp.Regexp{
			"x-docker-registry": regexp.MustCompile(`.+`),
		},
		SecurityInfo: &SecurityInfo{
			RiskLevel: "medium",
			CommonVulns: []string{
				"Container escape",
				"Exposed Docker daemon",
				"Vulnerable base images",
			},
			BestPractices: []string{
				"Use minimal base images",
				"Scan for vulnerabilities",
				"Don't run as root",
				"Use secrets management",
			},
		},
	}

	d.patterns["kubernetes"] = &TechDetectionPattern{
		Name:     "Kubernetes",
		Category: "Orchestration",
		Headers: map[string]*regexp.Regexp{
			"x-kubernetes-pf": regexp.MustCompile(`.+`),
		},
		SecurityInfo: &SecurityInfo{
			RiskLevel: "medium",
			CommonVulns: []string{
				"RBAC misconfigurations",
				"Exposed dashboard",
				"Secrets management issues",
			},
			BestPractices: []string{
				"Implement network policies",
				"Use RBAC properly",
				"Enable audit logging",
				"Regular security scans",
			},
		},
	}

	// Programming Languages
	d.patterns["php"] = &TechDetectionPattern{
		Name:     "PHP",
		Category: "Programming Language",
		Headers: map[string]*regexp.Regexp{
			"x-powered-by": regexp.MustCompile(`PHP`),
		},
		Cookies: map[string]*regexp.Regexp{
			"phpsessid": regexp.MustCompile(`.+`),
		},
		SecurityInfo: &SecurityInfo{
			RiskLevel: "medium",
			CommonVulns: []string{
				"Remote code execution",
				"File inclusion vulnerabilities",
				"Session hijacking",
			},
			BestPractices: []string{
				"Hide PHP version",
				"Disable dangerous functions",
				"Use prepared statements",
				"Keep PHP updated",
			},
		},
	}

	d.patterns["aspnet"] = &TechDetectionPattern{
		Name:     "ASP.NET",
		Category: "Programming Language",
		Headers: map[string]*regexp.Regexp{
			"x-powered-by":    regexp.MustCompile(`ASP\.NET`),
			"x-aspnet-version": regexp.MustCompile(`.+`),
		},
		SecurityInfo: &SecurityInfo{
			RiskLevel: "low",
			CommonVulns: []string{
				"ViewState tampering",
				"Authentication bypass",
				"XXE vulnerabilities",
			},
			BestPractices: []string{
				"Use latest .NET version",
				"Implement proper authentication",
				"Enable request validation",
				"Use anti-CSRF tokens",
			},
		},
	}

	// Additional Technologies
	d.patterns["jquery"] = &TechDetectionPattern{
		Name:     "jQuery",
		Category: "JavaScript Library",
		Scripts: []*regexp.Regexp{
			regexp.MustCompile(`jquery(?:\.min)?\.js`),
			regexp.MustCompile(`\$\(document\)\.ready`),
			regexp.MustCompile(`jQuery\(`),
		},
		SecurityInfo: &SecurityInfo{
			RiskLevel: "low",
			CommonVulns: []string{
				"XSS in older versions",
				"Prototype pollution",
			},
			BestPractices: []string{
				"Use latest version",
				"Avoid using .html() with user input",
				"Validate all inputs",
			},
		},
	}

	d.patterns["bootstrap"] = &TechDetectionPattern{
		Name:     "Bootstrap",
		Category: "CSS Framework",
		HTML: []*regexp.Regexp{
			regexp.MustCompile(`bootstrap(?:\.min)?\.css`),
			regexp.MustCompile(`class="[^"]*\b(?:container|row|col-)`),
			regexp.MustCompile(`class="[^"]*\bbtn\b`),
		},
		SecurityInfo: &SecurityInfo{
			RiskLevel: "low",
			CommonVulns: []string{
				"XSS in tooltips/popovers",
			},
			BestPractices: []string{
				"Sanitize dynamic content",
				"Use latest version",
			},
		},
	}

	d.patterns["laravel"] = &TechDetectionPattern{
		Name:     "Laravel",
		Category: "PHP Framework",
		Cookies: map[string]*regexp.Regexp{
			"laravel_session": regexp.MustCompile(`.+`),
		},
		Headers: map[string]*regexp.Regexp{
			"x-csrf-token": regexp.MustCompile(`.+`),
		},
		SecurityInfo: &SecurityInfo{
			RiskLevel: "low",
			CommonVulns: []string{
				"Mass assignment",
				"SQL injection if raw queries used",
				"Debug mode exposure",
			},
			BestPractices: []string{
				"Disable debug in production",
				"Use Eloquent ORM properly",
				"Implement rate limiting",
				"Keep Laravel updated",
			},
		},
	}

	// Additional Web Servers
	d.patterns["iis"] = &TechDetectionPattern{
		Name:     "IIS",
		Category: "Web Server",
		Headers: map[string]*regexp.Regexp{
			"server": regexp.MustCompile(`(?i)microsoft-iis`),
		},
		SecurityInfo: &SecurityInfo{
			RiskLevel: "low",
			CommonVulns: []string{
				"Directory traversal",
				"IIS Short Name vulnerability",
				"HTTP.sys vulnerabilities",
			},
			BestPractices: []string{
				"Keep Windows and IIS updated",
				"Disable unnecessary modules",
				"Use URL Rewrite module properly",
				"Implement proper access controls",
			},
		},
	}

	d.patterns["lighttpd"] = &TechDetectionPattern{
		Name:     "lighttpd",
		Category: "Web Server",
		Headers: map[string]*regexp.Regexp{
			"server": regexp.MustCompile(`(?i)lighttpd`),
		},
		SecurityInfo: &SecurityInfo{
			RiskLevel: "low",
			BestPractices: []string{
				"Keep lighttpd updated",
				"Configure SSL/TLS properly",
				"Use mod_security if available",
			},
		},
	}

	d.patterns["caddy"] = &TechDetectionPattern{
		Name:     "Caddy",
		Category: "Web Server",
		Headers: map[string]*regexp.Regexp{
			"server": regexp.MustCompile(`(?i)caddy`),
		},
		SecurityInfo: &SecurityInfo{
			RiskLevel: "low",
			BestPractices: []string{
				"Automatic HTTPS is enabled by default",
				"Keep Caddy updated",
				"Review Caddyfile configuration",
			},
		},
	}

	// Additional CDN Providers
	d.patterns["fastly"] = &TechDetectionPattern{
		Name:     "Fastly",
		Category: "CDN",
		Headers: map[string]*regexp.Regexp{
			"x-served-by": regexp.MustCompile(`(?i)cache-`),
			"x-fastly":    regexp.MustCompile(`.+`),
			"x-timer":     regexp.MustCompile(`.+`),
		},
		SecurityInfo: &SecurityInfo{
			RiskLevel: "low",
			BestPractices: []string{
				"Configure proper cache rules",
				"Use VCL for custom logic",
				"Enable WAF features",
			},
		},
	}

	d.patterns["cloudfront"] = &TechDetectionPattern{
		Name:     "Amazon CloudFront",
		Category: "CDN",
		Headers: map[string]*regexp.Regexp{
			"via":             regexp.MustCompile(`(?i)cloudfront`),
			"x-amz-cf-id":     regexp.MustCompile(`.+`),
			"x-amz-cf-pop":    regexp.MustCompile(`.+`),
		},
		SecurityInfo: &SecurityInfo{
			RiskLevel: "low",
			BestPractices: []string{
				"Use Origin Access Identity",
				"Enable field-level encryption",
				"Configure WAF rules",
				"Use signed URLs for restricted content",
			},
		},
	}

	d.patterns["akamai"] = &TechDetectionPattern{
		Name:     "Akamai",
		Category: "CDN",
		Headers: map[string]*regexp.Regexp{
			"x-akamai-request-id": regexp.MustCompile(`.+`),
			"akamai-grn":          regexp.MustCompile(`.+`),
		},
		SecurityInfo: &SecurityInfo{
			RiskLevel: "low",
			BestPractices: []string{
				"Use Kona Site Defender for security",
				"Enable bot management",
				"Configure proper cache policies",
			},
		},
	}

	d.patterns["azurecdn"] = &TechDetectionPattern{
		Name:     "Azure CDN",
		Category: "CDN",
		Headers: map[string]*regexp.Regexp{
			"x-ec-debug": regexp.MustCompile(`.+`),
			"x-cache":    regexp.MustCompile(`(?i).*azure.*`),
		},
		SecurityInfo: &SecurityInfo{
			RiskLevel: "low",
			BestPractices: []string{
				"Use Azure Front Door for enhanced security",
				"Enable HTTPS everywhere",
				"Configure custom rules",
			},
		},
	}

	// Modern Hosting Platforms
	d.patterns["vercel"] = &TechDetectionPattern{
		Name:     "Vercel",
		Category: "Hosting Platform",
		Headers: map[string]*regexp.Regexp{
			"x-vercel-id":    regexp.MustCompile(`.+`),
			"x-vercel-cache": regexp.MustCompile(`.+`),
			"server":         regexp.MustCompile(`(?i)vercel`),
		},
		SecurityInfo: &SecurityInfo{
			RiskLevel: "low",
			BestPractices: []string{
				"Use environment variables for secrets",
				"Enable Edge Functions security",
				"Configure proper CORS headers",
			},
		},
	}

	d.patterns["netlify"] = &TechDetectionPattern{
		Name:     "Netlify",
		Category: "Hosting Platform",
		Headers: map[string]*regexp.Regexp{
			"x-nf-request-id": regexp.MustCompile(`.+`),
			"server":          regexp.MustCompile(`(?i)netlify`),
		},
		SecurityInfo: &SecurityInfo{
			RiskLevel: "low",
			BestPractices: []string{
				"Use Netlify Identity for auth",
				"Configure proper redirects",
				"Use environment variables",
			},
		},
	}

	d.patterns["githubpages"] = &TechDetectionPattern{
		Name:     "GitHub Pages",
		Category: "Hosting Platform",
		Headers: map[string]*regexp.Regexp{
			"x-github-request-id": regexp.MustCompile(`.+`),
			"server":              regexp.MustCompile(`(?i)github\.com`),
		},
		HTML: []*regexp.Regexp{
			regexp.MustCompile(`\.github\.io`),
		},
		SecurityInfo: &SecurityInfo{
			RiskLevel: "low",
			BestPractices: []string{
				"Use HTTPS (automatic)",
				"No server-side code execution",
				"Keep dependencies updated",
			},
		},
	}

	d.patterns["heroku"] = &TechDetectionPattern{
		Name:     "Heroku",
		Category: "Hosting Platform",
		Headers: map[string]*regexp.Regexp{
			"via": regexp.MustCompile(`(?i)vegur`),
		},
		SecurityInfo: &SecurityInfo{
			RiskLevel: "low",
			BestPractices: []string{
				"Use Heroku's SSL certificates",
				"Enable automatic security updates",
				"Use config vars for secrets",
				"Monitor with Heroku metrics",
			},
		},
	}

	d.patterns["railway"] = &TechDetectionPattern{
		Name:     "Railway",
		Category: "Hosting Platform",
		Headers: map[string]*regexp.Regexp{
			"x-railway-id": regexp.MustCompile(`.+`),
		},
		SecurityInfo: &SecurityInfo{
			RiskLevel: "low",
			BestPractices: []string{
				"Use private networking",
				"Secure environment variables",
				"Enable healthchecks",
			},
		},
	}

	d.patterns["render"] = &TechDetectionPattern{
		Name:     "Render",
		Category: "Hosting Platform",
		Headers: map[string]*regexp.Regexp{
			"x-render-id": regexp.MustCompile(`.+`),
		},
		SecurityInfo: &SecurityInfo{
			RiskLevel: "low",
			BestPractices: []string{
				"Use private services when needed",
				"Configure proper health checks",
				"Enable auto-deploy from Git",
			},
		},
	}

	// Modern JavaScript Frameworks
	d.patterns["nextjs"] = &TechDetectionPattern{
		Name:     "Next.js",
		Category: "JavaScript Framework",
		HTML: []*regexp.Regexp{
			regexp.MustCompile(`<div id="__next"`),
			regexp.MustCompile(`/_next/static/`),
			regexp.MustCompile(`__NEXT_DATA__`),
		},
		Scripts: []*regexp.Regexp{
			regexp.MustCompile(`/_next/static/chunks/`),
		},
		SecurityInfo: &SecurityInfo{
			RiskLevel: "low",
			CommonVulns: []string{
				"Server-side XSS",
				"API route vulnerabilities",
				"Environment variable exposure",
			},
			BestPractices: []string{
				"Use Next.js Security Headers",
				"Sanitize user inputs",
				"Use environment variables properly",
				"Keep Next.js updated",
				"Implement CSP",
			},
		},
	}

	d.patterns["nuxt"] = &TechDetectionPattern{
		Name:     "Nuxt.js",
		Category: "JavaScript Framework",
		HTML: []*regexp.Regexp{
			regexp.MustCompile(`<div id="__nuxt"`),
			regexp.MustCompile(`__NUXT__`),
		},
		SecurityInfo: &SecurityInfo{
			RiskLevel: "low",
			BestPractices: []string{
				"Use Nuxt security module",
				"Configure proper CSP",
				"Sanitize user inputs",
			},
		},
	}

	d.patterns["gatsby"] = &TechDetectionPattern{
		Name:     "Gatsby",
		Category: "Static Site Generator",
		HTML: []*regexp.Regexp{
			regexp.MustCompile(`gatsby-focus-wrapper`),
			regexp.MustCompile(`___gatsby`),
		},
		SecurityInfo: &SecurityInfo{
			RiskLevel: "low",
			BestPractices: []string{
				"Keep Gatsby plugins updated",
				"Use gatsby-plugin-csp",
				"Sanitize GraphQL queries",
			},
		},
	}

	d.patterns["svelte"] = &TechDetectionPattern{
		Name:     "Svelte",
		Category: "JavaScript Framework",
		HTML: []*regexp.Regexp{
			regexp.MustCompile(`svelte-`),
		},
		Scripts: []*regexp.Regexp{
			regexp.MustCompile(`svelte`),
		},
		SecurityInfo: &SecurityInfo{
			RiskLevel: "low",
			BestPractices: []string{
				"Sanitize HTML content",
				"Use @html directive carefully",
				"Keep dependencies updated",
			},
		},
	}

	d.patterns["sveltekit"] = &TechDetectionPattern{
		Name:     "SvelteKit",
		Category: "JavaScript Framework",
		HTML: []*regexp.Regexp{
			regexp.MustCompile(`sveltekit:`),
		},
		SecurityInfo: &SecurityInfo{
			RiskLevel: "low",
			BestPractices: []string{
				"Use CSRF protection",
				"Sanitize inputs",
				"Configure proper CSP",
			},
		},
	}

	d.patterns["remix"] = &TechDetectionPattern{
		Name:     "Remix",
		Category: "JavaScript Framework",
		HTML: []*regexp.Regexp{
			regexp.MustCompile(`__remixContext`),
		},
		SecurityInfo: &SecurityInfo{
			RiskLevel: "low",
			BestPractices: []string{
				"Use CSRF tokens",
				"Validate form inputs",
				"Implement proper auth",
			},
		},
	}

	d.patterns["astro"] = &TechDetectionPattern{
		Name:     "Astro",
		Category: "Static Site Generator",
		HTML: []*regexp.Regexp{
			regexp.MustCompile(`astro-`),
		},
		SecurityInfo: &SecurityInfo{
			RiskLevel: "low",
			BestPractices: []string{
				"Keep Astro updated",
				"Sanitize dynamic content",
				"Use proper CSP",
			},
		},
	}

	d.patterns["solidjs"] = &TechDetectionPattern{
		Name:     "SolidJS",
		Category: "JavaScript Framework",
		HTML: []*regexp.Regexp{
			regexp.MustCompile(`_\$`),
		},
		Scripts: []*regexp.Regexp{
			regexp.MustCompile(`solid-js`),
		},
		SecurityInfo: &SecurityInfo{
			RiskLevel: "low",
			BestPractices: []string{
				"Sanitize innerHTML",
				"Use proper CSP",
				"Keep dependencies updated",
			},
		},
	}

	// CMS Platforms
	d.patterns["ghost"] = &TechDetectionPattern{
		Name:     "Ghost",
		Category: "CMS",
		HTML: []*regexp.Regexp{
			regexp.MustCompile(`<meta name="generator" content="Ghost`),
			regexp.MustCompile(`/ghost/api/`),
		},
		SecurityInfo: &SecurityInfo{
			RiskLevel: "low",
			BestPractices: []string{
				"Keep Ghost updated",
				"Use strong admin passwords",
				"Enable 2FA",
				"Use SSL/TLS",
			},
		},
	}

	d.patterns["strapi"] = &TechDetectionPattern{
		Name:     "Strapi",
		Category: "Headless CMS",
		HTML: []*regexp.Regexp{
			regexp.MustCompile(`/strapi/`),
		},
		Headers: map[string]*regexp.Regexp{
			"x-powered-by": regexp.MustCompile(`(?i)strapi`),
		},
		SecurityInfo: &SecurityInfo{
			RiskLevel: "medium",
			CommonVulns: []string{
				"API endpoint exposure",
				"Authentication bypass",
				"Plugin vulnerabilities",
			},
			BestPractices: []string{
				"Configure proper CORS",
				"Use strong API tokens",
				"Keep Strapi and plugins updated",
				"Implement rate limiting",
			},
		},
	}

	d.patterns["contentful"] = &TechDetectionPattern{
		Name:     "Contentful",
		Category: "Headless CMS",
		HTML: []*regexp.Regexp{
			regexp.MustCompile(`cdn\.contentful\.com`),
			regexp.MustCompile(`contentful`),
		},
		SecurityInfo: &SecurityInfo{
			RiskLevel: "low",
			BestPractices: []string{
				"Use delivery tokens properly",
				"Don't expose management tokens",
				"Implement proper access controls",
			},
		},
	}

	d.patterns["sanity"] = &TechDetectionPattern{
		Name:     "Sanity",
		Category: "Headless CMS",
		HTML: []*regexp.Regexp{
			regexp.MustCompile(`cdn\.sanity\.io`),
			regexp.MustCompile(`sanity`),
		},
		SecurityInfo: &SecurityInfo{
			RiskLevel: "low",
			BestPractices: []string{
				"Use proper token scopes",
				"Enable CORS correctly",
				"Monitor API usage",
			},
		},
	}

	// Additional E-commerce
	d.patterns["bigcommerce"] = &TechDetectionPattern{
		Name:     "BigCommerce",
		Category: "E-commerce",
		HTML: []*regexp.Regexp{
			regexp.MustCompile(`bigcommerce`),
			regexp.MustCompile(`cdn\d+\.bigcommerce\.com`),
		},
		SecurityInfo: &SecurityInfo{
			RiskLevel: "low",
			BestPractices: []string{
				"Use HTTPS everywhere",
				"Keep themes updated",
				"Review app permissions",
			},
		},
	}

	d.patterns["prestashop"] = &TechDetectionPattern{
		Name:     "PrestaShop",
		Category: "E-commerce",
		HTML: []*regexp.Regexp{
			regexp.MustCompile(`PrestaShop`),
			regexp.MustCompile(`/modules/`),
		},
		SecurityInfo: &SecurityInfo{
			RiskLevel: "medium",
			CommonVulns: []string{
				"Module vulnerabilities",
				"SQL injection",
				"XSS vulnerabilities",
			},
			BestPractices: []string{
				"Keep PrestaShop updated",
				"Review module security",
				"Use SSL for transactions",
			},
		},
	}

	d.patterns["opencart"] = &TechDetectionPattern{
		Name:     "OpenCart",
		Category: "E-commerce",
		HTML: []*regexp.Regexp{
			regexp.MustCompile(`OpenCart`),
			regexp.MustCompile(`route=`),
		},
		Cookies: map[string]*regexp.Regexp{
			"ocsid": regexp.MustCompile(`.+`),
		},
		SecurityInfo: &SecurityInfo{
			RiskLevel: "medium",
			CommonVulns: []string{
				"Extension vulnerabilities",
				"File upload issues",
				"SQL injection",
			},
			BestPractices: []string{
				"Keep OpenCart updated",
				"Review extensions carefully",
				"Use security extensions",
			},
		},
	}

	// Analytics and Tracking
	d.patterns["googleanalytics"] = &TechDetectionPattern{
		Name:     "Google Analytics",
		Category: "Analytics",
		Scripts: []*regexp.Regexp{
			regexp.MustCompile(`google-analytics\.com/analytics\.js`),
			regexp.MustCompile(`googletagmanager\.com/gtag/js`),
			regexp.MustCompile(`UA-\d+-\d+`),
			regexp.MustCompile(`G-[A-Z0-9]+`),
		},
		HTML: []*regexp.Regexp{
			regexp.MustCompile(`gtag\(`),
		},
		SecurityInfo: &SecurityInfo{
			RiskLevel: "low",
			BestPractices: []string{
				"Anonymize IP addresses",
				"Configure data retention",
				"Comply with privacy regulations",
			},
		},
	}

	d.patterns["googletagmanager"] = &TechDetectionPattern{
		Name:     "Google Tag Manager",
		Category: "Tag Management",
		Scripts: []*regexp.Regexp{
			regexp.MustCompile(`googletagmanager\.com/gtm\.js`),
			regexp.MustCompile(`GTM-[A-Z0-9]+`),
		},
		SecurityInfo: &SecurityInfo{
			RiskLevel: "low",
			CommonVulns: []string{
				"Third-party script injection",
				"Data leakage through tags",
			},
			BestPractices: []string{
				"Review all tags regularly",
				"Limit container access",
				"Use allowlist for JavaScript variables",
			},
		},
	}

	d.patterns["segment"] = &TechDetectionPattern{
		Name:     "Segment",
		Category: "Analytics",
		Scripts: []*regexp.Regexp{
			regexp.MustCompile(`cdn\.segment\.com`),
			regexp.MustCompile(`analytics\.js`),
		},
		SecurityInfo: &SecurityInfo{
			RiskLevel: "low",
			BestPractices: []string{
				"Use proper write keys",
				"Implement privacy controls",
				"Monitor data flows",
			},
		},
	}

	d.patterns["mixpanel"] = &TechDetectionPattern{
		Name:     "Mixpanel",
		Category: "Analytics",
		Scripts: []*regexp.Regexp{
			regexp.MustCompile(`cdn\.mxpnl\.com`),
			regexp.MustCompile(`mixpanel`),
		},
		SecurityInfo: &SecurityInfo{
			RiskLevel: "low",
			BestPractices: []string{
				"Don't track PII without consent",
				"Use proper token scopes",
				"Configure data retention",
			},
		},
	}

	d.patterns["hotjar"] = &TechDetectionPattern{
		Name:     "Hotjar",
		Category: "Analytics",
		Scripts: []*regexp.Regexp{
			regexp.MustCompile(`static\.hotjar\.com`),
			regexp.MustCompile(`hjid`),
		},
		SecurityInfo: &SecurityInfo{
			RiskLevel: "low",
			CommonVulns: []string{
				"Session recording privacy concerns",
				"PII in recordings",
			},
			BestPractices: []string{
				"Suppress sensitive data",
				"Review recording settings",
				"Comply with privacy laws",
			},
		},
	}

	// Monitoring and Error Tracking
	d.patterns["sentry"] = &TechDetectionPattern{
		Name:     "Sentry",
		Category: "Error Tracking",
		Scripts: []*regexp.Regexp{
			regexp.MustCompile(`browser\.sentry-cdn\.com`),
			regexp.MustCompile(`@sentry/`),
		},
		SecurityInfo: &SecurityInfo{
			RiskLevel: "low",
			CommonVulns: []string{
				"Source map exposure",
				"Sensitive data in error logs",
			},
			BestPractices: []string{
				"Filter sensitive data",
				"Use proper DSN security",
				"Enable release tracking",
				"Don't expose source maps publicly",
			},
		},
	}

	d.patterns["newrelic"] = &TechDetectionPattern{
		Name:     "New Relic",
		Category: "Monitoring",
		Scripts: []*regexp.Regexp{
			regexp.MustCompile(`js-agent\.newrelic\.com`),
			regexp.MustCompile(`NREUM`),
		},
		SecurityInfo: &SecurityInfo{
			RiskLevel: "low",
			BestPractices: []string{
				"Secure your license key",
				"Configure data collection properly",
				"Monitor for anomalies",
			},
		},
	}

	d.patterns["datadog"] = &TechDetectionPattern{
		Name:     "Datadog",
		Category: "Monitoring",
		Scripts: []*regexp.Regexp{
			regexp.MustCompile(`datadoghq\.com`),
			regexp.MustCompile(`DD_RUM`),
		},
		SecurityInfo: &SecurityInfo{
			RiskLevel: "low",
			BestPractices: []string{
				"Protect API keys",
				"Configure proper access controls",
				"Monitor security events",
			},
		},
	}

	// Additional JavaScript Libraries
	d.patterns["lodash"] = &TechDetectionPattern{
		Name:     "Lodash",
		Category: "JavaScript Library",
		Scripts: []*regexp.Regexp{
			regexp.MustCompile(`lodash(?:\.min)?\.js`),
		},
		SecurityInfo: &SecurityInfo{
			RiskLevel: "low",
			CommonVulns: []string{
				"Prototype pollution (older versions)",
			},
			BestPractices: []string{
				"Use latest version (4.17.21+)",
				"Avoid using vulnerable functions",
			},
		},
	}

	d.patterns["momentjs"] = &TechDetectionPattern{
		Name:     "Moment.js",
		Category: "JavaScript Library",
		Scripts: []*regexp.Regexp{
			regexp.MustCompile(`moment(?:\.min)?\.js`),
		},
		SecurityInfo: &SecurityInfo{
			RiskLevel: "low",
			BestPractices: []string{
				"Consider migrating to Day.js or date-fns (Moment.js is deprecated)",
				"Keep updated if still using",
			},
		},
	}

	d.patterns["axios"] = &TechDetectionPattern{
		Name:     "Axios",
		Category: "JavaScript Library",
		Scripts: []*regexp.Regexp{
			regexp.MustCompile(`axios(?:\.min)?\.js`),
		},
		SecurityInfo: &SecurityInfo{
			RiskLevel: "low",
			BestPractices: []string{
				"Validate responses",
				"Use HTTPS",
				"Keep Axios updated",
			},
		},
	}

	d.patterns["threejs"] = &TechDetectionPattern{
		Name:     "Three.js",
		Category: "JavaScript Library",
		Scripts: []*regexp.Regexp{
			regexp.MustCompile(`three(?:\.min)?\.js`),
		},
		SecurityInfo: &SecurityInfo{
			RiskLevel: "low",
			BestPractices: []string{
				"Validate 3D model files",
				"Sanitize user-uploaded models",
			},
		},
	}

	d.patterns["d3"] = &TechDetectionPattern{
		Name:     "D3.js",
		Category: "JavaScript Library",
		Scripts: []*regexp.Regexp{
			regexp.MustCompile(`d3(?:\.min)?\.js`),
		},
		SecurityInfo: &SecurityInfo{
			RiskLevel: "low",
			CommonVulns: []string{
				"XSS through data visualization",
			},
			BestPractices: []string{
				"Sanitize data before rendering",
				"Use .text() instead of .html() when possible",
			},
		},
	}

	// Additional CSS Frameworks
	d.patterns["tailwindcss"] = &TechDetectionPattern{
		Name:     "Tailwind CSS",
		Category: "CSS Framework",
		HTML: []*regexp.Regexp{
			regexp.MustCompile(`class="[^"]*\b(?:flex|grid|hidden|block|text-|bg-|p-|m-|w-|h-)`),
		},
		SecurityInfo: &SecurityInfo{
			RiskLevel: "low",
			BestPractices: []string{
				"Use PurgeCSS to remove unused styles",
				"Keep Tailwind updated",
			},
		},
	}

	d.patterns["materialui"] = &TechDetectionPattern{
		Name:     "Material-UI",
		Category: "UI Framework",
		HTML: []*regexp.Regexp{
			regexp.MustCompile(`class="[^"]*\bMui[A-Z]`),
		},
		Scripts: []*regexp.Regexp{
			regexp.MustCompile(`@material-ui/`),
			regexp.MustCompile(`@mui/`),
		},
		SecurityInfo: &SecurityInfo{
			RiskLevel: "low",
			BestPractices: []string{
				"Keep MUI updated",
				"Sanitize user inputs in components",
			},
		},
	}

	d.patterns["bulma"] = &TechDetectionPattern{
		Name:     "Bulma",
		Category: "CSS Framework",
		HTML: []*regexp.Regexp{
			regexp.MustCompile(`bulma(?:\.min)?\.css`),
			regexp.MustCompile(`class="[^"]*\b(?:hero|navbar|card|panel|modal)\b`),
		},
		SecurityInfo: &SecurityInfo{
			RiskLevel: "low",
			BestPractices: []string{
				"Keep Bulma updated",
				"Sanitize dynamic content",
			},
		},
	}

	d.patterns["foundation"] = &TechDetectionPattern{
		Name:     "Foundation",
		Category: "CSS Framework",
		HTML: []*regexp.Regexp{
			regexp.MustCompile(`foundation(?:\.min)?\.css`),
			regexp.MustCompile(`class="[^"]*\b(?:row|columns|orbit|reveal)\b`),
		},
		SecurityInfo: &SecurityInfo{
			RiskLevel: "low",
			BestPractices: []string{
				"Keep Foundation updated",
				"Use latest version",
			},
		},
	}

	// Payment Processors
	d.patterns["stripe"] = &TechDetectionPattern{
		Name:     "Stripe",
		Category: "Payment Processor",
		Scripts: []*regexp.Regexp{
			regexp.MustCompile(`js\.stripe\.com`),
			regexp.MustCompile(`Stripe\(`),
		},
		SecurityInfo: &SecurityInfo{
			RiskLevel: "medium",
			CommonVulns: []string{
				"API key exposure",
				"PCI compliance issues",
			},
			BestPractices: []string{
				"Never expose secret keys",
				"Use Stripe.js for card handling",
				"Implement SCA properly",
				"Use webhooks securely",
				"Keep Stripe.js updated",
			},
		},
	}

	d.patterns["paypal"] = &TechDetectionPattern{
		Name:     "PayPal",
		Category: "Payment Processor",
		Scripts: []*regexp.Regexp{
			regexp.MustCompile(`paypal\.com/sdk/js`),
			regexp.MustCompile(`paypal\.Buttons`),
		},
		SecurityInfo: &SecurityInfo{
			RiskLevel: "medium",
			BestPractices: []string{
				"Validate webhook signatures",
				"Use HTTPS for all transactions",
				"Implement proper IPN handling",
			},
		},
	}

	// Build Tools and Bundlers
	d.patterns["webpack"] = &TechDetectionPattern{
		Name:     "Webpack",
		Category: "Build Tool",
		HTML: []*regexp.Regexp{
			regexp.MustCompile(`webpackJsonp`),
			regexp.MustCompile(`webpack_require`),
		},
		SecurityInfo: &SecurityInfo{
			RiskLevel: "low",
			BestPractices: []string{
				"Don't expose source maps in production",
				"Keep webpack updated",
				"Use content hashing for cache busting",
			},
		},
	}

	d.patterns["vite"] = &TechDetectionPattern{
		Name:     "Vite",
		Category: "Build Tool",
		HTML: []*regexp.Regexp{
			regexp.MustCompile(`@vite/`),
		},
		Scripts: []*regexp.Regexp{
			regexp.MustCompile(`vite\.svg`),
		},
		SecurityInfo: &SecurityInfo{
			RiskLevel: "low",
			BestPractices: []string{
				"Keep Vite updated",
				"Configure proper CSP",
				"Don't expose .env files",
			},
		},
	}

	// Additional Technologies
	d.patterns["express"] = &TechDetectionPattern{
		Name:     "Express.js",
		Category: "Web Framework",
		Headers: map[string]*regexp.Regexp{
			"x-powered-by": regexp.MustCompile(`Express`),
		},
		SecurityInfo: &SecurityInfo{
			RiskLevel: "medium",
			CommonVulns: []string{
				"Information disclosure via x-powered-by",
				"Missing security headers",
				"Route parameter pollution",
			},
			BestPractices: []string{
				"Disable x-powered-by header",
				"Use helmet.js for security headers",
				"Implement rate limiting",
				"Keep Express updated",
			},
		},
	}

	d.patterns["flask"] = &TechDetectionPattern{
		Name:     "Flask",
		Category: "Web Framework",
		Headers: map[string]*regexp.Regexp{
			"server": regexp.MustCompile(`Werkzeug`),
		},
		SecurityInfo: &SecurityInfo{
			RiskLevel: "medium",
			CommonVulns: []string{
				"Debug mode in production",
				"SSTI vulnerabilities",
				"Session hijacking",
			},
			BestPractices: []string{
				"Never run debug mode in production",
				"Use proper session management",
				"Implement CSRF protection",
				"Keep Flask updated",
			},
		},
	}

	d.patterns["django"] = &TechDetectionPattern{
		Name:     "Django",
		Category: "Web Framework",
		Cookies: map[string]*regexp.Regexp{
			"csrftoken": regexp.MustCompile(`.+`),
		},
		SecurityInfo: &SecurityInfo{
			RiskLevel: "low",
			CommonVulns: []string{
				"SQL injection (if using raw queries)",
				"XSS (if autoescape disabled)",
			},
			BestPractices: []string{
				"Use Django ORM properly",
				"Enable CSRF protection",
				"Use Django security middleware",
				"Keep Django updated",
			},
		},
	}

	d.patterns["rails"] = &TechDetectionPattern{
		Name:     "Ruby on Rails",
		Category: "Web Framework",
		Headers: map[string]*regexp.Regexp{
			"x-powered-by": regexp.MustCompile(`(?i)phusion passenger`),
		},
		Cookies: map[string]*regexp.Regexp{
			"_session_id": regexp.MustCompile(`.+`),
		},
		SecurityInfo: &SecurityInfo{
			RiskLevel: "low",
			CommonVulns: []string{
				"Mass assignment",
				"CSRF bypass",
				"SQL injection",
			},
			BestPractices: []string{
				"Use strong parameters",
				"Enable CSRF protection",
				"Keep Rails updated",
				"Use secure session cookies",
			},
		},
	}

	d.patterns["fastapi"] = &TechDetectionPattern{
		Name:     "FastAPI",
		Category: "Web Framework",
		Headers: map[string]*regexp.Regexp{
			"server": regexp.MustCompile(`uvicorn`),
		},
		SecurityInfo: &SecurityInfo{
			RiskLevel: "low",
			BestPractices: []string{
				"Use OAuth2 for authentication",
				"Validate all inputs with Pydantic",
				"Enable CORS properly",
				"Keep FastAPI updated",
			},
		},
	}

	d.patterns["redis"] = &TechDetectionPattern{
		Name:     "Redis",
		Category: "Database",
		Headers: map[string]*regexp.Regexp{
			"x-redis-version": regexp.MustCompile(`.+`),
		},
		SecurityInfo: &SecurityInfo{
			RiskLevel: "medium",
			CommonVulns: []string{
				"Unauthorized access",
				"Command injection",
				"Data exposure",
			},
			BestPractices: []string{
				"Require authentication",
				"Bind to localhost or use firewall",
				"Disable dangerous commands",
				"Use encryption in transit",
			},
		},
	}

	d.patterns["postgresql"] = &TechDetectionPattern{
		Name:     "PostgreSQL",
		Category: "Database",
		Headers: map[string]*regexp.Regexp{
			"x-powered-by": regexp.MustCompile(`(?i)postgres`),
		},
		SecurityInfo: &SecurityInfo{
			RiskLevel: "medium",
			BestPractices: []string{
				"Use prepared statements",
				"Implement least privilege",
				"Enable SSL connections",
				"Keep PostgreSQL updated",
			},
		},
	}

	d.patterns["swagger"] = &TechDetectionPattern{
		Name:     "Swagger/OpenAPI",
		Category: "API Documentation",
		HTML: []*regexp.Regexp{
			regexp.MustCompile(`swagger-ui`),
			regexp.MustCompile(`openapi`),
		},
		SecurityInfo: &SecurityInfo{
			RiskLevel: "low",
			CommonVulns: []string{
				"API endpoint disclosure",
				"Authentication bypass in documentation",
			},
			BestPractices: []string{
				"Protect Swagger UI in production",
				"Don't expose internal APIs",
				"Use authentication for docs",
			},
		},
	}

	d.patterns["graphql"] = &TechDetectionPattern{
		Name:     "GraphQL",
		Category: "API",
		HTML: []*regexp.Regexp{
			regexp.MustCompile(`/graphql`),
			regexp.MustCompile(`graphiql`),
		},
		SecurityInfo: &SecurityInfo{
			RiskLevel: "medium",
			CommonVulns: []string{
				"Query depth attacks",
				"Introspection enabled in production",
				"N+1 query problems",
			},
			BestPractices: []string{
				"Disable introspection in production",
				"Implement query depth limiting",
				"Use query complexity analysis",
				"Implement proper authentication",
			},
		},
	}

	d.patterns["firebase"] = &TechDetectionPattern{
		Name:     "Firebase",
		Category: "Backend Platform",
		Scripts: []*regexp.Regexp{
			regexp.MustCompile(`firebase(?:app)?\.js`),
			regexp.MustCompile(`firebaseio\.com`),
		},
		SecurityInfo: &SecurityInfo{
			RiskLevel: "medium",
			CommonVulns: []string{
				"Weak security rules",
				"API key exposure",
				"Unauthorized data access",
			},
			BestPractices: []string{
				"Configure proper security rules",
				"Don't rely on API key secrecy",
				"Use Firebase Authentication",
				"Enable App Check",
			},
		},
	}

	d.patterns["supabase"] = &TechDetectionPattern{
		Name:     "Supabase",
		Category: "Backend Platform",
		Scripts: []*regexp.Regexp{
			regexp.MustCompile(`supabase`),
		},
		SecurityInfo: &SecurityInfo{
			RiskLevel: "medium",
			BestPractices: []string{
				"Configure RLS policies",
				"Use service role key securely",
				"Implement proper auth",
			},
		},
	}
}

// DetectTechnologies detects technologies from HTML and headers
func (d *TechnologyDetector) DetectTechnologies(html string, headers http.Header, cookies string) []Technology {
	var detected []Technology
	detectedNames := make(map[string]bool)

	for _, pattern := range d.patterns {
		confidence := "low"
		var evidence []string

		// Check headers
		if pattern.Headers != nil {
			for headerName, headerPattern := range pattern.Headers {
				headerValue := headers.Get(headerName)
				if headerValue != "" && headerPattern.MatchString(headerValue) {
					confidence = "high"
					evidence = append(evidence, "Header: "+headerName)
				}
			}
		}

		// Check HTML patterns
		if pattern.HTML != nil {
			for _, htmlPattern := range pattern.HTML {
				if htmlPattern.MatchString(html) {
					if confidence == "low" {
						confidence = "medium"
					}
					evidence = append(evidence, "HTML content")
				}
			}
		}

		// Check script patterns
		if pattern.Scripts != nil {
			for _, scriptPattern := range pattern.Scripts {
				if scriptPattern.MatchString(html) {
					if confidence == "low" {
						confidence = "medium"
					}
					evidence = append(evidence, "JavaScript")
				}
			}
		}

		// Check cookies
		if pattern.Cookies != nil && cookies != "" {
			for cookieName, cookiePattern := range pattern.Cookies {
				if strings.Contains(cookies, cookieName) || cookiePattern.MatchString(cookies) {
					if confidence != "high" {
						confidence = "medium"
					}
					evidence = append(evidence, "Cookie: "+cookieName)
				}
			}
		}

		// If technology detected, add it
		if len(evidence) > 0 && !detectedNames[pattern.Name] {
			detectedNames[pattern.Name] = true

			tech := Technology{
				Name:       pattern.Name,
				Category:   pattern.Category,
				Confidence: confidence,
				Evidence:   evidence,
			}

			// Extract version if possible
			version := d.extractVersion(pattern.Name, html, headers)
			if version != "" {
				tech.Version = version
			}

			detected = append(detected, tech)
		}
	}

	return detected
}

// extractVersion attempts to extract version information
func (d *TechnologyDetector) extractVersion(techName, html string, headers http.Header) string {
	versionPatterns := map[string]*regexp.Regexp{
		"WordPress": regexp.MustCompile(`WordPress\s+([\d\.]+)`),
		"Drupal":    regexp.MustCompile(`Drupal\s+([\d\.]+)`),
		"jQuery":    regexp.MustCompile(`jquery[/-]([\d\.]+)`),
		"PHP":       regexp.MustCompile(`PHP/([\d\.]+)`),
		"nginx":     regexp.MustCompile(`nginx/([\d\.]+)`),
		"Apache":    regexp.MustCompile(`Apache/([\d\.]+)`),
	}

	if pattern, exists := versionPatterns[techName]; exists {
		// Check in HTML
		if matches := pattern.FindStringSubmatch(html); len(matches) > 1 {
			return matches[1]
		}

		// Check in headers
		for _, values := range headers {
			for _, value := range values {
				if matches := pattern.FindStringSubmatch(value); len(matches) > 1 {
					return matches[1]
				}
			}
		}
	}

	return ""
}

// AssessSecurityRisks provides security assessment for detected technologies
func (d *TechnologyDetector) AssessSecurityRisks(technologies []Technology) []SecurityAssessment {
	var assessments []SecurityAssessment

	for _, tech := range technologies {
		if pattern, exists := d.patterns[strings.ToLower(strings.ReplaceAll(tech.Name, " ", ""))]; exists {
			if pattern.SecurityInfo != nil {
				assessment := SecurityAssessment{
					Technology:       tech.Name,
					Version:         tech.Version,
					RiskLevel:       pattern.SecurityInfo.RiskLevel,
					Vulnerabilities: pattern.SecurityInfo.CommonVulns,
					Recommendations: pattern.SecurityInfo.BestPractices,
				}

				// Check for outdated versions
				if tech.Version != "" && pattern.SecurityInfo.OutdatedVersions != nil {
					if status, isOutdated := pattern.SecurityInfo.OutdatedVersions[tech.Version]; isOutdated {
						assessment.RiskLevel = "high"
						assessment.Vulnerabilities = append(assessment.Vulnerabilities,
							"Outdated version: "+status)
					}
				}

				assessments = append(assessments, assessment)
			}
		}
	}

	return assessments
}

// ConvertToUnified converts detected technologies to unified format with evidence
func (d *TechnologyDetector) ConvertToUnified(technologies []Technology) []*UnifiedTechnology {
	unified := make([]*UnifiedTechnology, 0, len(technologies))

	for _, tech := range technologies {
		// Get security info for this technology
		pattern, exists := d.patterns[strings.ToLower(strings.ReplaceAll(tech.Name, " ", ""))]

		security := TechnologySecurity{
			RiskLevel:       "low",
			Vulnerabilities: []string{},
			Recommendations: []string{},
			CVEs:            []string{},
		}

		if exists && pattern.SecurityInfo != nil {
			security.RiskLevel = pattern.SecurityInfo.RiskLevel
			security.Vulnerabilities = pattern.SecurityInfo.CommonVulns
			security.Recommendations = pattern.SecurityInfo.BestPractices

			// Check for outdated versions
			if tech.Version != "" && pattern.SecurityInfo.OutdatedVersions != nil {
				if status, isOutdated := pattern.SecurityInfo.OutdatedVersions[tech.Version]; isOutdated {
					security.RiskLevel = "high"
					security.Vulnerabilities = append(security.Vulnerabilities,
						"Outdated version: "+status)
				}
			}
		}

		// Build evidence from detection data
		evidence := DetectionEvidence{
			Signatures: tech.Evidence,
		}

		unifiedTech := &UnifiedTechnology{
			Name:       tech.Name,
			Category:   tech.Category,
			Version:    tech.Version,
			Confidence: tech.Confidence,
			Security:   security,
			Evidence:   evidence,
		}

		unified = append(unified, unifiedTech)
	}

	return unified
}