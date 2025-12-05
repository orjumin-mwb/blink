package checker

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/olegrjumin/blink/internal/httpclient"
	"github.com/olegrjumin/blink/internal/mwbapi"
	"github.com/olegrjumin/blink/internal/scamguardapi"
)

// Checker performs URL checks
type Checker struct {
	client                *httpclient.Client
	mwbClient             *mwbapi.Client
	scamGuardClient       *scamguardapi.Client
	runtimeDetector       *RuntimeDetector
	runtimeAPIInterceptor *RuntimeAPIInterceptor
	techDetector          *TechnologyDetector
}

// New creates a new Checker instance
func New(client *httpclient.Client, mwbClient *mwbapi.Client, scamGuardClient *scamguardapi.Client) *Checker {
	return &Checker{
		client:                client,
		mwbClient:             mwbClient,
		scamGuardClient:       scamGuardClient,
		runtimeDetector:       NewRuntimeDetector(),
		runtimeAPIInterceptor: NewRuntimeAPIInterceptor(),
		techDetector:          NewTechnologyDetector(),
	}
}

// CheckURL performs a check on a single URL with the given options
// Returns a CheckResult with status, timing, and error information
func (c *Checker) CheckURL(ctx context.Context, rawURL string, opts CheckOptions) *CheckResult {
	startTime := time.Now()

	// Initialize result with the original URL
	result := &CheckResult{
		URL:           rawURL,
		OK:            false,
		Status:        0,
		ErrorType:     ErrorNone,
		RedirectCount: 0,
	}

	// Step 1: Validate and parse the URL
	parsedURL, err := url.Parse(rawURL)
	if err != nil || parsedURL.Scheme == "" || parsedURL.Host == "" {
		result.ErrorType = ErrorInvalidURL
		result.ErrorMessage = "invalid URL format"
		result.TotalMs = time.Since(startTime).Milliseconds()
		return result
	}

	// Ensure scheme is http or https
	if parsedURL.Scheme != "http" && parsedURL.Scheme != "https" {
		result.ErrorType = ErrorInvalidURL
		result.ErrorMessage = "URL must use http or https"
		result.TotalMs = time.Since(startTime).Milliseconds()
		return result
	}

	// Set protocol
	result.Protocol = parsedURL.Scheme

	// Check MWB reputation FIRST - fail fast if malicious
	isMalicious, err := c.mwbClient.CheckURL(ctx, rawURL)
	if err != nil {
		// If MWB check fails, log but continue with regular check
		result.MWBURLChecker = false
	} else {
		result.MWBURLChecker = isMalicious
		if isMalicious {
			// URL is malicious - stop immediately
			result.ErrorType = ErrorHTTP
			result.ErrorMessage = "URL flagged as malicious by Malwarebytes URL Checker"
			result.TotalMs = time.Since(startTime).Milliseconds()
			return result
		}
	}

	// Step 2: Perform HTTP request with redirect handling
	currentURL := rawURL
	redirectCount := 0
	var lastResp *httpclient.Response
	redirectChain := make([]RedirectHop, 0, opts.MaxRedirects)

	for {
		// Perform the request
		resp, err := c.client.Do(ctx, opts.Method, currentURL, opts.UserAgent)
		if err != nil {
			result.ErrorType, result.ErrorMessage = ClassifyError(err)
			result.TotalMs = time.Since(startTime).Milliseconds()
			return result
		}

		// Check if HEAD request returned 405 Method Not Allowed
		if opts.Method == "HEAD" && resp.StatusCode == 405 {
			// Capture that we got a 405 on HEAD request
			result.MethodNotAllowed = true
			result.InitialStatus = 405

			// Try GET instead
			resp, err = c.client.Do(ctx, "GET", currentURL, opts.UserAgent)
			if err != nil {
				result.ErrorType, result.ErrorMessage = ClassifyError(err)
				result.TotalMs = time.Since(startTime).Milliseconds()
				return result
			}
		}

		lastResp = resp

		// Check if it's a redirect (3xx)
		if opts.FollowRedirects && resp.StatusCode >= 300 && resp.StatusCode < 400 {
			// Get Location header
			location := resp.Header.Get("Location")
			if location == "" {
				// No location header, stop here
				break
			}

			// Capture redirect hop
			redirectChain = append(redirectChain, RedirectHop{
				URL:      currentURL,
				Status:   resp.StatusCode,
				Location: location,
			})

			// Check redirect limit
			redirectCount++
			if redirectCount > opts.MaxRedirects {
				result.Status = resp.StatusCode
				result.ErrorType = ErrorHTTP
				result.ErrorMessage = fmt.Sprintf("too many redirects (max: %d)", opts.MaxRedirects)
				result.TotalMs = time.Since(startTime).Milliseconds()
				return result
			}

			// Parse the location (might be relative)
			locationURL, err := url.Parse(location)
			if err != nil {
				result.ErrorType = ErrorInvalidURL
				result.ErrorMessage = "invalid redirect location"
				result.TotalMs = time.Since(startTime).Milliseconds()
				return result
			}

			// If relative, resolve against current URL
			currentParsed, _ := url.Parse(currentURL)
			currentURL = currentParsed.ResolveReference(locationURL).String()

			// Continue to follow redirect
			continue
		}

		// Not a redirect or not following redirects, stop here
		break
	}

	// Step 3: Process the final response
	result.Status = lastResp.StatusCode
	result.FinalURL = currentURL
	result.RedirectCount = redirectCount
	if len(redirectChain) > 0 {
		result.RedirectChain = redirectChain
	}
	result.TotalMs = time.Since(startTime).Milliseconds()

	// Extract HTTP version (e.g., "HTTP/2.0" -> "2")
	if strings.HasPrefix(lastResp.Proto, "HTTP/") {
		result.HTTPVersion = strings.TrimPrefix(lastResp.Proto, "HTTP/")
	}

	// Extract detailed timings
	timings := ExtractTimings(lastResp.Timings)
	result.DNSMs = timings.DNSMs
	result.ConnectMs = timings.ConnectMs
	result.TLSMs = timings.TLSMs
	result.TTFBMs = timings.TTFBMs

	// Classify speed
	result.SpeedClass = ClassifySpeed(result.TotalMs)

	// Extract TLS/certificate information (Phase 5)
	if tlsInfo := ExtractTLSInfo(lastResp.TLS); tlsInfo != nil {
		result.TLSVersion = tlsInfo.TLSVersion
		result.CertValid = tlsInfo.CertValid
		result.CertExpiresAt = tlsInfo.CertExpiresAt
		result.CertDaysRemaining = tlsInfo.CertDaysRemaining
		result.CertExpiringSoon = tlsInfo.CertExpiringSoon
		result.CertIssuer = tlsInfo.CertIssuer
	}

	// Extract response metadata (Phase 5)
	if contentType := lastResp.Header.Get("Content-Type"); contentType != "" {
		result.ContentType = contentType
	}
	if contentLength := lastResp.Header.Get("Content-Length"); contentLength != "" {
		// Parse Content-Length as int64
		if size, err := strconv.ParseInt(contentLength, 10, 64); err == nil {
			result.SizeBytes = size
		}
	}

	// Determine if the link is "OK"
	// 2xx and 3xx status codes are considered successful
	if result.Status >= 200 && result.Status < 400 {
		result.OK = true
	} else {
		// For 4xx and 5xx errors, classify as http_error
		result.ErrorType = ErrorHTTP
		result.ErrorMessage = fmt.Sprintf("HTTP %d", result.Status)
	}

	return result
}

// DeepCheckURL performs JavaScript and browser API analysis on a URL
// This is COMPLETELY SEPARATE from basic check - no status codes, redirects, TLS info
// legacyDeepCheckResult is used internally for backwards compatibility during detection
type legacyDeepCheckResult struct {
	URL                 string
	Timestamp           time.Time
	BrowserAPIs         []DetectedAPI
	DeviceAPIs          []DeviceCapability
	PrivacyRisks        []PrivacyRisk
	Trackers            []DetectedTracker
	JSLibraries         []JSLibrary
	Technologies        []Technology
	SecurityAssessments []SecurityAssessment
	Images              []Image
	OutgoingLinks       []OutgoingLink
	ExternalScripts     []string
	Errors              []string
	AnalysisComplete    bool
	ScriptsAnalyzed     int

	// Additional data for scoring context
	HTMLContent      string
	Forms            []FormInfo
	HTMLMetadata     *HTMLMetadata
	ImageAnalysis    *ImageAnalysis
	RuntimeAnalysis  *RuntimeResult
	SecurityCheck    *SecurityCheckResult
	Fingerprinting   *FingerprintAnalysis
	AnalysisDuration string
}

// SecurityAssessment represents security analysis for a technology (legacy)
type SecurityAssessment struct {
	Technology      string   `json:"technology"`
	Version         string   `json:"version,omitempty"`
	RiskLevel       string   `json:"risk_level"`
	Vulnerabilities []string `json:"vulnerabilities"`
	Recommendations []string `json:"recommendations"`
}

func (c *Checker) DeepCheckURL(ctx context.Context, rawURL string, opts DeepCheckOptions) *DeepCheckResult {
	startTime := time.Now()

	// Initialize legacy result for internal use
	result := &legacyDeepCheckResult{
		URL:              rawURL,
		Timestamp:        startTime,
		BrowserAPIs:      []DetectedAPI{},
		DeviceAPIs:       []DeviceCapability{},
		PrivacyRisks:     []PrivacyRisk{},
		Trackers:         []DetectedTracker{},
		JSLibraries:      []JSLibrary{},
		Technologies:     []Technology{},
		Images:           []Image{},
		OutgoingLinks:    []OutgoingLink{},
		ExternalScripts:  []string{},
		Errors:           []string{},
		AnalysisComplete: false,
	}

	// Validate URL
	parsedURL, err := url.Parse(rawURL)
	if err != nil || parsedURL.Scheme == "" || parsedURL.Host == "" {
		result.Errors = append(result.Errors, "Invalid URL format")
		result.AnalysisComplete = true
		result.AnalysisDuration = fmt.Sprintf("%.2fs", time.Since(startTime).Seconds())
		return c.buildUnifiedResponse(rawURL, startTime, result, nil, []string{})
	}

	// Fetch HTML body with GET request (always use GET for deep check)
	opts.Method = "GET"
	resp, body, err := c.client.DoWithBody(ctx, opts.Method, rawURL, opts.UserAgent)
	if err != nil {
		result.Errors = append(result.Errors, fmt.Sprintf("Failed to fetch URL: %v", err))
		result.AnalysisComplete = true
		result.AnalysisDuration = fmt.Sprintf("%.2fs", time.Since(startTime).Seconds())
		return c.buildUnifiedResponse(rawURL, startTime, result, nil, []string{})
	}
	defer body.Close()

	// Read body with 10MB size limit for JavaScript analysis
	const maxBodySize = 10 * 1024 * 1024 // 10MB
	bodyReader := io.LimitReader(body, maxBodySize)
	bodyBytes, err := io.ReadAll(bodyReader)
	if err != nil {
		result.Errors = append(result.Errors, fmt.Sprintf("Failed to read response body: %v", err))
		result.AnalysisComplete = true
		result.AnalysisDuration = fmt.Sprintf("%.2fs", time.Since(startTime).Seconds())
		return c.buildUnifiedResponse(rawURL, startTime, result, nil, []string{})
	}

	htmlContent := string(bodyBytes)

	// Parse HTML for metadata and structure
	htmlParser, err := NewHTMLParser(rawURL)
	if err == nil {
		parseResult, err := htmlParser.Parse(bytes.NewReader(bodyBytes))
		if err == nil && parseResult != nil {
			result.OutgoingLinks = parseResult.Links
			result.HTMLMetadata = parseResult.Metadata
			result.Images = parseResult.Images

			// Analyze images if any were found
			if len(parseResult.Images) > 0 {
				analyzer := NewImageAnalyzer(parseResult.Images)
				result.ImageAnalysis = analyzer.Analyze()
			}
		}
	}

	// Detect technologies with enhanced detection
	// Get cookies from response headers
	var cookieString string
	if cookieHeader := resp.Header.Get("Set-Cookie"); cookieHeader != "" {
		cookieString = cookieHeader
	}
	result.Technologies = c.techDetector.DetectTechnologies(htmlContent, resp.Header, cookieString)

	// Perform security assessment on detected technologies
	if len(result.Technologies) > 0 {
		result.SecurityAssessments = c.techDetector.AssessSecurityRisks(result.Technologies)
	}

	// Initialize security detectors
	securityFormsDetector := NewSecurityFormsDetector()
	securityCookieDetector := NewSecurityCookieDetector()
	securityHeadersDetector := NewSecurityHeadersDetector()
	securityCORSDetector := NewSecurityCORSDetector()

	// Parse cookies from Set-Cookie headers
	var cookies []*http.Cookie
	if setCookieHeaders := resp.Header["Set-Cookie"]; len(setCookieHeaders) > 0 {
		for _, cookieHeader := range setCookieHeaders {
			if cookie := parseCookieString(cookieHeader); cookie != nil {
				cookies = append(cookies, cookie)
			}
		}
	}

	// Extract inline scripts for security analysis (before we do that later)
	inlineScriptsForSecurity := extractInlineScripts(htmlContent)
	externalScriptsForSecurity := extractExternalScripts(htmlContent)

	// Extract forms for security analysis
	formsForSecurity := securityFormsDetector.extractForms(htmlContent)

	// Store HTML and forms for context-aware scoring
	result.HTMLContent = htmlContent
	result.Forms = formsForSecurity

	// Perform comprehensive security analysis
	result.SecurityCheck = c.performSecurityAnalysis(
		htmlContent,
		rawURL,
		resp.Header,
		cookies,
		securityFormsDetector,
		securityCookieDetector,
		securityHeadersDetector,
		securityCORSDetector,
		inlineScriptsForSecurity,
		externalScriptsForSecurity,
		formsForSecurity,
	)

	// Initialize detectors
	browserAPIDetector := NewBrowserAPIDetector()
	trackerDetector := NewTrackerDetector()

	// Initialize trackers if nil
	if result.Trackers == nil {
		result.Trackers = []DetectedTracker{}
	}

	// Detect trackers in HTML
	htmlTrackers := trackerDetector.DetectInHTML(htmlContent)
	result.Trackers = append(result.Trackers, htmlTrackers...)

	// Extract and analyze inline scripts
	inlineScripts := extractInlineScripts(htmlContent)
	for _, script := range inlineScripts {
		// Detect browser APIs in inline scripts
		apis := browserAPIDetector.Detect(script, "inline")
		result.BrowserAPIs = append(result.BrowserAPIs, apis...)

		// Detect trackers in inline scripts
		trackers := trackerDetector.DetectInJavaScript(script, "inline")
		for _, tracker := range trackers {
			// Avoid duplicates
			isDuplicate := false
			for _, existing := range result.Trackers {
				if existing.Name == tracker.Name {
					isDuplicate = true
					break
				}
			}
			if !isDuplicate {
				result.Trackers = append(result.Trackers, tracker)
			}
		}
	}
	result.ScriptsAnalyzed = len(inlineScripts)

	// Extract external script URLs
	externalScripts := extractExternalScripts(htmlContent)
	result.ExternalScripts = externalScripts

	// Check external script URLs against tracker patterns
	for _, scriptURL := range externalScripts {
		fmt.Printf("[DEBUG] Checking external script URL: %s\n", scriptURL)
		trackers := trackerDetector.DetectInJavaScript("", scriptURL)
		fmt.Printf("[DEBUG] Found %d trackers for URL: %s\n", len(trackers), scriptURL)
		for _, tracker := range trackers {
			fmt.Printf("[DEBUG] Found tracker: %s (Category: %s)\n", tracker.Name, tracker.Category)
			// Avoid duplicates
			isDuplicate := false
			for _, existing := range result.Trackers {
				if existing.Name == tracker.Name {
					isDuplicate = true
					break
				}
			}
			if !isDuplicate {
				result.Trackers = append(result.Trackers, tracker)
			}
		}
	}

	// Analyze device capabilities
	result.DeviceAPIs = analyzeDeviceCapabilities(result.BrowserAPIs)

	// Analyze fingerprinting
	if fingerprinting := browserAPIDetector.AnalyzeFingerprinting(result.BrowserAPIs); fingerprinting != nil {
		result.Fingerprinting = fingerprinting
	}

	// Analyze privacy risks
	result.PrivacyRisks = trackerDetector.AnalyzePrivacyRisks(result.Trackers, result.BrowserAPIs)

	// Perform runtime detection if enabled
	if opts.EnableRuntimeDetection && c.runtimeDetector != nil {
		// Try the improved simple detection first
		runtimeResult, err := c.runtimeDetector.DetectRuntimeTrackersSimple(rawURL, opts.RuntimeTimeout)

		if err != nil {
			// If simple detection fails, try fallback method
			fmt.Printf("[DEBUG] Simple runtime detection failed: %v, trying fallback\n", err)
			runtimeResult, err = c.runtimeDetector.FallbackRuntimeDetection(rawURL)

			if err != nil {
				result.Errors = append(result.Errors, fmt.Sprintf("Runtime detection failed: %v", err))
			}
		}

		if runtimeResult != nil && err == nil {
			// Merge runtime trackers with static detection
			for _, runtimeTracker := range runtimeResult.Trackers {
				// Check if not already detected
				isDuplicate := false
				for _, existing := range result.Trackers {
					if existing.Name == runtimeTracker.Name {
						isDuplicate = true
						break
					}
				}
				if !isDuplicate {
					runtimeTracker.DetectedAt = "runtime"
					result.Trackers = append(result.Trackers, runtimeTracker)
				}
			}

			// Add runtime analysis to result
			result.RuntimeAnalysis = runtimeResult

			// Run API interception to detect actual API usage
			if c.runtimeAPIInterceptor != nil {
				fmt.Printf("[DEBUG] Running API interceptor for actual usage detection\n")
				// Use a longer timeout for API interception (10 seconds minimum)
				apiTimeout := opts.RuntimeTimeout
				if apiTimeout < 10*time.Second {
					apiTimeout = 10 * time.Second
				}
				apiUsage, apiErr := c.runtimeAPIInterceptor.DetectAPIUsage(rawURL, apiTimeout)
				if apiErr != nil {
					fmt.Printf("[DEBUG] API interception failed: %v\n", apiErr)
					result.Errors = append(result.Errors, fmt.Sprintf("API interception failed: %v", apiErr))
				} else {
					fmt.Printf("[DEBUG] API interception succeeded, found %d available APIs and %d actually used\n",
						len(apiUsage.Available), len(apiUsage.ActualUsage))
					result.RuntimeAnalysis.APIUsage = apiUsage
				}
			}
		}
	}

	// Convert to unified format using ResponseBuilder and Aggregator
	unifiedResult := c.buildUnifiedResponse(rawURL, startTime, result, resp.Header, externalScripts)

	return unifiedResult
}

// buildUnifiedResponse converts legacy detection results to unified format
func (c *Checker) buildUnifiedResponse(targetURL string, startTime time.Time, legacyResult *legacyDeepCheckResult, headers http.Header, externalScripts []string) *DeepCheckResult {
	builder := NewResponseBuilder(targetURL)
	builder.SetAnalysisDuration(time.Since(startTime))
	aggregator := builder.GetAggregator()

	// Convert and aggregate technologies
	unifiedTech := c.techDetector.ConvertToUnified(legacyResult.Technologies)
	for _, tech := range unifiedTech {
		aggregator.AddTechnology(tech.Name, tech, "static")
	}

	// Convert and aggregate trackers
	trackerDetector := NewTrackerDetector()
	unifiedTrackers := trackerDetector.ConvertToUnified(legacyResult.Trackers)
	for _, tracker := range unifiedTrackers {
		aggregator.AddTracker(tracker.Name, tracker, "static")
	}

	// Convert and aggregate browser APIs
	browserAPIDetector := NewBrowserAPIDetector()
	unifiedAPIs := browserAPIDetector.ConvertToUnified(legacyResult.BrowserAPIs, false)
	for _, api := range unifiedAPIs {
		aggregator.AddAPI(api.Name, api, "static")
	}

	// If runtime analysis was performed, add runtime detections
	if legacyResult.RuntimeAnalysis != nil {
		// Add runtime trackers
		if c.runtimeDetector != nil {
			networkReqs := make([]string, 0, len(legacyResult.RuntimeAnalysis.NetworkRequests))
			for _, req := range legacyResult.RuntimeAnalysis.NetworkRequests {
				networkReqs = append(networkReqs, req)
			}

			runtimeTrackers := c.runtimeDetector.ConvertTrackersToUnified(
				legacyResult.RuntimeAnalysis.Trackers,
				networkReqs,
			)
			for _, tracker := range runtimeTrackers {
				aggregator.AddTracker(tracker.Name, tracker, "runtime")
			}

			// Add runtime-executed APIs
			if len(legacyResult.RuntimeAnalysis.ExecutedAPIs) > 0 {
				runtimeAPIs := c.runtimeDetector.ConvertAPIsToUnified(legacyResult.RuntimeAnalysis.ExecutedAPIs)
				for _, api := range runtimeAPIs {
					aggregator.AddAPI(api.Name, api, "runtime")
				}
			}
		}
	}

	// Set security data
	if legacyResult.SecurityCheck != nil {
		builder.SetSecurityIssues(legacyResult.SecurityCheck)
	}

	// Set context data for improved scoring
	if headers != nil && legacyResult.HTMLContent != "" {
		builder.SetContextData(headers, legacyResult.HTMLContent, legacyResult.Forms)
	}

	// TODO: Check for security.txt in the future
	// For now, set to false
	builder.SetSecurityTxt(false)

	// Build page info from legacy data
	pageInfo := &PageInfo{
		Metadata: legacyResult.HTMLMetadata,
		Resources: &PageResources{
			Scripts: &ScriptInfo{
				External:     len(externalScripts),
				ExternalURLs: externalScripts,
				Inline:       legacyResult.ScriptsAnalyzed,
			},
			Images: &ImageInfo{
				Total:  len(legacyResult.Images),
				Images: legacyResult.Images,
			},
			Links: &LinkInfo{
				Internal:        0,
				External:        len(legacyResult.OutgoingLinks),
				Links:           legacyResult.OutgoingLinks,
				ExternalDomains: []string{},
			},
		},
	}

	// Populate image info from image analysis
	if legacyResult.ImageAnalysis != nil {
		pageInfo.Resources.Images.LazyLoaded = legacyResult.ImageAnalysis.LazyLoadedCount
		pageInfo.Resources.Images.MissingAlt = len(legacyResult.ImageAnalysis.MissingAlt)
		pageInfo.Resources.Images.Formats = legacyResult.ImageAnalysis.Formats
	}

	// Extract external domains from links
	externalDomains := make(map[string]bool)
	for _, link := range legacyResult.OutgoingLinks {
		parsedURL, err := url.Parse(link.AbsoluteURL)
		if err == nil && parsedURL.Host != "" {
			externalDomains[parsedURL.Host] = true
		}
	}
	domains := make([]string, 0, len(externalDomains))
	for domain := range externalDomains {
		domains = append(domains, domain)
	}
	pageInfo.Resources.Links.ExternalDomains = domains

	builder.SetPageInfo(pageInfo)

	// Detect payment methods
	if legacyResult.HTMLContent != "" {
		c.detectAndSetPaymentMethods(builder, legacyResult, headers, externalScripts)
	}

	// Build network data if available
	if legacyResult.RuntimeAnalysis != nil && len(legacyResult.RuntimeAnalysis.NetworkRequests) > 0 {
		networkData := &NetworkData{
			Requests:        []NetworkRequest{},
			ExternalDomains: []string{},
		}

		// Convert network requests
		for _, req := range legacyResult.RuntimeAnalysis.NetworkRequests {
			networkData.Requests = append(networkData.Requests, NetworkRequest{
				URL:    req,
				Method: "GET",
				Type:   "unknown",
			})
		}

		builder.SetNetworkData(networkData)
	}

	// Build and return unified result
	return builder.Build()
}

// extractInlineScripts extracts inline JavaScript from HTML
func extractInlineScripts(html string) []string {
	var scripts []string

	// Simple regex to find script tags (not perfect but good enough)
	scriptRegex := regexp.MustCompile(`(?i)<script[^>]*>([^<]+)</script>`)
	matches := scriptRegex.FindAllStringSubmatch(html, -1)

	for _, match := range matches {
		if len(match) > 1 && strings.TrimSpace(match[1]) != "" {
			scripts = append(scripts, match[1])
		}
	}

	return scripts
}

// extractExternalScripts extracts external script URLs from HTML
func extractExternalScripts(html string) []string {
	var scripts []string

	// Regex to find script tags with src attribute
	scriptRegex := regexp.MustCompile(`(?i)<script[^>]+src\s*=\s*["']([^"']+)["']`)
	matches := scriptRegex.FindAllStringSubmatch(html, -1)

	for _, match := range matches {
		if len(match) > 1 {
			scripts = append(scripts, match[1])
		}
	}

	return scripts
}

// detectAndSetPaymentMethods performs payment detection and adds results to the builder
func (c *Checker) detectAndSetPaymentMethods(builder *ResponseBuilder, legacyResult *legacyDeepCheckResult, headers http.Header, externalScripts []string) {
	log.Printf("[DEBUG] Payment detection starting, HTML length: %d", len(legacyResult.HTMLContent))

	// Create payment detector
	paymentDetector := NewPaymentDetector()

	// Extract inline scripts
	inlineScripts := extractInlineScripts(legacyResult.HTMLContent)
	allScripts := append(inlineScripts, externalScripts...)

	log.Printf("[DEBUG] Extracted %d inline scripts, %d external scripts", len(inlineScripts), len(externalScripts))

	// Prepare network data if available
	var networkData []NetworkRequest
	if legacyResult.RuntimeAnalysis != nil && len(legacyResult.RuntimeAnalysis.NetworkRequests) > 0 {
		networkData = make([]NetworkRequest, 0, len(legacyResult.RuntimeAnalysis.NetworkRequests))
		for _, req := range legacyResult.RuntimeAnalysis.NetworkRequests {
			networkData = append(networkData, NetworkRequest{
				URL:    req,
				Method: "GET",
				Type:   "xhr",
			})
		}
	}

	// Perform payment detection
	paymentResult := paymentDetector.Detect(legacyResult.HTMLContent, headers, allScripts, networkData)

	log.Printf("[DEBUG] Payment detection complete, found %d providers, %d methods", len(paymentResult.Providers), len(paymentResult.PaymentMethods))

	// Build payment analysis summary
	summary := &PaymentSummary{
		TotalProviders: len(paymentResult.Providers),
		IsSecure:       paymentResult.Compliance.SecureTransmission,
	}

	// Determine primary provider (highest confidence)
	if len(paymentResult.Providers) > 0 {
		highestScore := 0.0
		for _, provider := range paymentResult.Providers {
			if provider.ConfidenceScore > highestScore {
				highestScore = provider.ConfidenceScore
				summary.PrimaryProvider = provider.Name
				summary.ConfidenceLevel = provider.Confidence
			}
		}
	}

	// Set category flags
	for _, method := range paymentResult.PaymentMethods {
		switch method {
		case "credit_card":
			summary.HasCreditCard = true
		case "cryptocurrency":
			summary.HasCrypto = true
		case "buy_now_pay_later":
			summary.HasBNPL = true
		}
	}

	// Check for wallet methods
	walletMethods := []string{"apple_pay", "google_pay", "paypal", "amazon_pay", "venmo"}
	for _, method := range paymentResult.PaymentMethods {
		for _, wallet := range walletMethods {
			if method == wallet {
				summary.HasWallets = true
				break
			}
		}
		if summary.HasWallets {
			break
		}
	}

	// Create payment analysis
	paymentAnalysis := &PaymentAnalysis{
		Providers:      paymentResult.Providers,
		Methods:        paymentResult.PaymentMethods,
		CheckoutFlow:   paymentResult.CheckoutFlow,
		Compliance:     &paymentResult.Compliance,
		RiskAssessment: &paymentResult.RiskAssessment,
		Summary:        summary,
	}

	// Set payment data in builder
	builder.SetPaymentAnalysis(paymentAnalysis)

	log.Printf("[DEBUG] Payment analysis set in builder with %d providers", len(paymentAnalysis.Providers))
}

// analyzeDeviceCapabilities converts detected APIs to device capabilities
func analyzeDeviceCapabilities(apis []DetectedAPI) []DeviceCapability {
	var capabilities []DeviceCapability
	deviceTypes := make(map[string]bool)

	for _, api := range apis {
		var deviceType string
		var apiUsed string

		switch api.Category {
		case "Device Access":
			if strings.Contains(api.Name, "Media") {
				deviceType = "camera/microphone"
				apiUsed = "getUserMedia"
			} else if strings.Contains(api.Name, "Bluetooth") {
				deviceType = "bluetooth"
				apiUsed = "navigator.bluetooth"
			} else if strings.Contains(api.Name, "USB") {
				deviceType = "usb"
				apiUsed = "navigator.usb"
			}
		case "Sensors":
			deviceType = "accelerometer/gyroscope"
			apiUsed = "DeviceOrientationEvent"
		case "Location Services":
			deviceType = "gps"
			apiUsed = "navigator.geolocation"
		}

		if deviceType != "" && !deviceTypes[deviceType] {
			deviceTypes[deviceType] = true
			capabilities = append(capabilities, DeviceCapability{
				Type:        deviceType,
				APIUsed:     apiUsed,
				Detected:    true,
				CodeContext: strings.Join(api.Usage, "; "),
				FoundIn:     api.FoundIn,
			})
		}
	}

	return capabilities
}

// DeepCheckURLStreaming performs JavaScript analysis with streaming results
func (c *Checker) DeepCheckURLStreaming(ctx context.Context, rawURL string, opts DeepCheckOptions, events chan<- StreamEvent) {
	defer close(events)
	startTime := time.Now()
	isCancelled := func() bool {
		return ctx.Err() != nil
	}

	// Send initial event
	sendEvent(ctx, events, "analysis_started", "Starting deep analysis", map[string]string{
		"url":       rawURL,
		"timestamp": startTime.Format(time.RFC3339),
	})
	sendEvent(ctx, events, "analysis_progress", "Initializing...", map[string]interface{}{
		"progress": 5,
		"step":     "Validating URL",
	})

	// Validate URL
	parsedURL, err := url.Parse(rawURL)
	if err != nil || parsedURL.Scheme == "" || parsedURL.Host == "" {
		sendEvent(ctx, events, "error", "Invalid URL format", map[string]string{"error": "Invalid URL format"})
		return
	}

	if isCancelled() {
		return
	}

	// Fetch HTML body
	sendEvent(ctx, events, "fetching", "Fetching page content", nil)
	sendEvent(ctx, events, "analysis_progress", "Fetching page...", map[string]interface{}{
		"progress": 10,
		"step":     "Fetching page content",
	})
	opts.Method = "GET"
	resp, body, err := c.client.DoWithBody(ctx, opts.Method, rawURL, opts.UserAgent)
	if err != nil {
		sendEvent(ctx, events, "error", "Failed to fetch URL", map[string]string{"error": err.Error()})
		return
	}
	defer body.Close()

	if isCancelled() {
		return
	}

	// Read body
	const maxBodySize = 10 * 1024 * 1024 // 10MB
	bodyReader := io.LimitReader(body, maxBodySize)
	bodyBytes, err := io.ReadAll(bodyReader)
	log.Printf("[DEBUG] Streaming: Read bodyBytes, length=%d, err=%v", len(bodyBytes), err)
	if err != nil {
		sendEvent(ctx, events, "error", "Failed to read response", map[string]string{"error": err.Error()})
		return
	}

	htmlContent := string(bodyBytes)
	log.Printf("[DEBUG] Streaming: htmlContent loaded, length=%d", len(htmlContent))

	if isCancelled() {
		return
	}

	// Progress: 20% - HTML parsing
	sendEvent(ctx, events, "analysis_progress", "Parsing HTML...", map[string]interface{}{
		"progress": 20,
		"step":     "Parsing page structure",
	})

	// Parse HTML for links and images
	htmlParser, err := NewHTMLParser(rawURL)
	if err == nil {
		parseResult, err := htmlParser.Parse(bytes.NewReader(bodyBytes))
		if err == nil && parseResult != nil {
			// Emit links found
			if len(parseResult.Links) > 0 {
				sendEvent(ctx, events, "links_found", "Links discovered", map[string]interface{}{
					"links": parseResult.Links,
					"count": len(parseResult.Links),
				})
			}

			// Emit images found
			if len(parseResult.Images) > 0 {
				sendEvent(ctx, events, "images_found", "Images discovered", map[string]interface{}{
					"images": parseResult.Images,
					"count":  len(parseResult.Images),
				})
			}
		}
	}

	if isCancelled() {
		return
	}

	// Progress: 30% - Technology detection
	sendEvent(ctx, events, "analysis_progress", "Detecting technologies...", map[string]interface{}{
		"progress": 30,
		"step":     "Analyzing technology stack",
	})

	// Detect technologies
	var cookieString string
	if cookieHeader := resp.Header.Get("Set-Cookie"); cookieHeader != "" {
		cookieString = cookieHeader
	}
	technologies := c.techDetector.DetectTechnologies(htmlContent, resp.Header, cookieString)
	for _, tech := range technologies {
		sendEvent(ctx, events, "technology_found", "Technology detected", map[string]interface{}{
			"name":       tech.Name,
			"category":   tech.Category,
			"version":    tech.Version,
			"confidence": tech.Confidence,
		})
	}

	if isCancelled() {
		return
	}

	// Progress: 40% - Tracker detection
	sendEvent(ctx, events, "analysis_progress", "Analyzing trackers...", map[string]interface{}{
		"progress": 40,
		"step":     "Detecting tracking services",
	})

	// Initialize detectors
	browserAPIDetector := NewBrowserAPIDetector()
	trackerDetector := NewTrackerDetector()

	// Detect trackers in HTML
	trackers := trackerDetector.DetectInHTML(htmlContent)
	for _, tracker := range trackers {
		sendEvent(ctx, events, "tracker_found", "Tracker detected", tracker)
	}

	if isCancelled() {
		return
	}

	// Progress: 50% - Script analysis
	sendEvent(ctx, events, "analysis_progress", "Analyzing scripts...", map[string]interface{}{
		"progress": 50,
		"step":     "Analyzing inline scripts",
	})

	// Extract and analyze inline scripts
	inlineScripts := extractInlineScripts(htmlContent)
	for i, script := range inlineScripts {
		sendEvent(ctx, events, "analyzing_script", fmt.Sprintf("Analyzing inline script %d", i+1), map[string]string{
			"type":  "inline",
			"index": strconv.Itoa(i + 1),
		})

		// Detect browser APIs
		apis := browserAPIDetector.Detect(script, "inline")
		for _, api := range apis {
			sendEvent(ctx, events, "api_detected", "Browser API detected", api)
		}

		// Detect trackers in scripts
		scriptTrackers := trackerDetector.DetectInJavaScript(script, "inline")
		for _, tracker := range scriptTrackers {
			sendEvent(ctx, events, "tracker_found", "Tracker in script", tracker)
		}

		if isCancelled() {
			return
		}
	}

	// Extract external scripts
	externalScripts := extractExternalScripts(htmlContent)
	if len(externalScripts) > 0 {
		// Emit as network requests
		var requests []map[string]interface{}
		for _, scriptURL := range externalScripts {
			requests = append(requests, map[string]interface{}{
				"url":    scriptURL,
				"method": "GET",
				"type":   "script",
			})
		}
		sendEvent(ctx, events, "requests_found", "Network requests discovered", map[string]interface{}{
			"requests": requests,
			"count":    len(requests),
		})
	}

	if isCancelled() {
		return
	}

	// Progress: 70% - Security analysis
	sendEvent(ctx, events, "analysis_progress", "Analyzing security...", map[string]interface{}{
		"progress": 70,
		"step":     "Running security checks",
	})

	// Perform security analysis
	securityFormsDetector := NewSecurityFormsDetector()
	securityCookieDetector := NewSecurityCookieDetector()
	securityHeadersDetector := NewSecurityHeadersDetector()
	securityCORSDetector := NewSecurityCORSDetector()

	// Parse cookies from Set-Cookie headers
	var cookies []*http.Cookie
	if setCookieHeaders := resp.Header["Set-Cookie"]; len(setCookieHeaders) > 0 {
		for _, cookieHeader := range setCookieHeaders {
			if cookie := parseCookieString(cookieHeader); cookie != nil {
				cookies = append(cookies, cookie)
			}
		}
	}

	// Extract forms
	forms := securityFormsDetector.extractForms(htmlContent)

	// Run security analysis
	securityResult := c.performSecurityAnalysis(
		htmlContent,
		rawURL,
		resp.Header,
		cookies,
		securityFormsDetector,
		securityCookieDetector,
		securityHeadersDetector,
		securityCORSDetector,
		inlineScripts,
		externalScripts,
		forms,
	)

	if isCancelled() {
		return
	}

	// Emit security issues by severity
	if securityResult != nil {
		for _, issue := range securityResult.Critical {
			sendEvent(ctx, events, "security_issue_found", "Security issue detected", map[string]interface{}{
				"security_issue": issue,
			})
		}
		for _, issue := range securityResult.High {
			sendEvent(ctx, events, "security_issue_found", "Security issue detected", map[string]interface{}{
				"security_issue": issue,
			})
		}
		for _, issue := range securityResult.Medium {
			sendEvent(ctx, events, "security_issue_found", "Security issue detected", map[string]interface{}{
				"security_issue": issue,
			})
		}
		for _, issue := range securityResult.Low {
			sendEvent(ctx, events, "security_issue_found", "Security issue detected", map[string]interface{}{
				"security_issue": issue,
			})
		}

		// Emit security score
		sendEvent(ctx, events, "security_score", "Security score calculated", map[string]interface{}{
			"score":          securityResult.SecurityScore,
			"total_issues":   securityResult.TotalIssues,
			"critical_count": securityResult.CriticalCount,
			"high_count":     securityResult.HighCount,
			"medium_count":   securityResult.MediumCount,
			"low_count":      securityResult.LowCount,
		})
	}

	// Progress: 90% - Finalizing
	sendEvent(ctx, events, "analysis_progress", "Finalizing analysis...", map[string]interface{}{
		"progress": 90,
		"step":     "Analyzing privacy risks",
	})

	// Analyze fingerprinting
	allAPIs := []DetectedAPI{}
	for _, script := range inlineScripts {
		apis := browserAPIDetector.Detect(script, "inline")
		allAPIs = append(allAPIs, apis...)
	}

	if fingerprinting := browserAPIDetector.AnalyzeFingerprinting(allAPIs); fingerprinting != nil {
		sendEvent(ctx, events, "fingerprinting", "Fingerprinting analysis", fingerprinting)
	}

	if isCancelled() {
		return
	}

	// Analyze privacy risks
	privacyRisks := trackerDetector.AnalyzePrivacyRisks(trackers, allAPIs)
	for _, risk := range privacyRisks {
		sendEvent(ctx, events, "privacy_risk", "Privacy risk detected", risk)
	}

	if isCancelled() {
		return
	}

	// Progress: 95% - Payment detection
	sendEvent(ctx, events, "analysis_progress", "Detecting payment methods...", map[string]interface{}{
		"progress": 95,
		"step":     "Analyzing payment methods",
	})

	// Detect payment methods
	paymentDetector := NewPaymentDetector()
	allScripts := append(inlineScripts, externalScripts...)
	log.Printf("[DEBUG] Streaming payment detection: HTML length=%d, scripts=%d", len(htmlContent), len(allScripts))
	paymentResult := paymentDetector.Detect(htmlContent, resp.Header, allScripts, nil)
	log.Printf("[DEBUG] Streaming payment detection result: result=%v, providers=%d", paymentResult != nil, len(paymentResult.Providers))
	if paymentResult != nil && len(paymentResult.Providers) > 0 {
		// Build payment summary
		summary := &PaymentSummary{
			TotalProviders:  len(paymentResult.Providers),
			IsSecure:        paymentResult.Compliance.SecureTransmission,
			HasCreditCard:   false,
			HasWallets:      false,
			HasBNPL:         false,
			HasCrypto:       false,
			ConfidenceLevel: "low",
		}

		// Determine primary provider
		if len(paymentResult.Providers) > 0 {
			highestScore := 0.0
			for _, provider := range paymentResult.Providers {
				if provider.ConfidenceScore > highestScore {
					highestScore = provider.ConfidenceScore
					summary.PrimaryProvider = provider.Name
					summary.ConfidenceLevel = provider.Confidence
				}
			}
		}

		// Set category flags
		for _, method := range paymentResult.PaymentMethods {
			switch method {
			case "credit_card":
				summary.HasCreditCard = true
			case "cryptocurrency":
				summary.HasCrypto = true
			case "buy_now_pay_later":
				summary.HasBNPL = true
			}
		}

		// Check for wallet methods
		walletMethods := []string{"apple_pay", "google_pay", "paypal", "amazon_pay", "venmo"}
		for _, method := range paymentResult.PaymentMethods {
			for _, wallet := range walletMethods {
				if method == wallet {
					summary.HasWallets = true
					break
				}
			}
			if summary.HasWallets {
				break
			}
		}

		// Send payment event with full data
		paymentData := map[string]interface{}{
			"providers":       paymentResult.Providers,
			"methods":         paymentResult.PaymentMethods,
			"checkout_flow":   paymentResult.CheckoutFlow,
			"compliance":      paymentResult.Compliance,
			"risk_assessment": paymentResult.RiskAssessment,
			"summary":         summary,
		}
		sendEvent(ctx, events, "payment", "Payment methods detected", paymentData)

		log.Printf("[DEBUG] Streaming: Sent payment event with %d providers", len(paymentResult.Providers))
	}

	if isCancelled() {
		return
	}

	// Progress: 100% - Complete
	sendEvent(ctx, events, "analysis_progress", "Complete", map[string]interface{}{
		"progress": 100,
		"step":     "Analysis complete",
	})

	// Send completion event
	duration := time.Since(startTime)
	sendEvent(ctx, events, "analysis_complete", "Analysis complete", map[string]interface{}{
		"success":          true,
		"scripts_analyzed": len(inlineScripts),
		"trackers_found":   len(trackers),
		"apis_detected":    len(allAPIs),
		"duration":         fmt.Sprintf("%.2fs", duration.Seconds()),
	})
}

// performSecurityAnalysis runs all security detectors and aggregates results with context-aware scoring
func (c *Checker) performSecurityAnalysis(
	html string,
	pageURL string,
	headers http.Header,
	cookies []*http.Cookie,
	formsDetector *SecurityFormsDetector,
	cookieDetector *SecurityCookieDetector,
	headersDetector *SecurityHeadersDetector,
	corsDetector *SecurityCORSDetector,
	inlineScripts []string,
	externalScripts []string,
	forms []FormInfo,
) *SecurityCheckResult {
	result := &SecurityCheckResult{
		Critical:      []SecurityIssue{},
		High:          []SecurityIssue{},
		Medium:        []SecurityIssue{},
		Low:           []SecurityIssue{},
		SecurityScore: 100, // Start with perfect score
	}

	// Determine security context for weighted scoring
	context := c.determineSecurityContext(pageURL, html, forms)

	// Collect all security issues
	allIssues := []SecurityIssue{}

	// Run existing detectors
	formIssues := formsDetector.Detect(html, pageURL, headers)
	allIssues = append(allIssues, formIssues...)

	cookieIssues := cookieDetector.Detect(html, pageURL, headers, cookies)
	allIssues = append(allIssues, cookieIssues...)

	headerIssues := headersDetector.Detect(pageURL, headers)
	allIssues = append(allIssues, headerIssues...)

	corsIssues := corsDetector.Detect(pageURL, headers)
	allIssues = append(allIssues, corsIssues...)

	// Run new detectors
	mixedContentDetector := NewSecurityMixedContentDetector()
	mixedContentIssues := mixedContentDetector.Detect(html, pageURL)
	allIssues = append(allIssues, mixedContentIssues...)

	clientDetector := NewSecurityClientDetector()
	clientIssues := clientDetector.Detect(html, inlineScripts)
	allIssues = append(allIssues, clientIssues...)

	dataExposureDetector := NewSecurityDataExposureDetector()
	dataExposureIssues := dataExposureDetector.Detect(html, inlineScripts, externalScripts)
	allIssues = append(allIssues, dataExposureIssues...)

	authDetector := NewSecurityAuthDetector()
	authIssues := authDetector.Detect(html, pageURL, forms, inlineScripts)
	allIssues = append(allIssues, authIssues...)

	cryptoDetector := NewSecurityCryptoDetector()
	cryptoIssues := cryptoDetector.Detect(html, inlineScripts)
	allIssues = append(allIssues, cryptoIssues...)

	// Calculate context-aware security score
	result.SecurityScore = c.calculateContextAwareScore(allIssues, context)

	// Group issues by severity
	for _, issue := range allIssues {
		switch issue.Severity {
		case "critical":
			result.Critical = append(result.Critical, issue)
			result.CriticalCount++
		case "high":
			result.High = append(result.High, issue)
			result.HighCount++
		case "medium":
			result.Medium = append(result.Medium, issue)
			result.MediumCount++
		case "low":
			result.Low = append(result.Low, issue)
			result.LowCount++
		}
	}

	result.TotalIssues = len(allIssues)

	// Create category summaries
	result.FormsSummary = c.createCategorySummary(formIssues, "Forms")
	result.CookiesSummary = c.createCategorySummary(cookieIssues, "Cookies")
	result.HeadersSummary = c.createCategorySummary(headerIssues, "Headers")
	result.CORSSummary = c.createCategorySummary(corsIssues, "CORS")

	// Add verification results for critical issues
	for _, issue := range result.Critical {
		if issue.Verified {
			result.Verifications = append(result.Verifications, VerificationResult{
				Issue:     issue.Title,
				Method:    "Static Analysis",
				Confirmed: true,
				Details:   issue.Description,
				Timestamp: time.Now().Format(time.RFC3339),
			})
		}
	}

	return result
}

// SecurityContext holds information about the page type for context-aware scoring
type SecurityContext struct {
	PageType       string // "login", "payment", "api", "static"
	HasForms       bool
	HasPasswords   bool
	HasPayment     bool
	IsHTTPS        bool
	RiskMultiplier float64
}

// determineSecurityContext analyzes the page to determine its security context
func (c *Checker) determineSecurityContext(pageURL string, html string, forms []FormInfo) SecurityContext {
	context := SecurityContext{
		PageType:       "static",
		IsHTTPS:        strings.HasPrefix(pageURL, "https://"),
		RiskMultiplier: 1.0,
	}

	urlLower := strings.ToLower(pageURL)
	htmlLower := strings.ToLower(html)

	// Detect page type
	if strings.Contains(urlLower, "login") || strings.Contains(urlLower, "signin") ||
		strings.Contains(urlLower, "auth") {
		context.PageType = "login"
		context.RiskMultiplier = 2.0 // Login pages have higher risk
	} else if strings.Contains(urlLower, "checkout") || strings.Contains(urlLower, "payment") ||
		strings.Contains(urlLower, "cart") {
		context.PageType = "payment"
		context.RiskMultiplier = 2.5 // Payment pages have highest risk
	} else if strings.Contains(urlLower, "/api/") || strings.Contains(urlLower, "/v1/") ||
		strings.Contains(urlLower, "/v2/") {
		context.PageType = "api"
		context.RiskMultiplier = 1.5 // API endpoints need good security
	} else if strings.Contains(urlLower, "admin") || strings.Contains(urlLower, "dashboard") {
		context.PageType = "admin"
		context.RiskMultiplier = 2.0 // Admin panels are high risk
	}

	// Check for forms
	context.HasForms = len(forms) > 0

	// Check for password fields
	for _, form := range forms {
		if form.HasPasswordField {
			context.HasPasswords = true
			if context.PageType == "static" {
				context.PageType = "login"
				context.RiskMultiplier = 1.8
			}
			break
		}
	}

	// Check for payment indicators
	paymentKeywords := []string{"credit", "card", "cvv", "cvc", "payment", "billing"}
	for _, keyword := range paymentKeywords {
		if strings.Contains(htmlLower, keyword) {
			context.HasPayment = true
			if context.PageType == "static" {
				context.PageType = "payment"
				context.RiskMultiplier = 2.0
			}
			break
		}
	}

	return context
}

// calculateContextAwareScore computes security score with context-aware weighting
func (c *Checker) calculateContextAwareScore(issues []SecurityIssue, context SecurityContext) int {
	baseScore := 100.0

	// Base deductions per severity
	basePenalties := map[string]float64{
		"critical": 25.0,
		"high":     15.0,
		"medium":   8.0,
		"low":      3.0,
	}

	// Apply context-based multipliers to certain issue types
	for _, issue := range issues {
		basePenalty := basePenalties[issue.Severity]
		multiplier := 1.0

		// Apply context-specific multipliers
		switch issue.Type {
		case "form", "auth", "auth-bypass", "credentials":
			// Authentication issues are more severe on login/payment pages
			if context.PageType == "login" || context.PageType == "payment" {
				multiplier = 1.5
			}
		case "mixed-content", "sri":
			// Mixed content is more severe on HTTPS payment pages
			if context.IsHTTPS && context.HasPayment {
				multiplier = 1.3
			}
		case "cookie", "session":
			// Cookie/session issues matter more on authenticated pages
			if context.HasPasswords || context.PageType == "login" {
				multiplier = 1.4
			}
		case "client-xss", "data-exposure":
			// XSS and data exposure are critical on all interactive pages
			if context.HasForms {
				multiplier = 1.2
			}
		case "cors":
			// CORS issues matter more on API endpoints
			if context.PageType == "api" {
				multiplier = 1.5
			}
		}

		baseScore -= (basePenalty * multiplier)
	}

	// Ensure score doesn't go below 0 or above 100
	if baseScore < 0 {
		baseScore = 0
	}
	if baseScore > 100 {
		baseScore = 100
	}

	return int(baseScore)
}

// createCategorySummary creates a summary for a category of security issues
func (c *Checker) createCategorySummary(issues []SecurityIssue, category string) *SecuritySummary {
	if len(issues) == 0 {
		return nil
	}

	summary := &SecuritySummary{
		TotalIssues: len(issues),
		TopIssues:   []string{},
	}

	// Count by severity
	for _, issue := range issues {
		switch issue.Severity {
		case "critical":
			summary.CriticalCount++
		case "high":
			summary.HighCount++
		case "medium":
			summary.MediumCount++
		case "low":
			summary.LowCount++
		}

		// Add top 3 issues
		if len(summary.TopIssues) < 3 {
			summary.TopIssues = append(summary.TopIssues, issue.Title)
		}
	}

	return summary
}

// parseCookieString parses a Set-Cookie header value into an http.Cookie
func parseCookieString(cookieStr string) *http.Cookie {
	parts := strings.Split(cookieStr, ";")
	if len(parts) == 0 {
		return nil
	}

	// Parse name=value
	nameValue := strings.TrimSpace(parts[0])
	idx := strings.Index(nameValue, "=")
	if idx <= 0 {
		return nil
	}

	cookie := &http.Cookie{
		Name:  nameValue[:idx],
		Value: nameValue[idx+1:],
	}

	// Parse attributes
	for i := 1; i < len(parts); i++ {
		attr := strings.TrimSpace(strings.ToLower(parts[i]))

		if attr == "secure" {
			cookie.Secure = true
		} else if attr == "httponly" {
			cookie.HttpOnly = true
		} else if strings.HasPrefix(attr, "samesite=") {
			sameSiteValue := strings.TrimPrefix(attr, "samesite=")
			switch sameSiteValue {
			case "strict":
				cookie.SameSite = http.SameSiteStrictMode
			case "lax":
				cookie.SameSite = http.SameSiteLaxMode
			case "none":
				cookie.SameSite = http.SameSiteNoneMode
			}
		} else if strings.HasPrefix(attr, "path=") {
			cookie.Path = strings.TrimPrefix(parts[i], "Path=")
		} else if strings.HasPrefix(attr, "domain=") {
			cookie.Domain = strings.TrimPrefix(parts[i], "Domain=")
		}
	}

	return cookie
}

// NormalizeURL ensures the URL has a scheme and is properly formatted
// Helper function for future use
func NormalizeURL(rawURL string) string {
	// If URL doesn't have a scheme, add https://
	if !strings.HasPrefix(rawURL, "http://") && !strings.HasPrefix(rawURL, "https://") {
		return "https://" + rawURL
	}
	return rawURL
}
