package checker

import (
	"fmt"
	"net/http"
	"regexp"
	"strings"
	"math"

	"github.com/PuerkitoBio/goquery"
)

// PaymentDetector orchestrates comprehensive payment method detection
type PaymentDetector struct {
	providers      map[string]*PaymentProvider
	htmlAnalyzer   *PaymentHTMLAnalyzer
	jsAnalyzer     *PaymentJSAnalyzer
	apiDetector    *PaymentAPIDetector
	flowAnalyzer   *CheckoutFlowAnalyzer
	scorer         *PaymentConfidenceScorer
}

// PaymentProvider represents a payment service provider
type PaymentProvider struct {
	ID             string
	Name           string
	Category       string // gateway, processor, wallet, crypto, bnpl
	Priority       int
	Signatures     ProviderSignatures
	RiskAssessment RiskInfo
	ComplianceInfo ComplianceInfo
}

// ProviderSignatures contains patterns to identify a payment provider
type ProviderSignatures struct {
	// HTML/DOM patterns
	DOMSelectors   []string
	HTMLPatterns   []*regexp.Regexp
	FormFields     []string
	IframePatterns []string
	ButtonClasses  []string
	DataAttributes []string

	// JavaScript patterns
	JSObjects      []string
	JSFunctions    []string
	ScriptSources  []string
	SDKPatterns    []*regexp.Regexp

	// Network patterns
	APIEndpoints   []string
	WebhookURLs    []string
	CDNPatterns    []string

	// Headers and cookies
	Headers        map[string]*regexp.Regexp
	Cookies        map[string]*regexp.Regexp
}

// RiskInfo contains risk assessment for a payment provider
type RiskInfo struct {
	SecurityLevel   string   // high, medium, low
	CommonIssues    []string
	BestPractices   []string
}

// ComplianceInfo contains compliance information
type ComplianceInfo struct {
	PCICompliant bool
	Certifications []string
	DataProtection string
}

// PaymentDetectionResult represents the complete payment analysis
type PaymentDetectionResult struct {
	Providers       []DetectedProvider   `json:"providers"`
	PaymentMethods  []string            `json:"payment_methods"`
	CheckoutFlow    *CheckoutFlow       `json:"checkout_flow,omitempty"`
	Compliance      ComplianceAnalysis  `json:"compliance"`
	RiskAssessment  PaymentRiskAnalysis `json:"risk_assessment"`
	Evidence        PaymentEvidence     `json:"evidence"`
}

// DetectedProvider represents a detected payment provider
type DetectedProvider struct {
	Provider       string            `json:"provider"`
	Name           string            `json:"name"`
	Category       string            `json:"category"`
	Confidence     string            `json:"confidence"`
	ConfidenceScore float64          `json:"confidence_score"`
	Evidence       ProviderEvidence  `json:"evidence"`
	CheckoutType   string            `json:"checkout_type,omitempty"`
	Version        string            `json:"version,omitempty"`
}

// ProviderEvidence contains evidence for provider detection
type ProviderEvidence struct {
	HTMLElements   []string `json:"html_elements,omitempty"`
	JSObjects      []string `json:"js_objects,omitempty"`
	APIEndpoints   []string `json:"api_endpoints,omitempty"`
	ScriptSources  []string `json:"script_sources,omitempty"`
	IframeCheckout bool     `json:"iframe_checkout"`
	FormFields     []string `json:"form_fields,omitempty"`
}

// CheckoutFlow represents the checkout process analysis
type CheckoutFlow struct {
	Type               string              `json:"type"`
	CurrentPhase       string              `json:"current_phase,omitempty"`
	DetectedSteps      []string            `json:"detected_steps,omitempty"`
	PaymentOptions     []PaymentOption     `json:"payment_options,omitempty"`
	SecurityIndicators []string            `json:"security_indicators,omitempty"`
	OneClickCheckout   bool                `json:"one_click_checkout"`
}

// PaymentOption represents an available payment method
type PaymentOption struct {
	Method      string `json:"method"`
	Provider    string `json:"provider,omitempty"`
	Available   bool   `json:"available"`
	Default     bool   `json:"default,omitempty"`
}

// ComplianceAnalysis represents compliance status
type ComplianceAnalysis struct {
	PCIIndicators      bool     `json:"pci_indicators"`
	SecureTransmission bool     `json:"secure_transmission"`
	DataProtection     string   `json:"data_protection"`
	ComplianceBadges   []string `json:"compliance_badges,omitempty"`
}

// PaymentRiskAnalysis represents risk assessment
type PaymentRiskAnalysis struct {
	Level        string   `json:"level"`
	Score        int      `json:"score"`
	Factors      []string `json:"factors,omitempty"`
	Warnings     []string `json:"warnings,omitempty"`
	Suggestions  []string `json:"suggestions,omitempty"`
}

// PaymentEvidence contains all detection evidence
type PaymentEvidence struct {
	HTMLAnalysis    *PaymentHTMLResult    `json:"html_analysis,omitempty"`
	JSAnalysis      *PaymentJSResult      `json:"js_analysis,omitempty"`
	APIDetection    []PaymentAPI          `json:"api_detection,omitempty"`
	NetworkRequests []string              `json:"network_requests,omitempty"`
}

// PaymentHTMLResult contains HTML analysis results
type PaymentHTMLResult struct {
	CreditCardForms   []CreditCardForm   `json:"credit_card_forms,omitempty"`
	PaymentButtons    []PaymentButton    `json:"payment_buttons,omitempty"`
	EmbeddedCheckouts []EmbeddedCheckout `json:"embedded_checkouts,omitempty"`
	PaymentBadges     []string           `json:"payment_badges,omitempty"`
	CheckoutElements  []CheckoutElement  `json:"checkout_elements,omitempty"`
	WalletButtons     []WalletButton     `json:"wallet_buttons,omitempty"`
}

// CreditCardForm represents a detected credit card form
type CreditCardForm struct {
	FormID       string   `json:"form_id,omitempty"`
	Fields       []string `json:"fields"`
	Secure       bool     `json:"secure"`
	Provider     string   `json:"provider,omitempty"`
	Tokenization bool     `json:"tokenization"`
}

// PaymentButton represents a payment button
type PaymentButton struct {
	Text     string `json:"text"`
	Type     string `json:"type"`
	Provider string `json:"provider,omitempty"`
	Element  string `json:"element"`
}

// EmbeddedCheckout represents an embedded checkout iframe
type EmbeddedCheckout struct {
	Source   string `json:"source"`
	Provider string `json:"provider"`
	Secure   bool   `json:"secure"`
}

// CheckoutElement represents a checkout-related element
type CheckoutElement struct {
	Type    string `json:"type"`
	Content string `json:"content"`
	Purpose string `json:"purpose,omitempty"`
}

// WalletButton represents a digital wallet button
type WalletButton struct {
	Wallet   string `json:"wallet"`
	Detected bool   `json:"detected"`
	Element  string `json:"element,omitempty"`
}

// PaymentJSResult contains JavaScript analysis results
type PaymentJSResult struct {
	GlobalObjects      []string           `json:"global_objects,omitempty"`
	SDKInitializations []SDKInit          `json:"sdk_initializations,omitempty"`
	APIPatterns        []string           `json:"api_patterns,omitempty"`
	PaymentEvents      []PaymentEvent     `json:"payment_events,omitempty"`
	Tokenization       bool               `json:"tokenization"`
}

// SDKInit represents SDK initialization
type SDKInit struct {
	Provider string `json:"provider"`
	Method   string `json:"method"`
	Version  string `json:"version,omitempty"`
}

// PaymentEvent represents a payment-related event
type PaymentEvent struct {
	Event    string `json:"event"`
	Provider string `json:"provider,omitempty"`
	Type     string `json:"type"`
}

// PaymentAPI represents detected API endpoint
type PaymentAPI struct {
	Provider string `json:"provider"`
	Endpoint string `json:"endpoint"`
	Method   string `json:"method"`
	Type     string `json:"type"`
}

// ConfidenceScore represents detection confidence
type ConfidenceScore struct {
	Overall float64            `json:"overall"`
	Level   string             `json:"level"`
	Details map[string]float64 `json:"details"`
}

// NewPaymentDetector creates a new payment detector
func NewPaymentDetector() *PaymentDetector {
	d := &PaymentDetector{
		providers:    make(map[string]*PaymentProvider),
		scorer:       NewPaymentConfidenceScorer(),
	}

	// Initialize sub-components
	d.htmlAnalyzer = NewPaymentHTMLAnalyzer()
	d.jsAnalyzer = NewPaymentJSAnalyzer()
	d.apiDetector = NewPaymentAPIDetector()
	d.flowAnalyzer = NewCheckoutFlowAnalyzer()

	// Initialize provider database
	d.initializeProviders()

	return d
}

// Detect performs comprehensive payment detection
func (d *PaymentDetector) Detect(html string, headers http.Header, scripts []string, networkData []NetworkRequest) *PaymentDetectionResult {
	result := &PaymentDetectionResult{
		Providers:      []DetectedProvider{},
		PaymentMethods: []string{},
		Evidence:       PaymentEvidence{},
	}

	// Parse HTML
	doc, err := goquery.NewDocumentFromReader(strings.NewReader(html))
	if err != nil {
		return result
	}

	// 1. HTML Analysis
	htmlResult := d.htmlAnalyzer.Analyze(html, doc)
	result.Evidence.HTMLAnalysis = &htmlResult

	// 2. JavaScript Analysis
	if len(scripts) > 0 {
		jsResult := d.jsAnalyzer.AnalyzeScripts(scripts)
		result.Evidence.JSAnalysis = &jsResult
	}

	// 3. API Endpoint Detection
	if len(networkData) > 0 {
		apiResults := d.apiDetector.DetectAPICalls(networkData)
		result.Evidence.APIDetection = apiResults
	}

	// 4. Provider Detection
	detectedProviders := d.detectProviders(html, doc, headers, &htmlResult, result.Evidence.JSAnalysis, result.Evidence.APIDetection)
	result.Providers = detectedProviders

	// 5. Extract Payment Methods
	result.PaymentMethods = d.extractPaymentMethods(detectedProviders, &htmlResult)

	// 6. Analyze Checkout Flow
	result.CheckoutFlow = d.flowAnalyzer.AnalyzeFlow(html, doc, &htmlResult)

	// 7. Compliance Analysis
	result.Compliance = d.analyzeCompliance(html, headers, detectedProviders)

	// 8. Risk Assessment
	result.RiskAssessment = d.assessRisk(result)

	return result
}

// detectProviders identifies payment providers from all evidence
func (d *PaymentDetector) detectProviders(html string, doc *goquery.Document, headers http.Header,
	htmlResult *PaymentHTMLResult, jsResult *PaymentJSResult, apiDetection []PaymentAPI) []DetectedProvider {

	detected := []DetectedProvider{}
	processedProviders := make(map[string]bool)

	// Check each provider
	for providerID, provider := range d.providers {
		evidence := ProviderEvidence{}
		confidenceFactors := make(map[string]bool)

		// HTML Evidence
		htmlEvidence := d.checkHTMLEvidence(html, doc, provider, htmlResult)
		if len(htmlEvidence.HTMLElements) > 0 || len(htmlEvidence.FormFields) > 0 ||
		   len(htmlEvidence.ScriptSources) > 0 || htmlEvidence.IframeCheckout {
			evidence = htmlEvidence
			confidenceFactors["html"] = true
		}

		// JavaScript Evidence
		if jsResult != nil {
			jsEvidence := d.checkJSEvidence(jsResult, provider)
			if len(jsEvidence.JSObjects) > 0 {
				evidence.JSObjects = jsEvidence.JSObjects
				confidenceFactors["javascript"] = true
			}
		}

		// API Evidence
		apiEvidence := d.checkAPIEvidence(apiDetection, provider)
		if len(apiEvidence.APIEndpoints) > 0 {
			evidence.APIEndpoints = apiEvidence.APIEndpoints
			confidenceFactors["api"] = true
		}

		// Header Evidence
		headerEvidence := d.checkHeaderEvidence(headers, provider)
		if headerEvidence {
			confidenceFactors["headers"] = true
		}

		// Calculate confidence if evidence found
		if len(confidenceFactors) > 0 && !processedProviders[providerID] {
			confidence := d.calculateProviderConfidence(confidenceFactors)

			detected = append(detected, DetectedProvider{
				Provider:        providerID,
				Name:            provider.Name,
				Category:        provider.Category,
				Confidence:      confidence.Level,
				ConfidenceScore: confidence.Overall,
				Evidence:        evidence,
				CheckoutType:    d.determineCheckoutType(evidence),
			})

			processedProviders[providerID] = true
		}
	}

	return detected
}

// checkHTMLEvidence checks for HTML-based provider evidence
func (d *PaymentDetector) checkHTMLEvidence(html string, doc *goquery.Document,
	provider *PaymentProvider, htmlResult *PaymentHTMLResult) ProviderEvidence {

	evidence := ProviderEvidence{
		HTMLElements:  []string{},
		FormFields:    []string{},
		ScriptSources: []string{},
	}

	// Check HTML patterns
	for _, pattern := range provider.Signatures.HTMLPatterns {
		if pattern.MatchString(html) {
			evidence.HTMLElements = append(evidence.HTMLElements, pattern.String())
		}
	}

	// Check DOM selectors
	for _, selector := range provider.Signatures.DOMSelectors {
		if doc.Find(selector).Length() > 0 {
			evidence.HTMLElements = append(evidence.HTMLElements, selector)
		}
	}

	// Check script sources
	doc.Find("script[src]").Each(func(i int, s *goquery.Selection) {
		src, _ := s.Attr("src")
		for _, pattern := range provider.Signatures.ScriptSources {
			if strings.Contains(src, pattern) {
				evidence.ScriptSources = append(evidence.ScriptSources, src)
				break
			}
		}
	})

	// Check iframe patterns
	for _, iframe := range htmlResult.EmbeddedCheckouts {
		for _, pattern := range provider.Signatures.IframePatterns {
			if strings.Contains(iframe.Source, pattern) {
				evidence.IframeCheckout = true
				break
			}
		}
	}

	// Check form fields
	for _, form := range htmlResult.CreditCardForms {
		if form.Provider == provider.ID {
			evidence.FormFields = form.Fields
		}
	}

	return evidence
}

// checkJSEvidence checks for JavaScript-based provider evidence
func (d *PaymentDetector) checkJSEvidence(jsResult *PaymentJSResult, provider *PaymentProvider) ProviderEvidence {
	evidence := ProviderEvidence{
		JSObjects: []string{},
	}

	// Check global objects
	for _, obj := range jsResult.GlobalObjects {
		for _, pattern := range provider.Signatures.JSObjects {
			if strings.EqualFold(obj, pattern) {
				evidence.JSObjects = append(evidence.JSObjects, obj)
			}
		}
	}

	// Check SDK initializations
	for _, sdk := range jsResult.SDKInitializations {
		if strings.EqualFold(sdk.Provider, provider.ID) {
			evidence.JSObjects = append(evidence.JSObjects, sdk.Method)
		}
	}

	return evidence
}

// checkAPIEvidence checks for API endpoint evidence
func (d *PaymentDetector) checkAPIEvidence(apiDetection []PaymentAPI, provider *PaymentProvider) ProviderEvidence {
	evidence := ProviderEvidence{
		APIEndpoints: []string{},
	}

	for _, api := range apiDetection {
		if strings.EqualFold(api.Provider, provider.ID) {
			evidence.APIEndpoints = append(evidence.APIEndpoints, api.Endpoint)
		}
	}

	return evidence
}

// checkHeaderEvidence checks for header-based provider evidence
func (d *PaymentDetector) checkHeaderEvidence(headers http.Header, provider *PaymentProvider) bool {
	if provider.Signatures.Headers == nil {
		return false
	}

	for headerName, pattern := range provider.Signatures.Headers {
		headerValue := headers.Get(headerName)
		if headerValue != "" && pattern.MatchString(headerValue) {
			return true
		}
	}

	return false
}

// calculateProviderConfidence calculates confidence score for provider detection
func (d *PaymentDetector) calculateProviderConfidence(factors map[string]bool) ConfidenceScore {
	score := ConfidenceScore{
		Details: make(map[string]float64),
	}

	// Weight factors
	weights := map[string]float64{
		"html":       0.25,
		"javascript": 0.35,
		"api":        0.40,
		"headers":    0.20,
	}

	// Calculate weighted score
	for factor, detected := range factors {
		if detected {
			weight := weights[factor]
			score.Overall += weight
			score.Details[factor] = weight
		}
	}

	// Normalize to 0-100
	score.Overall = math.Min(score.Overall * 100, 100)

	// Determine level
	switch {
	case score.Overall >= 80:
		score.Level = "very_high"
	case score.Overall >= 60:
		score.Level = "high"
	case score.Overall >= 40:
		score.Level = "medium"
	case score.Overall >= 20:
		score.Level = "low"
	default:
		score.Level = "very_low"
	}

	return score
}

// determineCheckoutType determines the type of checkout implementation
func (d *PaymentDetector) determineCheckoutType(evidence ProviderEvidence) string {
	if evidence.IframeCheckout {
		return "embedded_iframe"
	}
	if len(evidence.JSObjects) > 0 {
		return "integrated_sdk"
	}
	if len(evidence.APIEndpoints) > 0 {
		return "api_based"
	}
	if len(evidence.FormFields) > 0 {
		return "hosted_redirect"
	}
	return "unknown"
}

// extractPaymentMethods extracts available payment methods
func (d *PaymentDetector) extractPaymentMethods(providers []DetectedProvider, htmlResult *PaymentHTMLResult) []string {
	methods := make(map[string]bool)

	// From providers
	for _, provider := range providers {
		switch provider.Category {
		case "gateway", "processor":
			methods["credit_card"] = true
		case "wallet":
			methods[strings.ToLower(provider.Name)] = true
		case "bnpl":
			methods["buy_now_pay_later"] = true
		case "crypto":
			methods["cryptocurrency"] = true
		}
	}

	// From HTML analysis
	if len(htmlResult.CreditCardForms) > 0 {
		methods["credit_card"] = true
	}

	for _, wallet := range htmlResult.WalletButtons {
		if wallet.Detected {
			methods[strings.ToLower(wallet.Wallet)] = true
		}
	}

	// Convert to slice
	result := []string{}
	for method := range methods {
		result = append(result, method)
	}

	return result
}

// analyzeCompliance performs compliance analysis
func (d *PaymentDetector) analyzeCompliance(html string, headers http.Header, providers []DetectedProvider) ComplianceAnalysis {
	compliance := ComplianceAnalysis{
		PCIIndicators:      false,
		SecureTransmission: false,
		DataProtection:     "unknown",
		ComplianceBadges:   []string{},
	}

	// Check for HTTPS (from headers or HTML)
	if scheme := headers.Get("X-Forwarded-Proto"); scheme == "https" {
		compliance.SecureTransmission = true
	}

	// Check for PCI compliance indicators
	pciKeywords := []string{"pci", "pci-dss", "pci compliant", "payment card industry"}
	htmlLower := strings.ToLower(html)
	for _, keyword := range pciKeywords {
		if strings.Contains(htmlLower, keyword) {
			compliance.PCIIndicators = true
			break
		}
	}

	// Check for compliance badges
	badgePatterns := []string{
		"pci-dss", "ssl-secure", "norton-secured", "mcafee-secure",
		"trustwave", "comodo-secure", "geotrust", "verified-by-visa",
		"mastercard-securecode", "american-express-safekey",
	}

	for _, pattern := range badgePatterns {
		if strings.Contains(htmlLower, pattern) {
			compliance.ComplianceBadges = append(compliance.ComplianceBadges, pattern)
		}
	}

	// Check provider compliance
	for _, provider := range providers {
		if p, exists := d.providers[provider.Provider]; exists {
			if p.ComplianceInfo.PCICompliant {
				compliance.PCIIndicators = true
			}
			if p.ComplianceInfo.DataProtection != "" {
				compliance.DataProtection = p.ComplianceInfo.DataProtection
			}
		}
	}

	return compliance
}

// assessRisk performs risk assessment
func (d *PaymentDetector) assessRisk(result *PaymentDetectionResult) PaymentRiskAnalysis {
	risk := PaymentRiskAnalysis{
		Level:       "low",
		Score:       0,
		Factors:     []string{},
		Warnings:    []string{},
		Suggestions: []string{},
	}

	// Positive factors (reduce risk)
	if result.Compliance.SecureTransmission {
		risk.Factors = append(risk.Factors, "secure_transmission")
	}
	if result.Compliance.PCIIndicators {
		risk.Factors = append(risk.Factors, "pci_compliance_indicated")
	}
	if len(result.Providers) > 0 {
		for _, provider := range result.Providers {
			if provider.Confidence == "high" || provider.Confidence == "very_high" {
				risk.Factors = append(risk.Factors, fmt.Sprintf("trusted_provider_%s", provider.Name))
			}
		}
	}

	// Negative factors (increase risk)
	if !result.Compliance.SecureTransmission {
		risk.Score += 30
		risk.Warnings = append(risk.Warnings, "Payment page not using HTTPS")
		risk.Suggestions = append(risk.Suggestions, "Always use HTTPS for payment pages")
	}

	// Check for custom/unknown implementations
	hasCustomImplementation := true
	for _, provider := range result.Providers {
		if provider.Category == "gateway" || provider.Category == "processor" {
			hasCustomImplementation = false
			break
		}
	}

	if hasCustomImplementation && len(result.Evidence.HTMLAnalysis.CreditCardForms) > 0 {
		risk.Score += 20
		risk.Warnings = append(risk.Warnings, "Custom payment implementation detected")
		risk.Suggestions = append(risk.Suggestions, "Consider using established payment gateways")
	}

	// Determine risk level
	switch {
	case risk.Score >= 70:
		risk.Level = "high"
	case risk.Score >= 40:
		risk.Level = "medium"
	default:
		risk.Level = "low"
	}

	return risk
}