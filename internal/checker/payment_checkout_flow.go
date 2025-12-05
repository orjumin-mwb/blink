package checker

import (
	"strings"

	"github.com/PuerkitoBio/goquery"
)

// CheckoutFlowAnalyzer analyzes the checkout flow and current phase
type CheckoutFlowAnalyzer struct {
	phaseKeywords map[string][]string
	stepIndicators []string
}

// NewCheckoutFlowAnalyzer creates a new checkout flow analyzer
func NewCheckoutFlowAnalyzer() *CheckoutFlowAnalyzer {
	return &CheckoutFlowAnalyzer{
		phaseKeywords: map[string][]string{
			"cart": {
				"shopping cart", "cart", "basket", "bag",
				"view cart", "cart items",
			},
			"shipping": {
				"shipping", "delivery", "shipping address",
				"delivery address", "ship to",
			},
			"payment": {
				"payment", "billing", "payment method",
				"card details", "pay now", "checkout",
			},
			"review": {
				"review order", "order review", "confirm",
				"order summary", "place order",
			},
			"success": {
				"order confirmation", "thank you", "order complete",
				"payment successful", "order received",
			},
		},
		stepIndicators: []string{
			"step-", "checkout-step", "progress-step",
		},
	}
}

// AnalyzeFlow analyzes the checkout flow
func (a *CheckoutFlowAnalyzer) AnalyzeFlow(html string, doc *goquery.Document, htmlResult *PaymentHTMLResult) *CheckoutFlow {
	flow := &CheckoutFlow{
		Type:               "unknown",
		DetectedSteps:      []string{},
		PaymentOptions:     []PaymentOption{},
		SecurityIndicators: []string{},
		OneClickCheckout:   false,
	}

	htmlLower := strings.ToLower(html)

	// 1. Identify checkout phase
	flow.CurrentPhase = a.identifyCheckoutPhase(htmlLower, doc)

	// 2. Detect checkout type
	flow.Type = a.detectCheckoutType(doc, htmlResult)

	// 3. Detect checkout steps
	flow.DetectedSteps = a.detectCheckoutSteps(doc)

	// 4. Extract payment options
	flow.PaymentOptions = a.extractPaymentOptions(doc, htmlResult)

	// 5. Find security indicators
	flow.SecurityIndicators = a.findSecurityIndicators(htmlLower, doc)

	// 6. Check for one-click checkout
	flow.OneClickCheckout = a.detectOneClickCheckout(htmlLower, doc)

	return flow
}

// identifyCheckoutPhase determines the current checkout phase
func (a *CheckoutFlowAnalyzer) identifyCheckoutPhase(html string, doc *goquery.Document) string {
	// Count matches for each phase
	phaseScores := make(map[string]int)

	for phase, keywords := range a.phaseKeywords {
		score := 0
		for _, keyword := range keywords {
			if strings.Contains(html, keyword) {
				score++
			}
		}
		phaseScores[phase] = score
	}

	// Find phase with highest score
	maxScore := 0
	currentPhase := "unknown"

	for phase, score := range phaseScores {
		if score > maxScore {
			maxScore = score
			currentPhase = phase
		}
	}

	// If no clear phase, check URL-based indicators
	if maxScore == 0 {
		doc.Find("meta[property='og:url'], link[rel='canonical']").Each(func(i int, el *goquery.Selection) {
			url := el.AttrOr("content", el.AttrOr("href", ""))
			urlLower := strings.ToLower(url)

			for phase, keywords := range a.phaseKeywords {
				for _, keyword := range keywords {
					if strings.Contains(urlLower, keyword) {
						currentPhase = phase
						return
					}
				}
			}
		})
	}

	return currentPhase
}

// detectCheckoutType determines the type of checkout implementation
func (a *CheckoutFlowAnalyzer) detectCheckoutType(doc *goquery.Document, htmlResult *PaymentHTMLResult) string {
	// Single page checkout
	if doc.Find(".checkout-container, #checkout, .single-page-checkout").Length() > 0 {
		return "single_page"
	}

	// Multi-step checkout
	if doc.Find(".checkout-steps, .progress-steps, [class*='step-']").Length() > 0 {
		return "multi_step"
	}

	// Embedded checkout (iframe)
	if len(htmlResult.EmbeddedCheckouts) > 0 {
		return "embedded"
	}

	// Express checkout (wallet buttons without forms)
	if len(htmlResult.WalletButtons) > 0 && len(htmlResult.CreditCardForms) == 0 {
		return "express"
	}

	// Modal/popup checkout
	if doc.Find(".checkout-modal, .modal-checkout, #checkout-modal").Length() > 0 {
		return "modal"
	}

	return "unknown"
}

// detectCheckoutSteps finds visible checkout steps
func (a *CheckoutFlowAnalyzer) detectCheckoutSteps(doc *goquery.Document) []string {
	steps := []string{}
	stepMap := make(map[string]bool)

	// Find step indicators
	doc.Find("[class*='step-'], .checkout-step, .progress-step").Each(func(i int, el *goquery.Selection) {
		text := strings.TrimSpace(el.Text())
		textLower := strings.ToLower(text)

		// Common step names
		stepNames := map[string]string{
			"cart":     "cart",
			"shipping": "shipping",
			"payment":  "payment",
			"billing":  "billing",
			"review":   "review",
			"confirm":  "confirmation",
		}

		for keyword, stepName := range stepNames {
			if strings.Contains(textLower, keyword) && !stepMap[stepName] {
				steps = append(steps, stepName)
				stepMap[stepName] = true
				break
			}
		}
	})

	return steps
}

// extractPaymentOptions finds available payment methods
func (a *CheckoutFlowAnalyzer) extractPaymentOptions(doc *goquery.Document, htmlResult *PaymentHTMLResult) []PaymentOption {
	options := []PaymentOption{}
	optionMap := make(map[string]bool)

	// From credit card forms
	if len(htmlResult.CreditCardForms) > 0 {
		options = append(options, PaymentOption{
			Method:    "credit_card",
			Available: true,
		})
		optionMap["credit_card"] = true
	}

	// From wallet buttons
	for _, wallet := range htmlResult.WalletButtons {
		if wallet.Detected && !optionMap[wallet.Wallet] {
			options = append(options, PaymentOption{
				Method:    wallet.Wallet,
				Available: true,
			})
			optionMap[wallet.Wallet] = true
		}
	}

	// From radio buttons or payment method selectors
	doc.Find("input[type='radio'][name*='payment'], select[name*='payment'] option").Each(func(i int, el *goquery.Selection) {
		value := strings.ToLower(el.AttrOr("value", el.Text()))

		methods := map[string]string{
			"credit": "credit_card",
			"card":   "credit_card",
			"paypal": "paypal",
			"stripe": "stripe",
			"bank":   "bank_transfer",
			"cod":    "cash_on_delivery",
			"crypto": "cryptocurrency",
		}

		for keyword, method := range methods {
			if strings.Contains(value, keyword) && !optionMap[method] {
				isDefault := el.HasClass("selected") || el.AttrOr("checked", "") == "checked"
				options = append(options, PaymentOption{
					Method:    method,
					Available: true,
					Default:   isDefault,
				})
				optionMap[method] = true
				break
			}
		}
	})

	return options
}

// findSecurityIndicators finds security-related elements
func (a *CheckoutFlowAnalyzer) findSecurityIndicators(html string, doc *goquery.Document) []string {
	indicators := []string{}
	indicatorMap := make(map[string]bool)

	// Security keywords
	securityKeywords := []string{
		"ssl", "https", "secure", "encrypted",
		"pci compliant", "verified", "protected",
		"safe checkout", "secure payment",
	}

	for _, keyword := range securityKeywords {
		if strings.Contains(html, keyword) && !indicatorMap[keyword] {
			indicators = append(indicators, keyword)
			indicatorMap[keyword] = true
		}
	}

	// Lock icons
	if doc.Find("i.fa-lock, .lock-icon, [class*='secure-icon']").Length() > 0 {
		if !indicatorMap["lock_icon"] {
			indicators = append(indicators, "lock_icon")
			indicatorMap["lock_icon"] = true
		}
	}

	// Security badges
	if doc.Find("img[alt*='secure'], img[src*='ssl'], img[src*='pci']").Length() > 0 {
		if !indicatorMap["security_badge"] {
			indicators = append(indicators, "security_badge")
			indicatorMap["security_badge"] = true
		}
	}

	return indicators
}

// detectOneClickCheckout checks for one-click/express checkout
func (a *CheckoutFlowAnalyzer) detectOneClickCheckout(html string, doc *goquery.Document) bool {
	// Check for one-click keywords
	oneClickKeywords := []string{
		"one-click", "one click", "express checkout",
		"quick checkout", "instant checkout", "buy now",
	}

	for _, keyword := range oneClickKeywords {
		if strings.Contains(html, keyword) {
			return true
		}
	}

	// Check for Amazon Pay or similar
	if doc.Find("[id*='amazon-pay'], [class*='amazon-pay']").Length() > 0 {
		return true
	}

	// Check for Shop Pay
	if strings.Contains(html, "shop pay") || strings.Contains(html, "shoppay") {
		return true
	}

	return false
}
