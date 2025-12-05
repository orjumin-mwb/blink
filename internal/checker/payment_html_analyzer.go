package checker

import (
	"regexp"
	"strings"

	"github.com/PuerkitoBio/goquery"
)

// PaymentHTMLAnalyzer analyzes HTML for payment-related elements
type PaymentHTMLAnalyzer struct {
	cardFieldPatterns    []*regexp.Regexp
	cvvFieldPatterns     []*regexp.Regexp
	expiryFieldPatterns  []*regexp.Regexp
	walletButtonPatterns map[string][]*regexp.Regexp
}

// NewPaymentHTMLAnalyzer creates a new HTML analyzer
func NewPaymentHTMLAnalyzer() *PaymentHTMLAnalyzer {
	return &PaymentHTMLAnalyzer{
		cardFieldPatterns: []*regexp.Regexp{
			regexp.MustCompile(`(?i)card.*number`),
			regexp.MustCompile(`(?i)cc.*number`),
			regexp.MustCompile(`(?i)credit.*card`),
			regexp.MustCompile(`(?i)cardnumber`),
			regexp.MustCompile(`(?i)ccnum`),
		},
		cvvFieldPatterns: []*regexp.Regexp{
			regexp.MustCompile(`(?i)cvv`),
			regexp.MustCompile(`(?i)cvc`),
			regexp.MustCompile(`(?i)cvv2`),
			regexp.MustCompile(`(?i)security.*code`),
			regexp.MustCompile(`(?i)card.*code`),
		},
		expiryFieldPatterns: []*regexp.Regexp{
			regexp.MustCompile(`(?i)exp.*date`),
			regexp.MustCompile(`(?i)expir`),
			regexp.MustCompile(`(?i)cc.*exp`),
			regexp.MustCompile(`(?i)card.*exp`),
		},
		walletButtonPatterns: map[string][]*regexp.Regexp{
			"apple_pay": {
				regexp.MustCompile(`(?i)apple.*pay`),
				regexp.MustCompile(`(?i)applepay`),
			},
			"google_pay": {
				regexp.MustCompile(`(?i)google.*pay`),
				regexp.MustCompile(`(?i)gpay`),
			},
			"paypal": {
				regexp.MustCompile(`(?i)paypal`),
			},
		},
	}
}

// Analyze performs comprehensive HTML analysis for payment elements
func (a *PaymentHTMLAnalyzer) Analyze(html string, doc *goquery.Document) PaymentHTMLResult {
	result := PaymentHTMLResult{
		CreditCardForms:   []CreditCardForm{},
		PaymentButtons:    []PaymentButton{},
		EmbeddedCheckouts: []EmbeddedCheckout{},
		PaymentBadges:     []string{},
		CheckoutElements:  []CheckoutElement{},
		WalletButtons:     []WalletButton{},
	}

	// 1. Detect credit card forms
	result.CreditCardForms = a.detectCreditCardForms(doc)

	// 2. Detect payment buttons
	result.PaymentButtons = a.detectPaymentButtons(doc)

	// 3. Detect embedded checkouts (iframes)
	result.EmbeddedCheckouts = a.detectEmbeddedCheckouts(doc)

	// 4. Detect payment badges/logos
	result.PaymentBadges = a.detectPaymentBadges(html, doc)

	// 5. Detect checkout elements
	result.CheckoutElements = a.detectCheckoutElements(doc)

	// 6. Detect wallet buttons
	result.WalletButtons = a.detectWalletButtons(doc)

	return result
}

// detectCreditCardForms finds forms with credit card fields
func (a *PaymentHTMLAnalyzer) detectCreditCardForms(doc *goquery.Document) []CreditCardForm {
	forms := []CreditCardForm{}

	doc.Find("form").Each(func(i int, form *goquery.Selection) {
		fields := []string{}
		hasCardField := false
		hasCVV := false
		hasExpiry := false
		tokenization := false
		provider := ""

		// Check all inputs in the form
		form.Find("input").Each(func(j int, input *goquery.Selection) {
			name, _ := input.Attr("name")
			id, _ := input.Attr("id")
			class, _ := input.Attr("class")
			dataAttr, _ := input.Attr("data-stripe")

			fieldText := strings.ToLower(name + " " + id + " " + class)

			// Check for card number field
			for _, pattern := range a.cardFieldPatterns {
				if pattern.MatchString(fieldText) {
					hasCardField = true
					fields = append(fields, "card_number")
					break
				}
			}

			// Check for CVV field
			for _, pattern := range a.cvvFieldPatterns {
				if pattern.MatchString(fieldText) {
					hasCVV = true
					fields = append(fields, "cvv")
					break
				}
			}

			// Check for expiry field
			for _, pattern := range a.expiryFieldPatterns {
				if pattern.MatchString(fieldText) {
					hasExpiry = true
					fields = append(fields, "expiry")
					break
				}
			}

			// Check for provider-specific attributes
			if dataAttr != "" {
				tokenization = true
				provider = "stripe"
			}
		})

		// If it looks like a credit card form, add it
		if hasCardField || (hasCVV && hasExpiry) {
			formID, _ := form.Attr("id")
			action, _ := form.Attr("action")
			secure := strings.HasPrefix(action, "https://")

			forms = append(forms, CreditCardForm{
				FormID:       formID,
				Fields:       fields,
				Secure:       secure,
				Provider:     provider,
				Tokenization: tokenization,
			})
		}
	})

	return forms
}

// detectPaymentButtons finds payment-related buttons
func (a *PaymentHTMLAnalyzer) detectPaymentButtons(doc *goquery.Document) []PaymentButton {
	buttons := []PaymentButton{}

	// Check buttons and links
	doc.Find("button, a, input[type='button'], input[type='submit']").Each(func(i int, el *goquery.Selection) {
		text := strings.TrimSpace(el.Text())
		value, _ := el.Attr("value")
		class, _ := el.Attr("class")
		id, _ := el.Attr("id")

		buttonText := strings.ToLower(text + " " + value + " " + class + " " + id)

		// Payment keywords
		paymentKeywords := []string{
			"pay now", "checkout", "complete order", "place order",
			"buy now", "purchase", "confirm payment", "submit payment",
		}

		for _, keyword := range paymentKeywords {
			if strings.Contains(buttonText, keyword) {
				buttons = append(buttons, PaymentButton{
					Text:    text,
					Type:    "checkout",
					Element: el.AttrOr("class", ""),
				})
				break
			}
		}

		// Provider-specific buttons
		if strings.Contains(class, "stripe-button") {
			buttons = append(buttons, PaymentButton{
				Text:     text,
				Type:     "provider",
				Provider: "stripe",
				Element:  class,
			})
		}

		if strings.Contains(class, "paypal-button") || strings.Contains(id, "paypal") {
			buttons = append(buttons, PaymentButton{
				Text:     text,
				Type:     "provider",
				Provider: "paypal",
				Element:  class,
			})
		}
	})

	return buttons
}

// detectEmbeddedCheckouts finds iframe-based embedded checkouts
func (a *PaymentHTMLAnalyzer) detectEmbeddedCheckouts(doc *goquery.Document) []EmbeddedCheckout {
	checkouts := []EmbeddedCheckout{}

	doc.Find("iframe").Each(func(i int, iframe *goquery.Selection) {
		src, exists := iframe.Attr("src")
		if !exists {
			return
		}

		srcLower := strings.ToLower(src)
		provider := ""
		secure := strings.HasPrefix(src, "https://")

		// Check for known providers
		providerPatterns := map[string][]string{
			"stripe": {"stripe.com", "checkout.stripe.com"},
			"paypal": {"paypal.com", "paypalobjects.com"},
			"square": {"squareup.com", "squarecdn.com"},
			"braintree": {"braintree"},
		}

		for p, patterns := range providerPatterns {
			for _, pattern := range patterns {
				if strings.Contains(srcLower, pattern) {
					provider = p
					break
				}
			}
			if provider != "" {
				break
			}
		}

		if provider != "" {
			checkouts = append(checkouts, EmbeddedCheckout{
				Source:   src,
				Provider: provider,
				Secure:   secure,
			})
		}
	})

	return checkouts
}

// detectPaymentBadges finds payment security badges and logos
func (a *PaymentHTMLAnalyzer) detectPaymentBadges(html string, doc *goquery.Document) []string {
	badges := []string{}
	badgeMap := make(map[string]bool)

	htmlLower := strings.ToLower(html)

	// Security badge keywords
	securityBadges := []string{
		"ssl secure", "pci compliant", "secure checkout",
		"norton secured", "mcafee secure", "verisign",
		"trustwave", "comodo secure", "geotrust",
		"secure payment", "encrypted", "verified by visa",
		"mastercard securecode", "american express safekey",
	}

	for _, badge := range securityBadges {
		if strings.Contains(htmlLower, badge) && !badgeMap[badge] {
			badges = append(badges, badge)
			badgeMap[badge] = true
		}
	}

	// Check for badge images
	doc.Find("img").Each(func(i int, img *goquery.Selection) {
		src, _ := img.Attr("src")
		alt, _ := img.Attr("alt")
		title, _ := img.Attr("title")

		imgText := strings.ToLower(src + " " + alt + " " + title)

		for _, badge := range securityBadges {
			if strings.Contains(imgText, badge) && !badgeMap[badge] {
				badges = append(badges, badge)
				badgeMap[badge] = true
				break
			}
		}
	})

	return badges
}

// detectCheckoutElements finds checkout-related elements
func (a *PaymentHTMLAnalyzer) detectCheckoutElements(doc *goquery.Document) []CheckoutElement {
	elements := []CheckoutElement{}

	// Order summary
	doc.Find(".order-summary, #order-summary, .cart-summary, #cart-summary").Each(func(i int, el *goquery.Selection) {
		elements = append(elements, CheckoutElement{
			Type:    "order_summary",
			Content: el.Text(),
			Purpose: "displays order total and items",
		})
	})

	// Payment method selector
	doc.Find("[name='payment_method'], .payment-method, .payment-options").Each(func(i int, el *goquery.Selection) {
		elements = append(elements, CheckoutElement{
			Type:    "payment_method_selector",
			Content: el.AttrOr("id", el.AttrOr("class", "")),
			Purpose: "allows selection of payment method",
		})
	})

	// Billing address
	doc.Find(".billing-address, #billing-address, [name='billing_address']").Each(func(i int, el *goquery.Selection) {
		elements = append(elements, CheckoutElement{
			Type:    "billing_address",
			Content: el.AttrOr("id", ""),
			Purpose: "collects billing information",
		})
	})

	return elements
}

// detectWalletButtons finds digital wallet payment buttons
func (a *PaymentHTMLAnalyzer) detectWalletButtons(doc *goquery.Document) []WalletButton {
	wallets := []WalletButton{}

	// Apple Pay
	applePayDetected := false
	doc.Find(".apple-pay-button, [class*='applepay'], [id*='apple-pay']").Each(func(i int, el *goquery.Selection) {
		if !applePayDetected {
			wallets = append(wallets, WalletButton{
				Wallet:   "apple_pay",
				Detected: true,
				Element:  el.AttrOr("class", ""),
			})
			applePayDetected = true
		}
	})

	// Google Pay
	googlePayDetected := false
	doc.Find(".google-pay-button, [class*='gpay'], [id*='google-pay']").Each(func(i int, el *goquery.Selection) {
		if !googlePayDetected {
			wallets = append(wallets, WalletButton{
				Wallet:   "google_pay",
				Detected: true,
				Element:  el.AttrOr("class", ""),
			})
			googlePayDetected = true
		}
	})

	// PayPal
	paypalDetected := false
	doc.Find(".paypal-button, [id*='paypal'], [class*='paypal']").Each(func(i int, el *goquery.Selection) {
		if !paypalDetected {
			wallets = append(wallets, WalletButton{
				Wallet:   "paypal",
				Detected: true,
				Element:  el.AttrOr("class", ""),
			})
			paypalDetected = true
		}
	})

	// Amazon Pay
	amazonPayDetected := false
	doc.Find("[id*='amazon-pay'], [class*='amazon-pay']").Each(func(i int, el *goquery.Selection) {
		if !amazonPayDetected {
			wallets = append(wallets, WalletButton{
				Wallet:   "amazon_pay",
				Detected: true,
				Element:  el.AttrOr("class", ""),
			})
			amazonPayDetected = true
		}
	})

	return wallets
}
