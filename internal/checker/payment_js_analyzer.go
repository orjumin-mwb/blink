package checker

import (
	"regexp"
)

// PaymentJSAnalyzer analyzes JavaScript code for payment integrations
type PaymentJSAnalyzer struct {
	sdkPatterns      map[string]*regexp.Regexp
	apiCallPatterns  []*regexp.Regexp
	tokenizationHints []*regexp.Regexp
}

// NewPaymentJSAnalyzer creates a new JavaScript analyzer
func NewPaymentJSAnalyzer() *PaymentJSAnalyzer {
	return &PaymentJSAnalyzer{
		sdkPatterns: map[string]*regexp.Regexp{
			"stripe":     regexp.MustCompile(`(?i)Stripe\s*\(['"](pk_[a-zA-Z0-9_]+)['"]`),
			"paypal":     regexp.MustCompile(`(?i)paypal\.Buttons\s*\(`),
			"square":     regexp.MustCompile(`(?i)new\s+SqPaymentForm\s*\(`),
			"braintree":  regexp.MustCompile(`(?i)braintree\.client\.create`),
			"razorpay":   regexp.MustCompile(`(?i)new\s+Razorpay\s*\(`),
			"adyen":      regexp.MustCompile(`(?i)AdyenCheckout\s*\(`),
		},
		apiCallPatterns: []*regexp.Regexp{
			regexp.MustCompile(`(?i)fetch\s*\([^)]*payment`),
			regexp.MustCompile(`(?i)fetch\s*\([^)]*checkout`),
			regexp.MustCompile(`(?i)\.post\s*\([^)]*payment`),
			regexp.MustCompile(`(?i)\.post\s*\([^)]*checkout`),
			regexp.MustCompile(`(?i)createPaymentMethod`),
			regexp.MustCompile(`(?i)createToken`),
		},
		tokenizationHints: []*regexp.Regexp{
			regexp.MustCompile(`(?i)createToken`),
			regexp.MustCompile(`(?i)tokenize`),
			regexp.MustCompile(`(?i)createPaymentMethod`),
		},
	}
}

// AnalyzeScripts analyzes JavaScript code for payment patterns
func (a *PaymentJSAnalyzer) AnalyzeScripts(scripts []string) PaymentJSResult {
	result := PaymentJSResult{
		GlobalObjects:      []string{},
		SDKInitializations: []SDKInit{},
		APIPatterns:        []string{},
		PaymentEvents:      []PaymentEvent{},
		Tokenization:       false,
	}

	globalObjMap := make(map[string]bool)
	sdkMap := make(map[string]bool)

	for _, script := range scripts {
		// 1. Detect global objects
		objects := a.detectGlobalObjects(script)
		for _, obj := range objects {
			if !globalObjMap[obj] {
				result.GlobalObjects = append(result.GlobalObjects, obj)
				globalObjMap[obj] = true
			}
		}

		// 2. Detect SDK initializations
		sdks := a.detectSDKInit(script)
		for _, sdk := range sdks {
			key := sdk.Provider + ":" + sdk.Method
			if !sdkMap[key] {
				result.SDKInitializations = append(result.SDKInitializations, sdk)
				sdkMap[key] = true
			}
		}

		// 3. Detect API patterns
		patterns := a.detectAPIPatterns(script)
		result.APIPatterns = append(result.APIPatterns, patterns...)

		// 4. Detect payment events
		events := a.detectPaymentEvents(script)
		result.PaymentEvents = append(result.PaymentEvents, events...)

		// 5. Check for tokenization
		if !result.Tokenization {
			result.Tokenization = a.detectTokenization(script)
		}
	}

	return result
}

// detectGlobalObjects finds payment-related global objects
func (a *PaymentJSAnalyzer) detectGlobalObjects(script string) []string {
	objects := []string{}

	// List of known payment objects
	paymentObjects := []string{
		"Stripe", "StripeCheckout",
		"PayPal", "paypal",
		"Square", "SqPaymentForm",
		"Braintree", "braintree",
		"Razorpay",
		"Adyen", "AdyenCheckout",
		"ApplePaySession",
		"Klarna",
		"Afterpay",
		"Affirm",
	}

	for _, obj := range paymentObjects {
		// Check if object is used in script
		patterns := []*regexp.Regexp{
			regexp.MustCompile(`(?i)\b` + obj + `\s*\(`),
			regexp.MustCompile(`(?i)\b` + obj + `\s*\.`),
			regexp.MustCompile(`(?i)new\s+` + obj + `\b`),
			regexp.MustCompile(`(?i)window\.` + obj + `\b`),
		}

		for _, pattern := range patterns {
			if pattern.MatchString(script) {
				objects = append(objects, obj)
				break
			}
		}
	}

	return objects
}

// detectSDKInit finds SDK initialization calls
func (a *PaymentJSAnalyzer) detectSDKInit(script string) []SDKInit {
	sdks := []SDKInit{}

	for provider, pattern := range a.sdkPatterns {
		if matches := pattern.FindAllStringSubmatch(script, -1); len(matches) > 0 {
			sdk := SDKInit{
				Provider: provider,
				Method:   "init",
			}

			// Try to extract version or key
			if len(matches[0]) > 1 {
				sdk.Version = matches[0][1]
			}

			sdks = append(sdks, sdk)
		}
	}

	return sdks
}

// detectAPIPatterns finds API call patterns
func (a *PaymentJSAnalyzer) detectAPIPatterns(script string) []string {
	patterns := []string{}
	patternMap := make(map[string]bool)

	for _, pattern := range a.apiCallPatterns {
		if matches := pattern.FindAllString(script, -1); len(matches) > 0 {
			for _, match := range matches {
				if !patternMap[match] {
					patterns = append(patterns, match)
					patternMap[match] = true
				}
			}
		}
	}

	return patterns
}

// detectPaymentEvents finds payment-related event handlers
func (a *PaymentJSAnalyzer) detectPaymentEvents(script string) []PaymentEvent {
	events := []PaymentEvent{}

	// Payment event patterns
	eventPatterns := map[string]*regexp.Regexp{
		"payment_success":   regexp.MustCompile(`(?i)on.*payment.*success`),
		"payment_error":     regexp.MustCompile(`(?i)on.*payment.*error`),
		"payment_cancel":    regexp.MustCompile(`(?i)on.*payment.*cancel`),
		"payment_complete":  regexp.MustCompile(`(?i)on.*payment.*complete`),
		"token_created":     regexp.MustCompile(`(?i)on.*token.*created`),
		"checkout_complete": regexp.MustCompile(`(?i)on.*checkout.*complete`),
	}

	for eventType, pattern := range eventPatterns {
		if pattern.MatchString(script) {
			events = append(events, PaymentEvent{
				Event: eventType,
				Type:  "callback",
			})
		}
	}

	return events
}

// detectTokenization checks if tokenization is being used
func (a *PaymentJSAnalyzer) detectTokenization(script string) bool {
	for _, pattern := range a.tokenizationHints {
		if pattern.MatchString(script) {
			return true
		}
	}
	return false
}
