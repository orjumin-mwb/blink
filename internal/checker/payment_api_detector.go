package checker

import "strings"

// PaymentAPIDetector detects payment API endpoints from network traffic
type PaymentAPIDetector struct {
	endpointPatterns map[string][]string
}

// NewPaymentAPIDetector creates a new API detector
func NewPaymentAPIDetector() *PaymentAPIDetector {
	d := &PaymentAPIDetector{
		endpointPatterns: make(map[string][]string),
	}
	d.initializeEndpoints()
	return d
}

// initializeEndpoints sets up known payment API endpoint patterns
func (d *PaymentAPIDetector) initializeEndpoints() {
	d.endpointPatterns = map[string][]string{
		"stripe": {
			"api.stripe.com/v1/payment_intents",
			"api.stripe.com/v1/checkout/sessions",
			"api.stripe.com/v1/customers",
			"api.stripe.com/v1/tokens",
			"api.stripe.com/v1/payment_methods",
			"checkout.stripe.com",
		},
		"paypal": {
			"api.paypal.com/v2/checkout/orders",
			"api.paypal.com/v1/payments",
			"api.paypal.com/v1/oauth2/token",
			"www.paypal.com/checkoutnow",
		},
		"square": {
			"connect.squareup.com/v2/payments",
			"connect.squareup.com/v2/customers",
			"connect.squareup.com/v2/orders",
		},
		"adyen": {
			"checkout-test.adyen.com",
			"checkout-live.adyen.com",
			"pal-test.adyen.com",
			"pal-live.adyen.com",
		},
		"braintree": {
			"api.braintreegateway.com",
			"payments.braintree-api.com",
		},
		"authorize.net": {
			"api.authorize.net",
			"apitest.authorize.net",
		},
		"razorpay": {
			"api.razorpay.com",
		},
		"mollie": {
			"api.mollie.com",
		},
		"checkout.com": {
			"api.checkout.com",
		},
		"klarna": {
			"api.klarna.com",
			"api.playground.klarna.com",
		},
		"coinbase": {
			"commerce.coinbase.com/charges",
			"api.commerce.coinbase.com",
		},
		"bitpay": {
			"bitpay.com/invoices",
		},
	}
}

// DetectAPICalls analyzes network requests for payment API calls
func (d *PaymentAPIDetector) DetectAPICalls(networkData []NetworkRequest) []PaymentAPI {
	detected := []PaymentAPI{}
	detectedMap := make(map[string]bool)

	for _, request := range networkData {
		urlLower := strings.ToLower(request.URL)

		// Check against known patterns
		for provider, patterns := range d.endpointPatterns {
			for _, pattern := range patterns {
				if strings.Contains(urlLower, strings.ToLower(pattern)) {
					key := provider + ":" + request.URL
					if !detectedMap[key] {
						detected = append(detected, PaymentAPI{
							Provider: provider,
							Endpoint: request.URL,
							Method:   request.Method,
							Type:     d.classifyAPICall(request.URL),
						})
						detectedMap[key] = true
					}
					break
				}
			}
		}
	}

	return detected
}

// classifyAPICall determines the type of payment API call
func (d *PaymentAPIDetector) classifyAPICall(url string) string {
	urlLower := strings.ToLower(url)

	callTypes := map[string][]string{
		"payment_intent": {"payment_intent", "payment-intent"},
		"checkout":       {"checkout", "session"},
		"token":          {"token", "tokenize"},
		"customer":       {"customer", "user"},
		"order":          {"order", "purchase"},
		"charge":         {"charge", "payment"},
		"refund":         {"refund"},
		"webhook":        {"webhook", "callback"},
	}

	for callType, keywords := range callTypes {
		for _, keyword := range keywords {
			if strings.Contains(urlLower, keyword) {
				return callType
			}
		}
	}

	return "unknown"
}

// matchAPIEndpoint finds which provider an endpoint belongs to
func (d *PaymentAPIDetector) matchAPIEndpoint(url string) string {
	urlLower := strings.ToLower(url)

	for provider, patterns := range d.endpointPatterns {
		for _, pattern := range patterns {
			if strings.Contains(urlLower, strings.ToLower(pattern)) {
				return provider
			}
		}
	}

	return ""
}
