package checker

import (
	"net/http"
	"testing"
)

func TestPaymentDetector_StripeDetection(t *testing.T) {
	detector := NewPaymentDetector()

	html := `
	<!DOCTYPE html>
	<html>
	<head>
		<script src="https://js.stripe.com/v3/"></script>
	</head>
	<body>
		<form id="payment-form">
			<div id="card-element"></div>
			<button id="submit">Pay Now</button>
		</form>
		<script>
			const stripe = Stripe('pk_test_51234567890');
			const elements = stripe.elements();
			const cardElement = elements.create('card');
		</script>
	</body>
	</html>
	`

	scripts := []string{
		`const stripe = Stripe('pk_test_51234567890');
		const elements = stripe.elements();
		const cardElement = elements.create('card');`,
	}

	headers := http.Header{}
	networkData := []NetworkRequest{
		{
			URL:    "https://api.stripe.com/v1/payment_intents",
			Method: "POST",
			Type:   "xhr",
		},
	}

	result := detector.Detect(html, headers, scripts, networkData)

	if len(result.Providers) == 0 {
		t.Fatal("Expected to detect Stripe provider")
	}

	found := false
	for _, provider := range result.Providers {
		if provider.Provider == "stripe" {
			found = true
			if provider.Confidence != "high" && provider.Confidence != "very_high" {
				t.Errorf("Expected high confidence for Stripe, got %s", provider.Confidence)
			}
			if len(provider.Evidence.JSObjects) == 0 {
				t.Error("Expected JS object evidence for Stripe")
			}
			if len(provider.Evidence.APIEndpoints) == 0 {
				t.Error("Expected API endpoint evidence for Stripe")
			}
		}
	}

	if !found {
		t.Error("Stripe provider not detected")
	}
}

func TestPaymentDetector_PayPalDetection(t *testing.T) {
	detector := NewPaymentDetector()

	html := `
	<!DOCTYPE html>
	<html>
	<head>
		<script src="https://www.paypal.com/sdk/js?client-id=test"></script>
	</head>
	<body>
		<div id="paypal-button-container"></div>
		<script>
			paypal.Buttons({
				createOrder: function(data, actions) {
					return actions.order.create({
						purchase_units: [{
							amount: {
								value: '100.00'
							}
						}]
					});
				}
			}).render('#paypal-button-container');
		</script>
	</body>
	</html>
	`

	scripts := []string{
		`paypal.Buttons({createOrder: function(data, actions) {}}).render('#paypal-button-container');`,
	}

	result := detector.Detect(html, http.Header{}, scripts, nil)

	found := false
	for _, provider := range result.Providers {
		if provider.Provider == "paypal" {
			found = true
			if provider.Confidence == "very_low" || provider.Confidence == "low" {
				t.Errorf("Expected higher confidence for PayPal, got %s", provider.Confidence)
			}
		}
	}

	if !found {
		t.Error("PayPal provider not detected")
	}
}

func TestPaymentDetector_CreditCardFormDetection(t *testing.T) {
	detector := NewPaymentDetector()

	html := `
	<!DOCTYPE html>
	<html>
	<body>
		<form action="https://secure.example.com/process" method="POST">
			<input type="text" name="card_number" placeholder="Card Number">
			<input type="text" name="expiry_date" placeholder="MM/YY">
			<input type="text" name="cvv" placeholder="CVV">
			<input type="text" name="cardholder_name" placeholder="Name on Card">
			<button type="submit">Pay</button>
		</form>
	</body>
	</html>
	`

	result := detector.Detect(html, http.Header{}, nil, nil)

	if result.Evidence.HTMLAnalysis == nil {
		t.Fatal("Expected HTML analysis results")
	}

	if len(result.Evidence.HTMLAnalysis.CreditCardForms) == 0 {
		t.Error("Expected to detect credit card form")
	}

	form := result.Evidence.HTMLAnalysis.CreditCardForms[0]
	if !form.Secure {
		t.Error("Expected form to be marked as secure (HTTPS action)")
	}

	// Check for expected fields
	expectedFields := map[string]bool{
		"card_number": false,
		"cvv":         false,
		"expiry":      false,
	}

	for _, field := range form.Fields {
		if _, exists := expectedFields[field]; exists {
			expectedFields[field] = true
		}
	}

	for field, found := range expectedFields {
		if !found {
			t.Errorf("Expected field %s not detected", field)
		}
	}
}

func TestPaymentDetector_WalletButtons(t *testing.T) {
	detector := NewPaymentDetector()

	html := `
	<!DOCTYPE html>
	<html>
	<body>
		<div class="apple-pay-button"></div>
		<div class="google-pay-button"></div>
		<div id="paypal-button"></div>
		<script>
			if (ApplePaySession && ApplePaySession.canMakePayments()) {
				document.querySelector('.apple-pay-button').style.display = 'block';
			}
		</script>
	</body>
	</html>
	`

	scripts := []string{
		`if (ApplePaySession && ApplePaySession.canMakePayments()) {}`,
	}

	result := detector.Detect(html, http.Header{}, scripts, nil)

	if result.Evidence.HTMLAnalysis == nil {
		t.Fatal("Expected HTML analysis results")
	}

	wallets := result.Evidence.HTMLAnalysis.WalletButtons
	if len(wallets) < 2 {
		t.Errorf("Expected at least 2 wallet buttons, got %d", len(wallets))
	}

	walletsFound := make(map[string]bool)
	for _, wallet := range wallets {
		walletsFound[wallet.Wallet] = true
	}

	expectedWallets := []string{"apple_pay", "google_pay", "paypal"}
	for _, expected := range expectedWallets {
		if !walletsFound[expected] {
			t.Errorf("Expected to detect %s wallet button", expected)
		}
	}
}

func TestPaymentDetector_EmbeddedCheckout(t *testing.T) {
	detector := NewPaymentDetector()

	html := `
	<!DOCTYPE html>
	<html>
	<body>
		<iframe src="https://checkout.stripe.com/pay/cs_test_12345"></iframe>
	</body>
	</html>
	`

	result := detector.Detect(html, http.Header{}, nil, nil)

	if result.Evidence.HTMLAnalysis == nil {
		t.Fatal("Expected HTML analysis results")
	}

	if len(result.Evidence.HTMLAnalysis.EmbeddedCheckouts) == 0 {
		t.Error("Expected to detect embedded checkout iframe")
	}

	checkout := result.Evidence.HTMLAnalysis.EmbeddedCheckouts[0]
	if checkout.Provider != "stripe" {
		t.Errorf("Expected Stripe provider for embedded checkout, got %s", checkout.Provider)
	}
	if !checkout.Secure {
		t.Error("Expected embedded checkout to be secure (HTTPS)")
	}
}

func TestPaymentDetector_CheckoutFlow(t *testing.T) {
	detector := NewPaymentDetector()

	html := `
	<!DOCTYPE html>
	<html>
	<body>
		<div class="checkout-steps">
			<div class="step-1 active">Shipping</div>
			<div class="step-2">Payment</div>
			<div class="step-3">Review</div>
		</div>
		<h1>Payment Method</h1>
		<div class="payment-options">
			<input type="radio" name="payment" value="credit_card" checked>
			<label>Credit Card</label>
			<input type="radio" name="payment" value="paypal">
			<label>PayPal</label>
		</div>
		<img src="/images/ssl-secure.png" alt="SSL Secure">
	</body>
	</html>
	`

	result := detector.Detect(html, http.Header{}, nil, nil)

	if result.CheckoutFlow == nil {
		t.Fatal("Expected checkout flow analysis")
	}

	flow := result.CheckoutFlow
	if flow.Type != "multi_step" {
		t.Errorf("Expected multi_step checkout, got %s", flow.Type)
	}

	if flow.CurrentPhase != "payment" {
		t.Errorf("Expected payment phase, got %s", flow.CurrentPhase)
	}

	if len(flow.DetectedSteps) < 2 {
		t.Errorf("Expected at least 2 detected steps, got %d", len(flow.DetectedSteps))
	}

	if len(flow.PaymentOptions) < 2 {
		t.Errorf("Expected at least 2 payment options, got %d", len(flow.PaymentOptions))
	}

	if len(flow.SecurityIndicators) == 0 {
		t.Error("Expected to detect security indicators")
	}
}

func TestPaymentDetector_MultipleProviders(t *testing.T) {
	detector := NewPaymentDetector()

	html := `
	<!DOCTYPE html>
	<html>
	<head>
		<script src="https://js.stripe.com/v3/"></script>
		<script src="https://www.paypal.com/sdk/js"></script>
	</head>
	<body>
		<div class="apple-pay-button"></div>
		<div id="paypal-button"></div>
		<form id="card-payment">
			<div id="card-element"></div>
		</form>
	</body>
	</html>
	`

	scripts := []string{
		`const stripe = Stripe('pk_test_123');`,
		`paypal.Buttons({}).render('#paypal-button');`,
	}

	result := detector.Detect(html, http.Header{}, scripts, nil)

	if len(result.Providers) < 2 {
		t.Errorf("Expected at least 2 providers, got %d", len(result.Providers))
	}

	providers := make(map[string]bool)
	for _, p := range result.Providers {
		providers[p.Provider] = true
	}

	expectedProviders := []string{"stripe", "paypal", "applepay"}
	for _, expected := range expectedProviders {
		if !providers[expected] {
			t.Errorf("Expected to detect %s provider", expected)
		}
	}
}

func TestPaymentDetector_ComplianceAnalysis(t *testing.T) {
	detector := NewPaymentDetector()

	html := `
	<!DOCTYPE html>
	<html>
	<head>
		<script src="https://js.stripe.com/v3/"></script>
	</head>
	<body>
		<div class="trust-badges">
			<img src="/pci-dss-compliant.png" alt="PCI DSS Compliant">
			<img src="/ssl-secure.png" alt="SSL Secure">
		</div>
		<p>All payments are securely processed and PCI compliant</p>
	</body>
	</html>
	`

	headers := http.Header{}
	headers.Set("X-Forwarded-Proto", "https")

	result := detector.Detect(html, headers, nil, nil)

	if !result.Compliance.SecureTransmission {
		t.Error("Expected secure transmission to be detected")
	}

	if !result.Compliance.PCIIndicators {
		t.Error("Expected PCI compliance indicators to be detected")
	}

	if len(result.Compliance.ComplianceBadges) == 0 {
		t.Error("Expected to detect compliance badges")
	}
}

func TestPaymentDetector_RiskAssessment(t *testing.T) {
	detector := NewPaymentDetector()

	// Scenario 1: Low risk - known provider, HTTPS, PCI
	html1 := `
	<!DOCTYPE html>
	<html>
	<head>
		<script src="https://js.stripe.com/v3/"></script>
	</head>
	<body>
		<div id="card-element"></div>
		<p>PCI DSS Compliant</p>
	</body>
	</html>
	`

	headers1 := http.Header{}
	headers1.Set("X-Forwarded-Proto", "https")

	result1 := detector.Detect(html1, headers1, []string{`Stripe('pk_test_123')`}, nil)

	if result1.RiskAssessment.Level != "low" {
		t.Errorf("Expected low risk for Stripe with HTTPS, got %s", result1.RiskAssessment.Level)
	}

	// Scenario 2: Medium/High risk - custom form without known provider, no HTTPS
	html2 := `
	<!DOCTYPE html>
	<html>
	<body>
		<form action="http://example.com/process">
			<input name="card_number">
			<input name="cvv">
		</form>
	</body>
	</html>
	`

	result2 := detector.Detect(html2, http.Header{}, nil, nil)

	if result2.RiskAssessment.Level == "low" {
		t.Errorf("Expected higher risk for custom implementation without HTTPS, got %s", result2.RiskAssessment.Level)
	}

	if len(result2.RiskAssessment.Warnings) == 0 {
		t.Error("Expected risk warnings for insecure payment setup")
	}
}

func TestPaymentDetector_ConfidenceScoring(t *testing.T) {
	detector := NewPaymentDetector()

	// High confidence: Multiple detection methods
	html := `
	<!DOCTYPE html>
	<html>
	<head>
		<script src="https://js.stripe.com/v3/"></script>
	</head>
	<body>
		<div class="stripe-payment-element"></div>
	</body>
	</html>
	`

	scripts := []string{`const stripe = Stripe('pk_test_123');`}
	networkData := []NetworkRequest{
		{URL: "https://api.stripe.com/v1/payment_intents", Method: "POST"},
	}

	result := detector.Detect(html, http.Header{}, scripts, networkData)

	if len(result.Providers) == 0 {
		t.Fatal("Expected to detect provider")
	}

	stripeProvider := result.Providers[0]
	if stripeProvider.ConfidenceScore < 60 {
		t.Errorf("Expected high confidence score (>60) with multiple detection methods, got %.2f", stripeProvider.ConfidenceScore)
	}

	if stripeProvider.Confidence == "low" || stripeProvider.Confidence == "very_low" {
		t.Errorf("Expected high confidence level with multiple detection methods, got %s", stripeProvider.Confidence)
	}
}

func TestPaymentDetector_BNPLProviders(t *testing.T) {
	detector := NewPaymentDetector()

	html := `
	<!DOCTYPE html>
	<html>
	<head>
		<script src="https://x.klarnacdn.net/kp/lib/v1/api.js"></script>
	</head>
	<body>
		<div id="klarna-payments-container"></div>
		<div class="afterpay-button"></div>
		<script>
			Klarna.Payments.init({client_token: 'token'});
		</script>
	</body>
	</html>
	`

	scripts := []string{`Klarna.Payments.init({client_token: 'token'});`}

	result := detector.Detect(html, http.Header{}, scripts, nil)

	foundKlarna := false
	for _, provider := range result.Providers {
		if provider.Provider == "klarna" {
			foundKlarna = true
			if provider.Category != "bnpl" {
				t.Errorf("Expected Klarna to be categorized as BNPL, got %s", provider.Category)
			}
		}
	}

	if !foundKlarna {
		t.Error("Expected to detect Klarna BNPL provider")
	}

	// Check payment methods
	hasBNPL := false
	for _, method := range result.PaymentMethods {
		if method == "buy_now_pay_later" {
			hasBNPL = true
			break
		}
	}

	if !hasBNPL {
		t.Error("Expected buy_now_pay_later in payment methods")
	}
}

func TestPaymentDetector_CryptocurrencyProviders(t *testing.T) {
	detector := NewPaymentDetector()

	html := `
	<!DOCTYPE html>
	<html>
	<head>
		<script src="https://commerce.coinbase.com/v1/checkout.js"></script>
	</head>
	<body>
		<button class="coinbase-button" data-code="BITCOIN">Pay with Bitcoin</button>
		<div id="bitpay-invoice"></div>
	</body>
	</html>
	`

	result := detector.Detect(html, http.Header{}, nil, nil)

	foundCrypto := false
	for _, provider := range result.Providers {
		if provider.Category == "crypto" {
			foundCrypto = true
			break
		}
	}

	if !foundCrypto {
		t.Error("Expected to detect cryptocurrency payment provider")
	}

	hasCryptoMethod := false
	for _, method := range result.PaymentMethods {
		if method == "cryptocurrency" {
			hasCryptoMethod = true
			break
		}
	}

	if !hasCryptoMethod {
		t.Error("Expected cryptocurrency in payment methods")
	}
}
