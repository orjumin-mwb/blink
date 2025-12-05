package checker

import "regexp"

// initializeProviders sets up the comprehensive payment provider database
func (d *PaymentDetector) initializeProviders() {
	// TIER 1 - Major Payment Processors

	// Stripe - Enhanced
	d.providers["stripe"] = &PaymentProvider{
		ID:       "stripe",
		Name:     "Stripe",
		Category: "gateway",
		Priority: 1,
		Signatures: ProviderSignatures{
			HTMLPatterns: []*regexp.Regexp{
				regexp.MustCompile(`stripe-payment-element`),
				regexp.MustCompile(`stripe-pricing-table`),
				regexp.MustCompile(`stripe\.com`),
			},
			DOMSelectors: []string{
				"stripe-payment-element",
				"stripe-pricing-table",
				"#stripe-checkout",
				".stripe-button",
			},
			ButtonClasses: []string{
				"stripe-button",
				"stripe-button-el",
			},
			DataAttributes: []string{
				"data-stripe",
				"data-stripe-key",
			},
			JSObjects: []string{
				"Stripe",
				"StripeCheckout",
			},
			JSFunctions: []string{
				"Stripe(",
				"stripe.elements",
				"stripe.createPaymentMethod",
			},
			ScriptSources: []string{
				"js.stripe.com",
				"stripe.com/v3/",
			},
			APIEndpoints: []string{
				"api.stripe.com/v1/payment_intents",
				"api.stripe.com/v1/checkout/sessions",
				"checkout.stripe.com",
			},
			IframePatterns: []string{
				"checkout.stripe.com",
				"js.stripe.com",
			},
		},
		RiskAssessment: RiskInfo{
			SecurityLevel: "high",
			CommonIssues: []string{
				"API key exposure in client-side code",
				"Webhook signature validation missing",
			},
			BestPractices: []string{
				"Never expose secret keys",
				"Use Stripe.js for card handling",
				"Implement SCA properly",
				"Verify webhook signatures",
			},
		},
		ComplianceInfo: ComplianceInfo{
			PCICompliant: true,
			Certifications: []string{"PCI DSS Level 1", "SOC 2 Type II"},
			DataProtection: "tokenization",
		},
	}

	// PayPal - Enhanced
	d.providers["paypal"] = &PaymentProvider{
		ID:       "paypal",
		Name:     "PayPal",
		Category: "gateway",
		Priority: 1,
		Signatures: ProviderSignatures{
			HTMLPatterns: []*regexp.Regexp{
				regexp.MustCompile(`paypal\.com/sdk/js`),
				regexp.MustCompile(`paypal-button`),
				regexp.MustCompile(`paypal-checkout`),
			},
			DOMSelectors: []string{
				"#paypal-button",
				".paypal-button",
				"#paypal-checkout-btn",
				"[data-paypal-button]",
			},
			ButtonClasses: []string{
				"paypal-button",
				"paypal-buttons",
			},
			JSObjects: []string{
				"paypal",
				"PayPal",
				"PAYPAL",
			},
			JSFunctions: []string{
				"paypal.Buttons",
				"paypal.FUNDING",
			},
			ScriptSources: []string{
				"paypal.com/sdk/js",
				"paypalobjects.com",
			},
			APIEndpoints: []string{
				"api.paypal.com/v2/checkout/orders",
				"api.paypal.com/v1/payments",
			},
			IframePatterns: []string{
				"paypal.com/checkoutnow",
				"paypal.com/smart/buttons",
			},
		},
		RiskAssessment: RiskInfo{
			SecurityLevel: "high",
			BestPractices: []string{
				"Validate webhook signatures",
				"Use HTTPS for all transactions",
				"Implement proper IPN handling",
			},
		},
		ComplianceInfo: ComplianceInfo{
			PCICompliant: true,
			Certifications: []string{"PCI DSS Level 1"},
			DataProtection: "tokenization",
		},
	}

	// Square
	d.providers["square"] = &PaymentProvider{
		ID:       "square",
		Name:     "Square",
		Category: "gateway",
		Priority: 1,
		Signatures: ProviderSignatures{
			HTMLPatterns: []*regexp.Regexp{
				regexp.MustCompile(`squareup\.com`),
				regexp.MustCompile(`square-payment-form`),
			},
			DOMSelectors: []string{
				"#sq-payment-form",
				".sq-input",
				"#sq-card-number",
			},
			JSObjects: []string{
				"Square",
				"SqPaymentForm",
			},
			ScriptSources: []string{
				"web.squarecdn.com/v1/square.js",
				"js.squareup.com",
			},
			APIEndpoints: []string{
				"connect.squareup.com/v2/payments",
			},
		},
		RiskAssessment: RiskInfo{
			SecurityLevel: "high",
		},
		ComplianceInfo: ComplianceInfo{
			PCICompliant: true,
			DataProtection: "tokenization",
		},
	}

	// Adyen
	d.providers["adyen"] = &PaymentProvider{
		ID:       "adyen",
		Name:     "Adyen",
		Category: "gateway",
		Priority: 1,
		Signatures: ProviderSignatures{
			HTMLPatterns: []*regexp.Regexp{
				regexp.MustCompile(`adyen\.com`),
				regexp.MustCompile(`adyen-checkout`),
			},
			DOMSelectors: []string{
				".adyen-checkout__payment-method",
				"#adyen-checkout",
			},
			JSObjects: []string{
				"AdyenCheckout",
			},
			ScriptSources: []string{
				"checkoutshopper-live.adyen.com",
				"checkoutshopper-test.adyen.com",
			},
			APIEndpoints: []string{
				"checkout-test.adyen.com",
				"checkout-live.adyen.com",
			},
		},
		ComplianceInfo: ComplianceInfo{
			PCICompliant: true,
			DataProtection: "tokenization",
		},
	}

	// Authorize.net
	d.providers["authorizenet"] = &PaymentProvider{
		ID:       "authorizenet",
		Name:     "Authorize.net",
		Category: "gateway",
		Priority: 1,
		Signatures: ProviderSignatures{
			HTMLPatterns: []*regexp.Regexp{
				regexp.MustCompile(`authorize\.net`),
				regexp.MustCompile(`acceptjs`),
			},
			JSObjects: []string{
				"Accept",
			},
			ScriptSources: []string{
				"js.authorize.net/v1/Accept.js",
				"jstest.authorize.net/v1/Accept.js",
			},
			APIEndpoints: []string{
				"api.authorize.net",
			},
		},
		ComplianceInfo: ComplianceInfo{
			PCICompliant: true,
			DataProtection: "tokenization",
		},
	}

	// Braintree
	d.providers["braintree"] = &PaymentProvider{
		ID:       "braintree",
		Name:     "Braintree",
		Category: "gateway",
		Priority: 1,
		Signatures: ProviderSignatures{
			HTMLPatterns: []*regexp.Regexp{
				regexp.MustCompile(`braintree`),
				regexp.MustCompile(`braintreepayments`),
			},
			JSObjects: []string{
				"braintree",
			},
			ScriptSources: []string{
				"js.braintreegateway.com",
			},
			APIEndpoints: []string{
				"api.braintreegateway.com",
			},
		},
		ComplianceInfo: ComplianceInfo{
			PCICompliant: true,
			DataProtection: "tokenization",
		},
	}

	// Checkout.com
	d.providers["checkoutcom"] = &PaymentProvider{
		ID:       "checkoutcom",
		Name:     "Checkout.com",
		Category: "gateway",
		Priority: 1,
		Signatures: ProviderSignatures{
			HTMLPatterns: []*regexp.Regexp{
				regexp.MustCompile(`checkout\.com`),
			},
			JSObjects: []string{
				"Frames",
			},
			ScriptSources: []string{
				"cdn.checkout.com",
			},
			APIEndpoints: []string{
				"api.checkout.com",
			},
		},
		ComplianceInfo: ComplianceInfo{
			PCICompliant: true,
			DataProtection: "tokenization",
		},
	}

	// Worldpay
	d.providers["worldpay"] = &PaymentProvider{
		ID:       "worldpay",
		Name:     "Worldpay",
		Category: "gateway",
		Priority: 1,
		Signatures: ProviderSignatures{
			HTMLPatterns: []*regexp.Regexp{
				regexp.MustCompile(`worldpay`),
			},
			ScriptSources: []string{
				"cdn.worldpay.com",
			},
		},
		ComplianceInfo: ComplianceInfo{
			PCICompliant: true,
		},
	}

	// Razorpay
	d.providers["razorpay"] = &PaymentProvider{
		ID:       "razorpay",
		Name:     "Razorpay",
		Category: "gateway",
		Priority: 2,
		Signatures: ProviderSignatures{
			HTMLPatterns: []*regexp.Regexp{
				regexp.MustCompile(`razorpay`),
			},
			JSObjects: []string{
				"Razorpay",
			},
			ScriptSources: []string{
				"checkout.razorpay.com/v1/checkout.js",
			},
		},
		ComplianceInfo: ComplianceInfo{
			PCICompliant: true,
		},
	}

	// Mollie
	d.providers["mollie"] = &PaymentProvider{
		ID:       "mollie",
		Name:     "Mollie",
		Category: "gateway",
		Priority: 2,
		Signatures: ProviderSignatures{
			HTMLPatterns: []*regexp.Regexp{
				regexp.MustCompile(`mollie`),
			},
			ScriptSources: []string{
				"js.mollie.com",
			},
			APIEndpoints: []string{
				"api.mollie.com",
			},
		},
		ComplianceInfo: ComplianceInfo{
			PCICompliant: true,
		},
	}

	// TIER 2 - Buy Now Pay Later (BNPL)

	// Klarna
	d.providers["klarna"] = &PaymentProvider{
		ID:       "klarna",
		Name:     "Klarna",
		Category: "bnpl",
		Priority: 2,
		Signatures: ProviderSignatures{
			HTMLPatterns: []*regexp.Regexp{
				regexp.MustCompile(`klarna`),
			},
			ButtonClasses: []string{
				"klarna-button",
				"klarna-payments",
			},
			JSObjects: []string{
				"Klarna",
			},
			ScriptSources: []string{
				"x.klarnacdn.net",
			},
		},
		ComplianceInfo: ComplianceInfo{
			PCICompliant: true,
		},
	}

	// Afterpay
	d.providers["afterpay"] = &PaymentProvider{
		ID:       "afterpay",
		Name:     "Afterpay",
		Category: "bnpl",
		Priority: 2,
		Signatures: ProviderSignatures{
			HTMLPatterns: []*regexp.Regexp{
				regexp.MustCompile(`afterpay`),
			},
			ButtonClasses: []string{
				"afterpay-button",
			},
			ScriptSources: []string{
				"js.afterpay.com",
				"portal.afterpay.com",
			},
		},
	}

	// Affirm
	d.providers["affirm"] = &PaymentProvider{
		ID:       "affirm",
		Name:     "Affirm",
		Category: "bnpl",
		Priority: 2,
		Signatures: ProviderSignatures{
			HTMLPatterns: []*regexp.Regexp{
				regexp.MustCompile(`affirm`),
			},
			JSObjects: []string{
				"affirm",
			},
			ScriptSources: []string{
				"cdn1.affirm.com",
			},
		},
	}

	// Sezzle
	d.providers["sezzle"] = &PaymentProvider{
		ID:       "sezzle",
		Name:     "Sezzle",
		Category: "bnpl",
		Priority: 2,
		Signatures: ProviderSignatures{
			HTMLPatterns: []*regexp.Regexp{
				regexp.MustCompile(`sezzle`),
			},
			ScriptSources: []string{
				"widget.sezzle.com",
			},
		},
	}

	// TIER 3 - Digital Wallets

	// Apple Pay
	d.providers["applepay"] = &PaymentProvider{
		ID:       "applepay",
		Name:     "Apple Pay",
		Category: "wallet",
		Priority: 1,
		Signatures: ProviderSignatures{
			HTMLPatterns: []*regexp.Regexp{
				regexp.MustCompile(`apple-pay`),
				regexp.MustCompile(`applepay`),
			},
			ButtonClasses: []string{
				"apple-pay-button",
				"apple-pay-btn",
			},
			JSObjects: []string{
				"ApplePaySession",
			},
			JSFunctions: []string{
				"ApplePaySession.canMakePayments",
			},
		},
		ComplianceInfo: ComplianceInfo{
			PCICompliant: true,
			DataProtection: "tokenization",
		},
	}

	// Google Pay
	d.providers["googlepay"] = &PaymentProvider{
		ID:       "googlepay",
		Name:     "Google Pay",
		Category: "wallet",
		Priority: 1,
		Signatures: ProviderSignatures{
			HTMLPatterns: []*regexp.Regexp{
				regexp.MustCompile(`google-pay`),
				regexp.MustCompile(`googlepay`),
				regexp.MustCompile(`gpay`),
			},
			ButtonClasses: []string{
				"google-pay-button",
				"gpay-button",
			},
			JSObjects: []string{
				"google.payments.api.PaymentsClient",
			},
			ScriptSources: []string{
				"pay.google.com/gp/p/js/pay.js",
			},
		},
		ComplianceInfo: ComplianceInfo{
			PCICompliant: true,
			DataProtection: "tokenization",
		},
	}

	// Samsung Pay
	d.providers["samsungpay"] = &PaymentProvider{
		ID:       "samsungpay",
		Name:     "Samsung Pay",
		Category: "wallet",
		Priority: 2,
		Signatures: ProviderSignatures{
			HTMLPatterns: []*regexp.Regexp{
				regexp.MustCompile(`samsung-pay`),
				regexp.MustCompile(`samsungpay`),
			},
			JSObjects: []string{
				"SamsungPay",
			},
		},
	}

	// Amazon Pay
	d.providers["amazonpay"] = &PaymentProvider{
		ID:       "amazonpay",
		Name:     "Amazon Pay",
		Category: "wallet",
		Priority: 2,
		Signatures: ProviderSignatures{
			HTMLPatterns: []*regexp.Regexp{
				regexp.MustCompile(`amazon.*pay`),
				regexp.MustCompile(`pay.*amazon`),
			},
			ButtonClasses: []string{
				"amazon-pay-button",
			},
			JSObjects: []string{
				"OffAmazonPayments",
			},
			ScriptSources: []string{
				"static-na.payments-amazon.com",
			},
		},
	}

	// Venmo
	d.providers["venmo"] = &PaymentProvider{
		ID:       "venmo",
		Name:     "Venmo",
		Category: "wallet",
		Priority: 2,
		Signatures: ProviderSignatures{
			HTMLPatterns: []*regexp.Regexp{
				regexp.MustCompile(`venmo`),
			},
			ButtonClasses: []string{
				"venmo-button",
			},
		},
	}

	// Cash App
	d.providers["cashapp"] = &PaymentProvider{
		ID:       "cashapp",
		Name:     "Cash App",
		Category: "wallet",
		Priority: 2,
		Signatures: ProviderSignatures{
			HTMLPatterns: []*regexp.Regexp{
				regexp.MustCompile(`cash.*app`),
				regexp.MustCompile(`cashapp`),
			},
		},
	}

	// TIER 4 - Cryptocurrency

	// Coinbase Commerce
	d.providers["coinbase"] = &PaymentProvider{
		ID:       "coinbase",
		Name:     "Coinbase Commerce",
		Category: "crypto",
		Priority: 2,
		Signatures: ProviderSignatures{
			HTMLPatterns: []*regexp.Regexp{
				regexp.MustCompile(`coinbase.*commerce`),
			},
			ScriptSources: []string{
				"commerce.coinbase.com",
			},
			ButtonClasses: []string{
				"coinbase-button",
			},
		},
	}

	// BitPay
	d.providers["bitpay"] = &PaymentProvider{
		ID:       "bitpay",
		Name:     "BitPay",
		Category: "crypto",
		Priority: 2,
		Signatures: ProviderSignatures{
			HTMLPatterns: []*regexp.Regexp{
				regexp.MustCompile(`bitpay`),
			},
			ScriptSources: []string{
				"bitpay.com/bitpay.min.js",
			},
		},
	}

	// CoinGate
	d.providers["coingate"] = &PaymentProvider{
		ID:       "coingate",
		Name:     "CoinGate",
		Category: "crypto",
		Priority: 3,
		Signatures: ProviderSignatures{
			HTMLPatterns: []*regexp.Regexp{
				regexp.MustCompile(`coingate`),
			},
		},
	}

	// BTCPay Server
	d.providers["btcpay"] = &PaymentProvider{
		ID:       "btcpay",
		Name:     "BTCPay Server",
		Category: "crypto",
		Priority: 3,
		Signatures: ProviderSignatures{
			HTMLPatterns: []*regexp.Regexp{
				regexp.MustCompile(`btcpay`),
			},
			ScriptSources: []string{
				"btcpay",
			},
		},
	}

	// TIER 5 - Regional Providers

	// PayU
	d.providers["payu"] = &PaymentProvider{
		ID:       "payu",
		Name:     "PayU",
		Category: "gateway",
		Priority: 2,
		Signatures: ProviderSignatures{
			HTMLPatterns: []*regexp.Regexp{
				regexp.MustCompile(`payu`),
			},
			ScriptSources: []string{
				"secure.payu.com",
			},
		},
	}

	// Mercado Pago
	d.providers["mercadopago"] = &PaymentProvider{
		ID:       "mercadopago",
		Name:     "Mercado Pago",
		Category: "gateway",
		Priority: 2,
		Signatures: ProviderSignatures{
			HTMLPatterns: []*regexp.Regexp{
				regexp.MustCompile(`mercado.*pago`),
				regexp.MustCompile(`mercadopago`),
			},
			ScriptSources: []string{
				"secure.mlstatic.com",
			},
		},
	}

	// Paytm
	d.providers["paytm"] = &PaymentProvider{
		ID:       "paytm",
		Name:     "Paytm",
		Category: "wallet",
		Priority: 2,
		Signatures: ProviderSignatures{
			HTMLPatterns: []*regexp.Regexp{
				regexp.MustCompile(`paytm`),
			},
			ScriptSources: []string{
				"securegw.paytm.in",
			},
		},
	}

	// Alipay
	d.providers["alipay"] = &PaymentProvider{
		ID:       "alipay",
		Name:     "Alipay",
		Category: "wallet",
		Priority: 2,
		Signatures: ProviderSignatures{
			HTMLPatterns: []*regexp.Regexp{
				regexp.MustCompile(`alipay`),
			},
		},
	}

	// WeChat Pay
	d.providers["wechatpay"] = &PaymentProvider{
		ID:       "wechatpay",
		Name:     "WeChat Pay",
		Category: "wallet",
		Priority: 2,
		Signatures: ProviderSignatures{
			HTMLPatterns: []*regexp.Regexp{
				regexp.MustCompile(`wechat.*pay`),
				regexp.MustCompile(`weixinpay`),
			},
		},
	}

	// iDEAL
	d.providers["ideal"] = &PaymentProvider{
		ID:       "ideal",
		Name:     "iDEAL",
		Category: "gateway",
		Priority: 2,
		Signatures: ProviderSignatures{
			HTMLPatterns: []*regexp.Regexp{
				regexp.MustCompile(`ideal`),
			},
		},
	}

	// Sofort
	d.providers["sofort"] = &PaymentProvider{
		ID:       "sofort",
		Name:     "Sofort",
		Category: "gateway",
		Priority: 2,
		Signatures: ProviderSignatures{
			HTMLPatterns: []*regexp.Regexp{
				regexp.MustCompile(`sofort`),
			},
		},
	}

	// Giropay
	d.providers["giropay"] = &PaymentProvider{
		ID:       "giropay",
		Name:     "Giropay",
		Category: "gateway",
		Priority: 2,
		Signatures: ProviderSignatures{
			HTMLPatterns: []*regexp.Regexp{
				regexp.MustCompile(`giropay`),
			},
		},
	}

	// 2Checkout (now Verifone)
	d.providers["2checkout"] = &PaymentProvider{
		ID:       "2checkout",
		Name:     "2Checkout",
		Category: "gateway",
		Priority: 2,
		Signatures: ProviderSignatures{
			HTMLPatterns: []*regexp.Regexp{
				regexp.MustCompile(`2checkout`),
				regexp.MustCompile(`verifone`),
			},
			ScriptSources: []string{
				"2checkout.com",
			},
		},
	}

	// E-commerce Platform Integrations

	// Shopify Payments
	d.providers["shopify_payments"] = &PaymentProvider{
		ID:       "shopify_payments",
		Name:     "Shopify Payments",
		Category: "gateway",
		Priority: 2,
		Signatures: ProviderSignatures{
			HTMLPatterns: []*regexp.Regexp{
				regexp.MustCompile(`shopify.*payment`),
			},
			ScriptSources: []string{
				"cdn.shopify.com",
			},
		},
	}

	// WooCommerce Payments
	d.providers["woocommerce_payments"] = &PaymentProvider{
		ID:       "woocommerce_payments",
		Name:     "WooCommerce Payments",
		Category: "gateway",
		Priority: 2,
		Signatures: ProviderSignatures{
			HTMLPatterns: []*regexp.Regexp{
				regexp.MustCompile(`woocommerce.*payment`),
			},
		},
	}
}
