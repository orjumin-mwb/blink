package checker

import "math"

// PaymentConfidenceScorer calculates confidence scores for payment detections
type PaymentConfidenceScorer struct {
	weights map[string]float64
}

// NewPaymentConfidenceScorer creates a new confidence scorer
func NewPaymentConfidenceScorer() *PaymentConfidenceScorer {
	return &PaymentConfidenceScorer{
		weights: map[string]float64{
			"html_form":        0.25,
			"html_elements":    0.20,
			"js_object":        0.30,
			"js_sdk_init":      0.35,
			"api_endpoint":     0.40,
			"iframe_checkout":  0.35,
			"payment_button":   0.20,
			"script_source":    0.25,
			"wallet_button":    0.25,
			"headers":          0.15,
			"multiple_sources": 0.10, // Bonus for multiple detection methods
		},
	}
}

// CalculateScore calculates the overall confidence score
func (s *PaymentConfidenceScorer) CalculateScore(evidence map[string]bool) ConfidenceScore {
	score := ConfidenceScore{
		Overall: 0.0,
		Details: make(map[string]float64),
	}

	// Calculate base score from weighted factors
	detectionCount := 0
	for factor, detected := range evidence {
		if detected {
			weight := s.weights[factor]
			score.Overall += weight
			score.Details[factor] = weight
			detectionCount++
		}
	}

	// Apply bonus for multiple detection sources
	if detectionCount >= 3 {
		bonus := s.weights["multiple_sources"]
		score.Overall += bonus
		score.Details["multiple_sources_bonus"] = bonus
	}

	// Normalize to 0-100 scale
	score.Overall = math.Min(score.Overall * 100, 100)

	// Determine confidence level
	score.Level = s.getConfidenceLevel(score.Overall)

	return score
}

// getConfidenceLevel returns the confidence level based on score
func (s *PaymentConfidenceScorer) getConfidenceLevel(score float64) string {
	switch {
	case score >= 85:
		return "very_high"
	case score >= 65:
		return "high"
	case score >= 45:
		return "medium"
	case score >= 25:
		return "low"
	default:
		return "very_low"
	}
}

// ScoreProviderDetection scores a specific provider detection
func (s *PaymentConfidenceScorer) ScoreProviderDetection(evidence ProviderEvidence) ConfidenceScore {
	factors := make(map[string]bool)

	// HTML evidence
	if len(evidence.HTMLElements) > 0 {
		factors["html_elements"] = true
	}
	if len(evidence.FormFields) > 0 {
		factors["html_form"] = true
	}
	if len(evidence.ScriptSources) > 0 {
		factors["script_source"] = true
	}

	// JavaScript evidence
	if len(evidence.JSObjects) > 0 {
		factors["js_object"] = true
	}

	// API evidence
	if len(evidence.APIEndpoints) > 0 {
		factors["api_endpoint"] = true
	}

	// Iframe evidence
	if evidence.IframeCheckout {
		factors["iframe_checkout"] = true
	}

	return s.CalculateScore(factors)
}

// CalculateOverallPaymentScore calculates the overall payment detection confidence
func (s *PaymentConfidenceScorer) CalculateOverallPaymentScore(result *PaymentDetectionResult) ConfidenceScore {
	factors := make(map[string]bool)

	// Check for various evidence types
	if result.Evidence.HTMLAnalysis != nil {
		html := result.Evidence.HTMLAnalysis

		if len(html.CreditCardForms) > 0 {
			factors["html_form"] = true
		}
		if len(html.PaymentButtons) > 0 {
			factors["payment_button"] = true
		}
		if len(html.WalletButtons) > 0 {
			factors["wallet_button"] = true
		}
		if len(html.EmbeddedCheckouts) > 0 {
			factors["iframe_checkout"] = true
		}
	}

	if result.Evidence.JSAnalysis != nil {
		js := result.Evidence.JSAnalysis

		if len(js.GlobalObjects) > 0 {
			factors["js_object"] = true
		}
		if len(js.SDKInitializations) > 0 {
			factors["js_sdk_init"] = true
		}
	}

	if len(result.Evidence.APIDetection) > 0 {
		factors["api_endpoint"] = true
	}

	// Providers detected
	if len(result.Providers) > 0 {
		factors["html_elements"] = true
	}

	return s.CalculateScore(factors)
}
