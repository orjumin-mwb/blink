package scamguardapi

import (
	"strings"
)

// EnhancedVerdict contains the parsed verdict with confidence
type EnhancedVerdict struct {
	Verdict    string  `json:"verdict"`    // safe, suspicious, malicious, unknown
	Confidence float64 `json:"confidence"` // 0.0 to 1.0
	Score      int     `json:"score"`      // 0-30 for ScamGuard portion
	Reason     string  `json:"reason"`     // Brief explanation
}

// ParseVerdictFromText analyzes the text response when verdict is "unknown"
func ParseVerdictFromText(text string, apiVerdict string) *EnhancedVerdict {
	// If API gave us a clear verdict, use it with high confidence
	if apiVerdict == "safe" || apiVerdict == "malicious" || apiVerdict == "suspicious" {
		score := 0
		if apiVerdict == "safe" {
			score = 30
		} else if apiVerdict == "suspicious" {
			score = 10
		}

		return &EnhancedVerdict{
			Verdict:    apiVerdict,
			Confidence: 0.95,
			Score:      score,
			Reason:     "Confirmed by threat intelligence",
		}
	}

	// For "unknown" verdicts, analyze the text
	textLower := strings.ToLower(text)

	// Check for strong positive indicators
	positiveIndicators := []string{
		"legitimate", "reputable", "established", "well-known",
		"trusted", "authentic", "official", "recognized as legitimate",
		"generally recognized", "known as the main website",
		"established service", "reputable service", "reliable",
		"safe to use", "no security concerns", "appears to be legitimate",
	}

	// Check for negative indicators - be more specific to avoid false positives
	negativeIndicators := []string{
		"is malicious", "phishing site", "scam site", "fraudulent site",
		"dangerous site", "harmful content", "security threat", "cyber attack",
		"fake website", "impersonation", "deceptive site", "virus detected",
		"malware detected", "trojan detected", "ransomware", "spyware",
		"avoid this", "do not visit", "reported as malicious", "known to be malicious",
	}

	// Check for suspicious indicators
	suspiciousIndicators := []string{
		"suspicious", "untrusted", "questionable", "risky",
		"caution", "warning", "recently created", "newly registered",
		"no reputation", "unknown domain", "be careful",
		"potential risk", "exercise caution", "red flags",
		"unusual", "anomalous", "potentially unsafe",
	}

	// Count indicator matches
	positiveCount := countMatches(textLower, positiveIndicators)
	negativeCount := countMatches(textLower, negativeIndicators)
	suspiciousCount := countMatches(textLower, suspiciousIndicators)

	// Check for specific phrases that indicate legitimacy
	hasLegitimatePhrase := containsAny(textLower, []string{
		"generally recognized as a legitimate",
		"is known as the main website",
		"established web hosting",
		"established domain registration",
		"reputable company",
		"well-known service",
		"the site appears legitimate",
		"appears legitimate",
		"this is the official website",
		"no indication of fraud",
		"established and highly reputable",
		"safe and globally established",
	})

	// Check for specific phrases that indicate danger
	hasDangerousPhrase := containsAny(textLower, []string{
		"known phishing site",
		"confirmed malicious",
		"actively distributing malware",
		"fraud alert",
		"scam website",
	})

	// Determine verdict based on indicator counts and phrases
	if hasDangerousPhrase || negativeCount >= 2 {
		return &EnhancedVerdict{
			Verdict:    "malicious",
			Confidence: min(0.9, 0.6+float64(negativeCount)*0.1),
			Score:      0,
			Reason:     "Text indicates malicious characteristics",
		}
	}

	if negativeCount > 0 && negativeCount > positiveCount {
		return &EnhancedVerdict{
			Verdict:    "suspicious",
			Confidence: min(0.8, 0.5+float64(negativeCount)*0.15),
			Score:      5,
			Reason:     "Text contains security concerns",
		}
	}

	// Prioritize positive indicators for established services
	if hasLegitimatePhrase || positiveCount >= 2 {
		return &EnhancedVerdict{
			Verdict:    "safe",
			Confidence: min(0.85, 0.6+float64(positiveCount)*0.08),
			Score:      25, // Slightly less than confirmed safe
			Reason:     "Text indicates legitimate service",
		}
	}

	if positiveCount >= 1 && negativeCount == 0 {
		return &EnhancedVerdict{
			Verdict:    "safe",
			Confidence: min(0.75, 0.55+float64(positiveCount)*0.1),
			Score:      23,
			Reason:     "Positive indicators found with no concerns",
		}
	}

	if suspiciousCount > 0 || (positiveCount == 0 && containsAny(textLower, []string{"unknown", "no match", "no data"})) {
		if suspiciousCount > positiveCount {
			return &EnhancedVerdict{
				Verdict:    "suspicious",
				Confidence: min(0.7, 0.5+float64(suspiciousCount)*0.1),
				Score:      10,
				Reason:     "Text indicates potential risks",
			}
		}
	}

	// If we have some positive indicators but not enough for "safe"
	if positiveCount == 1 && negativeCount == 0 {
		return &EnhancedVerdict{
			Verdict:    "unknown",
			Confidence: 0.6,
			Score:      20, // Better than suspicious, not as good as safe
			Reason:     "Limited positive indicators found",
		}
	}

	// Check if the text explicitly states it's unknown but provides context
	if strings.Contains(textLower, "verdict of \"unknown\"") || strings.Contains(textLower, "verdict: unknown") {
		// Look for additional context
		if strings.Contains(textLower, "no match in threat intelligence") && positiveCount > 0 {
			return &EnhancedVerdict{
				Verdict:    "unknown",
				Confidence: 0.5,
				Score:      18, // Slightly positive bias
				Reason:     "No threat data but some positive indicators",
			}
		}
	}

	// True unknown - no clear indicators
	return &EnhancedVerdict{
		Verdict:    "unknown",
		Confidence: 0.4,
		Score:      15, // Neutral score
		Reason:     "Insufficient data for determination",
	}
}

func countMatches(text string, keywords []string) int {
	count := 0
	for _, keyword := range keywords {
		if strings.Contains(text, keyword) {
			count++
		}
	}
	return count
}

func containsAny(text string, keywords []string) bool {
	for _, keyword := range keywords {
		if strings.Contains(text, keyword) {
			return true
		}
	}
	return false
}

func min(a, b float64) float64 {
	if a < b {
		return a
	}
	return b
}