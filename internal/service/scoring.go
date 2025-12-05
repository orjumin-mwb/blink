package service

import (
	"strings"

	"github.com/olegrjumin/blink/internal/checker"
)

// ScoreBreakdown contains the detailed score breakdown
type ScoreBreakdown struct {
	Basic      int     `json:"basic"`       // Score from basic URL check (0-50)
	ScamGuard  int     `json:"scamguard"`   // Score from ScamGuard AI (0-30)
	Deep       int     `json:"deep"`        // Score from deep check (0-20)
	Total      int     `json:"total"`       // Total score
	MaxScore   int     `json:"max_score"`   // Maximum possible score
	Percentage float64 `json:"percentage"`  // Percentage score
}

// VerdictResult contains the final verdict information
type VerdictResult struct {
	Verdict    string         `json:"verdict"`    // safe, mostly_safe, caution, suspicious, dangerous
	Confidence float64        `json:"confidence"` // Confidence in the verdict (0.0-1.0)
	Priority   string         `json:"priority"`   // What determined the verdict: scamguard, security, performance
	Reason     string         `json:"reason"`     // Brief explanation
	Score      ScoreBreakdown `json:"score"`      // Detailed score breakdown
}

// CalculateOverallScore computes the final score and verdict for a URL check
func CalculateOverallScore(result *checker.CheckResult) *VerdictResult {
	scoreBreakdown := ScoreBreakdown{}
	maxScore := 0

	// Basic check score (50 points max)
	basicScore := calculateBasicScore(result)
	scoreBreakdown.Basic = basicScore
	maxScore += 50

	// ScamGuard score (30 points max)
	if result.ScamGuard != nil {
		scamGuardScore := calculateScamGuardScore(result.ScamGuard)
		scoreBreakdown.ScamGuard = scamGuardScore
		maxScore += 30
	}

	// Deep check score (20 points max) - if available
	// Note: Deep check integration would go here when implemented
	// scoreBreakdown.Deep = calculateDeepCheckScore(result.DeepCheck)
	// maxScore += 20

	// Calculate totals
	scoreBreakdown.Total = scoreBreakdown.Basic + scoreBreakdown.ScamGuard + scoreBreakdown.Deep
	scoreBreakdown.MaxScore = maxScore
	if maxScore > 0 {
		scoreBreakdown.Percentage = float64(scoreBreakdown.Total) / float64(maxScore) * 100
	}

	// Determine verdict
	verdict := determineVerdict(result, scoreBreakdown)
	verdict.Score = scoreBreakdown

	return verdict
}

// calculateBasicScore calculates the score from basic URL check (0-50 points)
func calculateBasicScore(result *checker.CheckResult) int {
	score := 0

	// HTTP 405 Method Not Allowed - NO PENALTY
	// Many legitimate sites (Amazon, eBay, etc.) block HEAD requests
	// This is not a security indicator, just a server configuration choice
	// So we completely ignore it in scoring

	// DNS Resolution (10 points)
	if result.ErrorType != "DNS_FAILURE" && result.ErrorType != "INVALID_URL" {
		score += 10
	}

	// TLS Certificate (15 points)
	if result.Protocol == "https" {
		if result.CertValid && !result.CertExpiringSoon {
			score += 15
		} else if result.CertValid && result.CertExpiringSoon {
			score += 10 // Certificate expiring soon
		} else if result.CertValid {
			score += 8 // Valid but other issues
		}
	} else if result.Status > 0 {
		// HTTP site that responds (less points than HTTPS)
		score += 7
	}

	// Response Time (10 points)
	if result.TotalMs > 0 {
		if result.TotalMs < 1000 {
			score += 10 // Fast
		} else if result.TotalMs < 3000 {
			score += 7 // Moderate
		} else if result.TotalMs < 5000 {
			score += 4 // Slow but acceptable
		} else if result.TotalMs < 10000 {
			score += 2 // Very slow
		}
	}

	// HTTP Status (10 points)
	if result.Status >= 200 && result.Status < 300 {
		score += 10 // Success
	} else if result.Status >= 300 && result.Status < 400 {
		score += 7 // Redirects are ok
	} else if result.Status == 401 || result.Status == 403 {
		score += 4 // Auth required but server is up
	} else if result.Status > 0 {
		score += 2 // At least responding
	}

	// Redirect Chain (5 points)
	if len(result.RedirectChain) == 0 {
		score += 5 // No redirects
	} else if len(result.RedirectChain) <= 2 {
		score += 4 // Few redirects
	} else if len(result.RedirectChain) <= 4 {
		score += 2 // Several redirects
	}
	// More than 4 redirects = 0 points

	return score
}

// calculateScamGuardScore calculates the score from ScamGuard AI (0-30 points)
func calculateScamGuardScore(sg *checker.ScamGuardResult) int {
	if sg == nil {
		return 0
	}

	// If we have an enhanced score from text parsing, use it
	if sg.Score > 0 {
		return sg.Score
	}

	// Otherwise, use verdict-based scoring
	switch strings.ToLower(sg.Verdict) {
	case "safe":
		return 30
	case "unknown":
		// For unknown, check if we have enhanced verdict info
		if sg.EnhancedVerdict != "" && sg.EnhancedVerdict != "unknown" {
			switch strings.ToLower(sg.EnhancedVerdict) {
			case "safe":
				return 25 // Slightly less than confirmed safe
			case "suspicious":
				return 10
			case "malicious":
				return 0
			default:
				return 15
			}
		}
		return 15 // True unknown
	case "suspicious":
		return 10
	case "malicious":
		return 0
	default:
		return 15 // Default to unknown score
	}
}

// determineVerdict determines the final verdict based on all factors
func determineVerdict(result *checker.CheckResult, score ScoreBreakdown) *VerdictResult {
	verdict := &VerdictResult{
		Confidence: 0.5, // Default confidence
		Priority:   "overall",
	}

	// Check for critical issues that override scoring
	// ScamGuard AI verdict has highest priority - trust AI for legitimate site detection
	if result.ScamGuard != nil {
		// ScamGuard malicious verdict takes highest priority
		if strings.ToLower(result.ScamGuard.Verdict) == "malicious" {
			verdict.Verdict = "dangerous"
			verdict.Priority = "scamguard"
			verdict.Reason = "Identified as malicious by AI analysis"
			verdict.Confidence = result.ScamGuard.Confidence
			if verdict.Confidence == 0 {
				verdict.Confidence = 0.9
			}
			return verdict
		}

		// ScamGuard suspicious verdict is also high priority
		if strings.ToLower(result.ScamGuard.Verdict) == "suspicious" {
			verdict.Verdict = "suspicious"
			verdict.Priority = "scamguard"
			verdict.Reason = "Flagged as suspicious by AI analysis"
			verdict.Confidence = result.ScamGuard.Confidence
			if verdict.Confidence == 0 {
				verdict.Confidence = 0.7
			}
			return verdict
		}

		// ScamGuard safe verdict has high priority - trust AI assessment for legitimate sites
		if strings.ToLower(result.ScamGuard.Verdict) == "safe" {
			// Still check for critical network issues that might indicate the site is down
			if result.ErrorType == "DNS_FAILURE" || result.ErrorType == "INVALID_URL" {
				verdict.Verdict = "dangerous"
				verdict.Priority = "dns"
				verdict.Reason = "Domain does not exist or DNS resolution failed"
				verdict.Confidence = 0.95
				return verdict
			}

			// For valid sites marked safe by ScamGuard, trust the AI assessment
			verdict.Verdict = "safe"
			verdict.Priority = "scamguard"
			verdict.Reason = "Verified as legitimate by AI analysis"
			verdict.Confidence = result.ScamGuard.Confidence
			if verdict.Confidence == 0 {
				verdict.Confidence = 0.85
			}
			return verdict
		}

		// Use confidence from ScamGuard if available
		if result.ScamGuard.Confidence > 0 {
			verdict.Confidence = result.ScamGuard.Confidence
		}
	}

	// HTTP 405 is not a security issue - many legitimate sites block HEAD requests
	// We'll consider it in the scoring but not as a verdict determiner

	// Check for critical errors
	if result.ErrorType == "DNS_FAILURE" {
		verdict.Verdict = "dangerous"
		verdict.Priority = "dns"
		verdict.Reason = "Domain does not exist or DNS resolution failed"
		verdict.Confidence = 0.95
		return verdict
	}

	if result.ErrorType == "INVALID_URL" {
		verdict.Verdict = "dangerous"
		verdict.Priority = "url"
		verdict.Reason = "Invalid or malformed URL"
		verdict.Confidence = 1.0
		return verdict
	}

	if result.ErrorType == "CONNECTION_TIMEOUT" {
		verdict.Verdict = "suspicious"
		verdict.Priority = "connectivity"
		verdict.Reason = "Site is not responding"
		verdict.Confidence = 0.8
		return verdict
	}

	// TLS/Certificate issues
	if result.Protocol == "https" && result.CertValid == false && result.Status > 0 {
		verdict.Verdict = "dangerous"
		verdict.Priority = "tls"
		verdict.Reason = "Invalid or expired TLS certificate"
		verdict.Confidence = 0.9
		return verdict
	}

	// Determine verdict based on percentage score
	percentage := score.Percentage

	if percentage >= 90 {
		verdict.Verdict = "safe"
		verdict.Reason = "Site passed all security checks"
		if verdict.Confidence < 0.7 {
			verdict.Confidence = 0.85
		}
	} else if percentage >= 70 {
		verdict.Verdict = "mostly_safe"
		verdict.Reason = "Site appears safe with minor issues"
		if verdict.Confidence < 0.6 {
			verdict.Confidence = 0.7
		}
	} else if percentage >= 50 {
		verdict.Verdict = "caution"
		verdict.Reason = "Site has some concerning characteristics"
		if verdict.Confidence < 0.5 {
			verdict.Confidence = 0.6
		}
	} else if percentage >= 30 {
		verdict.Verdict = "suspicious"
		verdict.Reason = "Site shows multiple warning signs"
		if verdict.Confidence < 0.5 {
			verdict.Confidence = 0.65
		}
	} else {
		verdict.Verdict = "dangerous"
		verdict.Reason = "Site failed multiple security checks"
		if verdict.Confidence < 0.5 {
			verdict.Confidence = 0.75
		}
	}

	// Add context from ScamGuard if available
	if result.ScamGuard != nil && result.ScamGuard.Reason != "" {
		verdict.Reason = result.ScamGuard.Reason
	}

	return verdict
}