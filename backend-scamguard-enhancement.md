# Backend-Only ScamGuard Verdict Enhancement

## Overview
This document outlines backend improvements to extract meaningful verdicts and scores from ScamGuard API responses when it returns `verdict: "unknown"`. The enhanced verdict and score will automatically flow to the existing frontend verdict arc.

## Implementation Plan

### 1. Create Text Parser Module

Create a new parser that analyzes ScamGuard's text response to extract meaningful verdicts:

```go
// internal/scamguardapi/parser.go

package scamguardapi

import (
    "regexp"
    "strings"
)

// EnhancedVerdict contains the parsed verdict with confidence
type EnhancedVerdict struct {
    Verdict     string  `json:"verdict"`      // safe, suspicious, malicious, unknown
    Confidence  float64 `json:"confidence"`   // 0.0 to 1.0
    Score       int     `json:"score"`        // 0-30 for ScamGuard portion
    Reason      string  `json:"reason"`       // Brief explanation
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
        "established service", "reputable service",
    }

    // Check for negative indicators
    negativeIndicators := []string{
        "malicious", "phishing", "scam", "fraudulent",
        "dangerous", "harmful", "threat", "attack",
        "fake", "impersonation", "deceptive",
    }

    // Check for suspicious indicators
    suspiciousIndicators := []string{
        "suspicious", "untrusted", "questionable", "risky",
        "caution", "warning", "recently created", "newly registered",
        "no reputation", "unknown domain", "be careful",
    }

    // Count indicator matches
    positiveCount := countMatches(textLower, positiveIndicators)
    negativeCount := countMatches(textLower, negativeIndicators)
    suspiciousCount := countMatches(textLower, suspiciousIndicators)

    // Determine verdict based on indicator counts
    if negativeCount > 0 {
        return &EnhancedVerdict{
            Verdict:    "malicious",
            Confidence: min(0.9, 0.6 + float64(negativeCount)*0.1),
            Score:      0,
            Reason:     "Text indicates malicious characteristics",
        }
    }

    if positiveCount >= 2 {
        return &EnhancedVerdict{
            Verdict:    "safe",
            Confidence: min(0.85, 0.6 + float64(positiveCount)*0.1),
            Score:      25, // Slightly less than confirmed safe
            Reason:     "Text indicates legitimate service",
        }
    }

    if suspiciousCount > 0 || (positiveCount == 0 && containsAny(textLower, []string{"unknown", "no match", "no data"})) {
        if suspiciousCount > positiveCount {
            return &EnhancedVerdict{
                Verdict:    "suspicious",
                Confidence: min(0.7, 0.5 + float64(suspiciousCount)*0.1),
                Score:      10,
                Reason:     "Text indicates potential risks",
            }
        }
    }

    // If we have some positive indicators but not enough for "safe"
    if positiveCount == 1 {
        return &EnhancedVerdict{
            Verdict:    "unknown",
            Confidence: 0.6,
            Score:      20, // Better than suspicious, not as good as safe
            Reason:     "Limited positive indicators found",
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
```

### 2. Update ScamGuard Client

Enhance the client to use structured prompts and parse responses:

```go
// internal/scamguardapi/client.go - Add to existing file

// Enhanced prompt for better structured responses
const enhancedPrompt = `Analyze this URL for security threats. In your response, please include:
1. Whether the site appears legitimate, suspicious, or malicious
2. Key indicators that led to your assessment
3. Any reputation or historical information about the domain
4. Potential risks or concerns

URL to analyze: `

// Update ScanURLStreaming to use enhanced prompt
func (c *Client) ScanURLStreaming(ctx context.Context, url string, events chan<- StreamEvent) (*ScanResult, error) {
    // Build request body with enhanced prompt
    reqBody := CreateResponseRequest{
        Input:  enhancedPrompt + url,
        Stream: true,
        Capabilities: []Capability{
            {Type: "scan_url"},
        },
    }

    // ... rest of existing implementation ...
}

// Add enhanced result that includes parsed verdict
type EnhancedScanResult struct {
    *ScanResult
    Enhanced *EnhancedVerdict `json:"enhanced_verdict"`
}

// Update parseSSEStream to include text parsing
func (c *Client) parseSSEStream(body io.Reader, events chan<- StreamEvent) (*EnhancedScanResult, error) {
    // ... existing parsing logic ...

    // After collecting all the data, enhance the verdict
    result := &EnhancedScanResult{
        ScanResult: &ScanResult{
            Verdict:        verdict,
            Analysis:       analysisBuilder.String(),
            DestinationURL: destinationURL,
            Reachable:      reachable,
            ResponseID:     responseID,
            ThreadID:       threadID,
        },
    }

    // Parse the text to get enhanced verdict
    result.Enhanced = ParseVerdictFromText(result.Analysis, verdict)

    return result, nil
}
```

### 3. Update Checker to Use Enhanced Verdict

Modify the checker to use the enhanced verdict for scoring:

```go
// internal/checker/result.go - Add to existing structures

type ScamGuardResult struct {
    Verdict         string   `json:"verdict"`
    Analysis        string   `json:"analysis"`
    DestinationURL  string   `json:"destination_url,omitempty"`
    Reachable       bool     `json:"reachable"`
    ResponseID      string   `json:"response_id,omitempty"`
    ThreadID        string   `json:"thread_id,omitempty"`

    // Add enhanced fields
    EnhancedVerdict string   `json:"enhanced_verdict,omitempty"`
    Confidence      float64  `json:"confidence,omitempty"`
    Score           int      `json:"score,omitempty"`
    Reason          string   `json:"reason,omitempty"`
}
```

```go
// internal/checker/streaming.go - Update the ScamGuard result processing

case "response.completed":
    // After ScamGuard completes, parse the accumulated text
    if scamGuardResult != nil && scamGuardResult.Analysis != "" {
        enhanced := scamguardapi.ParseVerdictFromText(
            scamGuardResult.Analysis,
            scamGuardResult.Verdict,
        )

        // Update the result with enhanced verdict
        scamGuardResult.EnhancedVerdict = enhanced.Verdict
        scamGuardResult.Confidence = enhanced.Confidence
        scamGuardResult.Score = enhanced.Score
        scamGuardResult.Reason = enhanced.Reason

        // Use enhanced verdict for the final verdict if original was unknown
        if scamGuardResult.Verdict == "unknown" && enhanced.Verdict != "unknown" {
            scamGuardResult.Verdict = enhanced.Verdict
        }
    }

    sendEvent(ctx, events, "scamguard.completed", "ScamGuard analysis complete", nil)
```

### 4. Update Scoring Calculation

Integrate the enhanced ScamGuard score into the overall scoring:

```go
// internal/service/scoring.go - New file

package service

import (
    "github.com/yourusername/blink/internal/checker"
)

// CalculateOverallScore computes the final score and verdict
func CalculateOverallScore(result *checker.Result) (score int, verdict string) {
    totalScore := 0
    maxScore := 0

    // Basic check score (50 points max)
    basicScore := 0
    maxScore += 50

    // DNS (10 points)
    if result.ErrorType != "DNS_FAILURE" {
        basicScore += 10
    }

    // TLS Certificate (15 points)
    if result.TLS != nil {
        if result.TLS.Valid && !result.TLS.Expired {
            basicScore += 15
        } else if result.TLS.Valid && result.TLS.ExpiresInDays > 0 {
            basicScore += 10 // Expiring soon
        }
    } else if result.StatusCode > 0 {
        // HTTP site that responds
        basicScore += 8
    }

    // Response Time (10 points)
    if result.TotalMs < 1000 {
        basicScore += 10
    } else if result.TotalMs < 3000 {
        basicScore += 7
    } else if result.TotalMs < 5000 {
        basicScore += 4
    }

    // HTTP Status (10 points)
    if result.StatusCode >= 200 && result.StatusCode < 300 {
        basicScore += 10
    } else if result.StatusCode >= 300 && result.StatusCode < 400 {
        basicScore += 7 // Redirects
    } else if result.StatusCode > 0 {
        basicScore += 3 // At least responding
    }

    // Redirect Chain (5 points)
    if len(result.RedirectChain) <= 2 {
        basicScore += 5
    } else if len(result.RedirectChain) <= 4 {
        basicScore += 3
    }

    totalScore += basicScore

    // ScamGuard score (30 points max)
    if result.ScamGuard != nil {
        maxScore += 30

        // Use the enhanced score if available
        if result.ScamGuard.Score > 0 {
            totalScore += result.ScamGuard.Score
        } else {
            // Fallback to verdict-based scoring
            switch result.ScamGuard.Verdict {
            case "safe":
                totalScore += 30
            case "unknown":
                totalScore += 15
            case "suspicious":
                totalScore += 10
            case "malicious":
                totalScore += 0
            }
        }
    }

    // Deep check score (20 points max) - if available
    if result.DeepCheck != nil {
        maxScore += 20
        deepScore := calculateDeepCheckScore(result.DeepCheck)
        totalScore += deepScore
    }

    // Calculate percentage
    percentage := float64(totalScore) / float64(maxScore) * 100

    // Determine verdict with ScamGuard priority
    if result.ScamGuard != nil && result.ScamGuard.Verdict == "malicious" {
        verdict = "dangerous"
    } else if percentage >= 90 {
        verdict = "safe"
    } else if percentage >= 70 {
        verdict = "mostly_safe"
    } else if percentage >= 50 {
        verdict = "caution"
    } else if percentage >= 30 {
        verdict = "suspicious"
    } else {
        verdict = "dangerous"
    }

    return totalScore, verdict
}

func calculateDeepCheckScore(deepCheck *checker.DeepCheckResult) int {
    score := 20 // Start with full score and deduct

    // Deduct for security issues
    if len(deepCheck.SecurityIssues) > 0 {
        score -= min(10, len(deepCheck.SecurityIssues)*2)
    }

    // Deduct for trackers
    if len(deepCheck.Trackers) > 5 {
        score -= 5
    } else if len(deepCheck.Trackers) > 2 {
        score -= 3
    }

    // Deduct for mixed content
    httpResources := 0
    for _, req := range deepCheck.NetworkRequests {
        if strings.HasPrefix(req.URL, "http://") && !strings.HasPrefix(req.URL, "http://localhost") {
            httpResources++
        }
    }
    if httpResources > 0 {
        score -= min(5, httpResources)
    }

    return max(0, score)
}

func min(a, b int) int {
    if a < b {
        return a
    }
    return b
}

func max(a, b int) int {
    if a > b {
        return a
    }
    return b
}
```

### 5. Wire Everything Together

Update the main check handler to use the new scoring:

```go
// internal/httpapi/handlers.go - Update the existing check handler

func (s *Server) handleCheckStream(w http.ResponseWriter, r *http.Request) {
    // ... existing setup ...

    // After receiving the result
    go func() {
        for event := range events {
            // ... existing event handling ...

            // When check completes, calculate final score
            if event.Type == "complete" {
                if result, ok := event.Data.(*checker.Result); ok {
                    score, verdict := service.CalculateOverallScore(result)

                    // Send final verdict event
                    finalEvent := checker.Event{
                        Type:    "final_verdict",
                        Message: "Final verdict calculated",
                        Data: map[string]interface{}{
                            "score":   score,
                            "verdict": verdict,
                        },
                    }

                    // Write the final verdict event
                    eventData, _ := json.Marshal(finalEvent)
                    fmt.Fprintf(w, "event: %s\ndata: %s\n\n", finalEvent.Type, eventData)
                    flusher.Flush()
                }
            }
        }
    }()

    // ... rest of implementation ...
}
```

## Testing the Enhancement

### Test Cases

1. **Known legitimate site with "unknown" verdict**
   - Input: `https://www.zone.ee`
   - Expected: Enhanced verdict should be "safe" with ~0.75 confidence
   - Score: ~25/30 points

2. **Suspicious site with indicators**
   - Input: Recently created domain
   - Expected: Enhanced verdict "suspicious" with ~0.6 confidence
   - Score: 10/30 points

3. **Clear malicious site**
   - Input: Known phishing URL
   - Expected: Verdict "malicious" with high confidence
   - Score: 0/30 points

### Sample Enhanced Response Flow

```json
// Original ScamGuard response
{
  "verdict": "unknown",
  "analysis": "zone.ee is known as the main website for Zone, an established web hosting and domain registration service based in Estonia. It is generally recognized as a legitimate and reputable service..."
}

// After enhancement processing
{
  "verdict": "safe",           // Enhanced from "unknown"
  "enhanced_verdict": "safe",
  "confidence": 0.75,
  "score": 25,                  // Out of 30
  "reason": "Text indicates legitimate service",
  "analysis": "zone.ee is known as..."
}

// Final score sent to frontend
{
  "score": 75,                  // Total score
  "verdict": "mostly_safe",     // Final verdict for gauge
  "breakdown": {
    "basic": 45,
    "scamguard": 25,
    "deep": 5
  }
}
```

## Benefits

1. **No Frontend Changes Required** - The existing verdict arc automatically receives better data
2. **Intelligent Verdict Extraction** - Converts "unknown" to meaningful assessments
3. **Confidence-Based Scoring** - Higher confidence in parsed verdicts = higher scores
4. **Backwards Compatible** - Works with existing ScamGuard responses
5. **Future-Proof** - If ScamGuard improves their verdicts, we automatically use them

## Implementation Priority

1. **Phase 1**: Implement parser.go and test with existing responses
2. **Phase 2**: Update client.go to use enhanced prompts
3. **Phase 3**: Integrate scoring calculation
4. **Phase 4**: Wire into the streaming handlers

This approach ensures that the verdict arc always shows meaningful results, even when ScamGuard's threat intelligence database has no data about a URL.