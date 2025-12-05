# ScamGuard Verdict Enhancement Solution

## Problem Statement
The ScamGuard API frequently returns `verdict: "unknown"` even when the text analysis clearly indicates the site is legitimate or suspicious. This creates a poor user experience where the verdict gauge shows "unknown" despite having rich analysis data.

### Example Response
```json
{
  "verdict": "unknown",
  "analysis": "According to our Threat Intelligence scan, this link has a verdict of 'unknown.' This means there is currently no match in threat intelligence databases... zone.ee is known as the main website for Zone, an established web hosting and domain registration service based in Estonia. It is generally recognized as a legitimate and reputable service..."
}
```

## Solution Architecture

### 1. Enhanced Input with Structured Prompt

Update the ScamGuard API request to include a structured prompt that requests confidence scores:

```go
// internal/scamguardapi/client.go - Enhanced request

type CreateResponseRequest struct {
    Input        string         `json:"input"`
    Stream       bool           `json:"stream"`
    Capabilities []Capability   `json:"capabilities"`
    Metadata     *Metadata      `json:"metadata,omitempty"`
    SystemPrompt string         `json:"system_prompt,omitempty"` // Add this field
}

const structuredPrompt = `
Analyze the provided URL and return your assessment with the following structure:

1. VERDICT: [safe|suspicious|malicious|unknown]
2. CONFIDENCE: [0-100] - Your confidence level in this verdict
3. RISK_SCORE: [0-100] - Overall risk score (0=safe, 100=extremely dangerous)
4. INDICATORS:
   - LEGITIMACY: [0-100] - How legitimate the site appears
   - REPUTATION: [positive|neutral|negative|unknown]
   - THREAT_INTEL: [clean|flagged|unknown]
   - DOMAIN_AGE: [established|recent|new|unknown]
   - SECURITY_POSTURE: [strong|moderate|weak|unknown]

Then provide your detailed analysis as usual.

Format the structured data at the beginning of your response like this:
===STRUCTURED_DATA===
VERDICT: safe
CONFIDENCE: 85
RISK_SCORE: 15
LEGITIMACY: 90
REPUTATION: positive
THREAT_INTEL: clean
DOMAIN_AGE: established
SECURITY_POSTURE: strong
===END_STRUCTURED_DATA===

[Your detailed analysis follows...]
`

func (c *Client) ScanURLStreaming(ctx context.Context, url string, events chan<- StreamEvent) (*ScanResult, error) {
    // Build enhanced request body
    reqBody := CreateResponseRequest{
        Input:  fmt.Sprintf("%s\n\n%s", structuredPrompt, url),
        Stream: true,
        Capabilities: []Capability{
            {Type: "scan_url"},
        },
        Metadata: &Metadata{
            ClientTimezone: "UTC",
            PreferredLanguages: []string{"en"},
        },
    }
    // ... rest of the function
}
```

### 2. Enhanced Text Parsing

Create a text parser that extracts meaningful scores even when structured data isn't present:

```go
// internal/scamguardapi/text_parser.go

package scamguardapi

import (
    "regexp"
    "strings"
)

type ParsedAnalysis struct {
    Verdict        string  `json:"verdict"`
    Confidence     int     `json:"confidence"`
    RiskScore      int     `json:"risk_score"`
    Legitimacy     int     `json:"legitimacy"`
    Reputation     string  `json:"reputation"`
    ThreatIntel    string  `json:"threat_intel"`
    DomainAge      string  `json:"domain_age"`
    SecurityPosture string `json:"security_posture"`
    HasStructured  bool    `json:"has_structured"`
}

func ParseAnalysisText(text string, apiVerdict string) *ParsedAnalysis {
    result := &ParsedAnalysis{
        Verdict:    apiVerdict,
        Confidence: 50, // Default confidence for unknown
        RiskScore:  50, // Default neutral risk
    }

    // First, try to extract structured data
    if structured := extractStructuredData(text); structured != nil {
        return structured
    }

    // Fallback to intelligent text parsing
    textLower := strings.ToLower(text)

    // Legitimacy indicators
    legitimacyScore := 50
    if containsAny(textLower, []string{
        "legitimate", "reputable", "established", "well-known",
        "trusted", "authentic", "official", "recognized",
    }) {
        legitimacyScore += 30
    }
    if containsAny(textLower, []string{
        "generally recognized", "known as the main website",
        "established service", "reputable service",
    }) {
        legitimacyScore += 10
    }
    result.Legitimacy = min(100, legitimacyScore)

    // Risk indicators
    riskScore := 0
    if containsAny(textLower, []string{
        "malicious", "phishing", "scam", "fraudulent",
        "dangerous", "harmful", "threat", "attack",
    }) {
        riskScore += 50
    }
    if containsAny(textLower, []string{
        "suspicious", "untrusted", "questionable", "risky",
        "caution", "warning", "alert",
    }) {
        riskScore += 30
    }
    if containsAny(textLower, []string{
        "no match in threat intelligence", "verdict of \"unknown\"",
        "currently no match",
    }) {
        riskScore += 10 // Slight risk for completely unknown sites
    }
    result.RiskScore = min(100, riskScore)

    // Reputation extraction
    if containsAny(textLower, []string{"good reputation", "positive reputation", "well regarded"}) {
        result.Reputation = "positive"
    } else if containsAny(textLower, []string{"bad reputation", "poor reputation", "known for scams"}) {
        result.Reputation = "negative"
    } else if containsAny(textLower, []string{"mixed reputation", "some concerns"}) {
        result.Reputation = "neutral"
    } else {
        result.Reputation = "unknown"
    }

    // Domain age indicators
    if containsAny(textLower, []string{"established", "long-standing", "since 19", "since 20"}) {
        result.DomainAge = "established"
    } else if containsAny(textLower, []string{"recently created", "new domain", "registered recently"}) {
        result.DomainAge = "new"
    } else {
        result.DomainAge = "unknown"
    }

    // Calculate confidence based on how much information we extracted
    infoPoints := 0
    if result.Legitimacy != 50 { infoPoints++ }
    if result.RiskScore != 0 { infoPoints++ }
    if result.Reputation != "unknown" { infoPoints++ }
    if result.DomainAge != "unknown" { infoPoints++ }

    result.Confidence = 40 + (infoPoints * 15) // 40-100 confidence range

    // Determine final verdict if API returned "unknown"
    if apiVerdict == "unknown" {
        if result.RiskScore >= 70 {
            result.Verdict = "malicious"
        } else if result.RiskScore >= 40 {
            result.Verdict = "suspicious"
        } else if result.Legitimacy >= 70 && result.RiskScore <= 20 {
            result.Verdict = "safe"
        } else {
            result.Verdict = "unknown" // Keep unknown if truly ambiguous
        }
    }

    return result
}

func extractStructuredData(text string) *ParsedAnalysis {
    // Look for structured data section
    startMarker := "===STRUCTURED_DATA==="
    endMarker := "===END_STRUCTURED_DATA==="

    startIdx := strings.Index(text, startMarker)
    endIdx := strings.Index(text, endMarker)

    if startIdx == -1 || endIdx == -1 || startIdx >= endIdx {
        return nil
    }

    structuredSection := text[startIdx+len(startMarker):endIdx]

    result := &ParsedAnalysis{HasStructured: true}

    // Parse each line of structured data
    lines := strings.Split(structuredSection, "\n")
    for _, line := range lines {
        parts := strings.SplitN(line, ":", 2)
        if len(parts) != 2 {
            continue
        }

        key := strings.TrimSpace(parts[0])
        value := strings.TrimSpace(parts[1])

        switch key {
        case "VERDICT":
            result.Verdict = value
        case "CONFIDENCE":
            result.Confidence = parseInt(value, 50)
        case "RISK_SCORE":
            result.RiskScore = parseInt(value, 50)
        case "LEGITIMACY":
            result.Legitimacy = parseInt(value, 50)
        case "REPUTATION":
            result.Reputation = value
        case "THREAT_INTEL":
            result.ThreatIntel = value
        case "DOMAIN_AGE":
            result.DomainAge = value
        case "SECURITY_POSTURE":
            result.SecurityPosture = value
        }
    }

    return result
}

func containsAny(text string, keywords []string) bool {
    for _, keyword := range keywords {
        if strings.Contains(text, keyword) {
            return true
        }
    }
    return false
}

func parseInt(s string, defaultVal int) int {
    var val int
    if _, err := fmt.Sscanf(s, "%d", &val); err == nil {
        return val
    }
    return defaultVal
}

func min(a, b int) int {
    if a < b {
        return a
    }
    return b
}
```

### 3. Updated Scoring System

Integrate the parsed analysis into the scoring system:

```go
// internal/service/unified_scoring.go

type ScamGuardScore struct {
    BaseScore      int    `json:"base_score"`      // 0-30 points
    Confidence     int    `json:"confidence"`      // 0-100
    Details        string `json:"details"`
}

func CalculateScamGuardScore(analysis *scamguardapi.ParsedAnalysis) ScamGuardScore {
    score := ScamGuardScore{}

    // Base score calculation (max 30 points)
    switch analysis.Verdict {
    case "safe":
        score.BaseScore = 30
    case "unknown":
        // For unknown, use risk and legitimacy scores
        if analysis.Legitimacy >= 70 && analysis.RiskScore <= 30 {
            score.BaseScore = 20 // Likely safe
        } else if analysis.RiskScore >= 50 {
            score.BaseScore = 5 // Likely dangerous
        } else {
            score.BaseScore = 15 // Truly unknown
        }
    case "suspicious":
        score.BaseScore = 10
    case "malicious":
        score.BaseScore = 0
    }

    // Apply confidence modifier
    confidenceModifier := float64(analysis.Confidence) / 100.0
    score.BaseScore = int(float64(score.BaseScore) * (0.5 + 0.5*confidenceModifier))

    score.Confidence = analysis.Confidence

    // Generate details
    details := []string{}
    if analysis.Reputation == "positive" {
        details = append(details, "Positive reputation")
    } else if analysis.Reputation == "negative" {
        details = append(details, "Negative reputation")
    }

    if analysis.DomainAge == "established" {
        details = append(details, "Established domain")
    } else if analysis.DomainAge == "new" {
        details = append(details, "Recently created domain")
    }

    if analysis.ThreatIntel == "clean" {
        details = append(details, "Clean threat intel")
    } else if analysis.ThreatIntel == "flagged" {
        details = append(details, "Flagged in threat intel")
    }

    score.Details = strings.Join(details, ", ")

    return score
}
```

### 4. Frontend Updates

Update the frontend to handle the enhanced verdict data:

```javascript
// ui_form.html - Enhanced ScamGuard handling

let scamGuardAnalysis = null;

eventSource.addEventListener('scamguard.verdict', function(e) {
    const data = JSON.parse(e.data);
    if (data.data && data.data.verdict) {
        const verdict = data.data.verdict;

        // Store the verdict and any additional data
        window.currentVerdict = verdict;
        window.scamGuardConfidence = data.data.confidence || 50;

        // Update verdict display with confidence
        let verdictDisplay = '';
        let verdictClass = '';

        switch(verdict) {
            case 'safe':
                verdictDisplay = '✓ Verdict: Safe';
                verdictClass = 'text-green-600';
                break;
            case 'malicious':
                verdictDisplay = '⚠ Verdict: Malicious';
                verdictClass = 'text-red-600';
                break;
            case 'suspicious':
                verdictDisplay = '⚠ Verdict: Suspicious';
                verdictClass = 'text-orange-600';
                break;
            case 'unknown':
                // Check if we have additional context
                if (data.data.legitimacy >= 70) {
                    verdictDisplay = '◐ Verdict: Likely Safe';
                    verdictClass = 'text-blue-600';
                } else if (data.data.risk_score >= 50) {
                    verdictDisplay = '⚠ Verdict: Potentially Risky';
                    verdictClass = 'text-orange-500';
                } else {
                    verdictDisplay = '? Verdict: Unknown';
                    verdictClass = 'text-gray-600';
                }
                break;
            default:
                verdictDisplay = 'Verdict: ' + verdict;
                verdictClass = 'text-gray-600';
        }

        // Add confidence indicator if available
        if (window.scamGuardConfidence && window.scamGuardConfidence < 100) {
            verdictDisplay += ` (${window.scamGuardConfidence}% confidence)`;
        }

        scamGuardVerdict = `**${verdictDisplay}**`;

        // Update the verdict element with proper styling
        const verdictEl = document.getElementById('scamguard-verdict');
        if (verdictEl) {
            verdictEl.innerHTML = `<span class="${verdictClass} font-semibold">${verdictDisplay}</span>`;
        }
    }
});

eventSource.addEventListener('scamguard.analysis', function(e) {
    const data = JSON.parse(e.data);
    if (data.data) {
        scamGuardAnalysis = data.data;

        // Display additional insights if available
        if (scamGuardAnalysis.details) {
            const insightsEl = document.getElementById('scamguard-insights');
            if (insightsEl) {
                insightsEl.innerHTML = `
                    <div class="mt-2 p-2 bg-gray-50 rounded text-sm">
                        <strong>Key Insights:</strong> ${scamGuardAnalysis.details}
                    </div>
                `;
            }
        }
    }
});

// Enhanced verdict gauge update
function updateVerdictGauge(verdict, additionalData) {
    let score = 50; // Default neutral score
    let color = '#6b7280'; // Gray
    let label = 'Unknown';

    // Calculate score based on verdict and additional data
    if (verdict === 'safe') {
        score = 90 + (additionalData?.confidence ? Math.floor(additionalData.confidence / 10) : 0);
        color = '#10b981'; // Green
        label = 'Safe';
    } else if (verdict === 'malicious') {
        score = 10 - (additionalData?.confidence ? Math.floor(additionalData.confidence / 20) : 0);
        color = '#ef4444'; // Red
        label = 'Dangerous';
    } else if (verdict === 'suspicious') {
        score = 35;
        color = '#f59e0b'; // Orange
        label = 'Suspicious';
    } else if (verdict === 'unknown' && additionalData) {
        // Use parsed analysis for unknown verdicts
        if (additionalData.legitimacy >= 70 && additionalData.risk_score <= 30) {
            score = 70;
            color = '#3b82f6'; // Blue
            label = 'Likely Safe';
        } else if (additionalData.risk_score >= 50) {
            score = 30;
            color = '#f59e0b'; // Orange
            label = 'Potentially Risky';
        } else {
            score = 50;
            color = '#6b7280'; // Gray
            label = 'Unknown';
        }
    }

    // Animate gauge to new position
    animateGauge(score, color, label);
}
```

### 5. Backend Integration

Update the ScamGuard result handling:

```go
// internal/checker/streaming.go - Enhanced ScamGuard processing

case "response.scan_url_tool.completed":
    // Extract verdict and additional data
    var scanData struct {
        Item struct {
            Result struct {
                Verdict        string `json:"verdict"`
                DestinationURL string `json:"destination_url"`
                Reachable      bool   `json:"reachable"`
            } `json:"result"`
        } `json:"item"`
    }

    if err := json.Unmarshal(sgEvt.Data, &scanData); err == nil {
        // Parse the accumulated analysis text
        analysis := scamguardapi.ParseAnalysisText(
            analysisBuilder.String(),
            scanData.Item.Result.Verdict,
        )

        // Send enhanced verdict event
        sendEvent(ctx, events, "scamguard.verdict", "Scan verdict received", map[string]interface{}{
            "verdict":     analysis.Verdict,
            "confidence":  analysis.Confidence,
            "risk_score":  analysis.RiskScore,
            "legitimacy":  analysis.Legitimacy,
            "reputation":  analysis.Reputation,
            "domain_age":  analysis.DomainAge,
        })

        // Send analysis details
        sendEvent(ctx, events, "scamguard.analysis", "Analysis details", map[string]interface{}{
            "details":        analysis.Details,
            "has_structured": analysis.HasStructured,
        })
    }
```

## Implementation Benefits

1. **Better User Experience**: Users see meaningful verdicts even when threat intel databases have no data
2. **Confidence Indicators**: Shows confidence levels to indicate certainty
3. **Nuanced Scoring**: Converts "unknown" verdicts into actionable risk assessments
4. **Fallback Logic**: Works even if ScamGuard doesn't return structured data
5. **Rich Insights**: Extracts and displays key indicators from the analysis text

## Testing Scenarios

1. **Known Safe Site**: Should show "Safe" with high confidence
2. **Known Malicious Site**: Should show "Malicious" with high confidence
3. **Unknown Legitimate Site**: Should show "Likely Safe" based on text analysis
4. **New/Suspicious Site**: Should show appropriate risk level based on indicators
5. **No Analysis Available**: Should gracefully fall back to "Unknown"

## Migration Path

1. **Phase 1**: Implement text parser and test with existing responses
2. **Phase 2**: Add structured prompt to ScamGuard requests
3. **Phase 3**: Update frontend to display enhanced verdicts
4. **Phase 4**: Integrate into unified scoring system
5. **Phase 5**: Monitor and refine parsing rules based on real-world data

## Conclusion

This solution transforms the ScamGuard integration from a binary verdict system to a nuanced risk assessment tool that provides valuable insights even when threat intelligence databases have no data. The combination of structured prompts and intelligent text parsing ensures users always receive meaningful security assessments.