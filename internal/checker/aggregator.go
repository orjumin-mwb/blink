package checker

import (
	"strings"
	"sync"
)

// DetectionSource represents where a detection originated from
type DetectionSource struct {
	Static  bool `json:"static"`  // Found in HTML/JS
	Runtime bool `json:"runtime"` // Confirmed at runtime
	Network bool `json:"network"` // Made network requests
}

// DetectionEvidence contains evidence for how something was detected
type DetectionEvidence struct {
	Signatures      []string          `json:"signatures,omitempty"`
	Scripts         []string          `json:"scripts,omitempty"`
	NetworkRequests []string          `json:"network_requests,omitempty"`
	HTMLPatterns    []string          `json:"html_patterns,omitempty"`
	Headers         map[string]string `json:"headers,omitempty"`
	MetaTags        map[string]string `json:"meta_tags,omitempty"`
	UsageContext    []string          `json:"usage_context,omitempty"`
}

// UnifiedTracker represents a tracking service with merged detection info
type UnifiedTracker struct {
	Name       string             `json:"name"`
	Category   string             `json:"category"`
	RiskLevel  string             `json:"risk_level"`
	Purpose    string             `json:"purpose"`
	Detection  DetectionSource    `json:"detection"`
	Domains    []string           `json:"domains,omitempty"`
	Evidence   DetectionEvidence  `json:"evidence"`
}

// UnifiedTechnology represents a detected technology with security info
type UnifiedTechnology struct {
	Name       string             `json:"name"`
	Category   string             `json:"category"`
	Version    string             `json:"version,omitempty"`
	Confidence string             `json:"confidence"`
	Security   TechnologySecurity `json:"security"`
	Evidence   DetectionEvidence  `json:"evidence"`
}

// TechnologySecurity contains security assessment for a technology
type TechnologySecurity struct {
	RiskLevel       string   `json:"risk_level"`
	Vulnerabilities []string `json:"vulnerabilities,omitempty"`
	Recommendations []string `json:"recommendations,omitempty"`
	CVEs            []string `json:"cves,omitempty"`
}

// UnifiedAPI represents detected API usage with context
type UnifiedAPI struct {
	Name         string            `json:"name"`
	Category     string            `json:"category"`
	RiskLevel    string            `json:"risk_level"`
	Available    bool              `json:"available"`
	Executed     bool              `json:"executed"`
	UsageContext []string          `json:"usage_context,omitempty"`
}

// DetectionAggregator merges detections from multiple sources
type DetectionAggregator struct {
	mu           sync.RWMutex
	trackers     map[string]*UnifiedTracker
	technologies map[string]*UnifiedTechnology
	apis         map[string]*UnifiedAPI
}

// NewDetectionAggregator creates a new aggregator instance
func NewDetectionAggregator() *DetectionAggregator {
	return &DetectionAggregator{
		trackers:     make(map[string]*UnifiedTracker),
		technologies: make(map[string]*UnifiedTechnology),
		apis:         make(map[string]*UnifiedAPI),
	}
}

// AddTracker adds or merges a tracker detection
func (a *DetectionAggregator) AddTracker(name string, tracker *UnifiedTracker, source string) {
	a.mu.Lock()
	defer a.mu.Unlock()

	key := strings.ToLower(name)
	existing, exists := a.trackers[key]

	if !exists {
		a.trackers[key] = tracker
		a.updateDetectionSource(&tracker.Detection, source)
		return
	}

	// Merge detection sources
	a.updateDetectionSource(&existing.Detection, source)

	// Merge evidence
	a.mergeEvidence(&existing.Evidence, &tracker.Evidence)

	// Merge domains
	existing.Domains = a.mergeStringSlices(existing.Domains, tracker.Domains)

	// Update risk level to highest
	if a.compareRiskLevel(tracker.RiskLevel, existing.RiskLevel) > 0 {
		existing.RiskLevel = tracker.RiskLevel
	}
}

// AddTechnology adds or merges a technology detection
func (a *DetectionAggregator) AddTechnology(name string, tech *UnifiedTechnology, source string) {
	a.mu.Lock()
	defer a.mu.Unlock()

	key := strings.ToLower(name)
	existing, exists := a.technologies[key]

	if !exists {
		a.technologies[key] = tech
		return
	}

	// Merge evidence
	a.mergeEvidence(&existing.Evidence, &tech.Evidence)

	// Update version if more specific
	if tech.Version != "" && (existing.Version == "" || len(tech.Version) > len(existing.Version)) {
		existing.Version = tech.Version
	}

	// Update confidence to highest
	if a.compareConfidence(tech.Confidence, existing.Confidence) > 0 {
		existing.Confidence = tech.Confidence
	}

	// Merge security info
	a.mergeTechnologySecurity(&existing.Security, &tech.Security)
}

// AddAPI adds or merges an API detection
func (a *DetectionAggregator) AddAPI(name string, api *UnifiedAPI, source string) {
	a.mu.Lock()
	defer a.mu.Unlock()

	key := strings.ToLower(name)
	existing, exists := a.apis[key]

	if !exists {
		a.apis[key] = api
		return
	}

	// Update availability and execution status
	if source == "static" {
		existing.Available = existing.Available || api.Available
	} else if source == "runtime" {
		existing.Executed = existing.Executed || api.Executed
	}

	// Merge usage context
	existing.UsageContext = a.mergeStringSlices(existing.UsageContext, api.UsageContext)

	// Update risk level to highest
	if a.compareRiskLevel(api.RiskLevel, existing.RiskLevel) > 0 {
		existing.RiskLevel = api.RiskLevel
	}
}

// GetTrackers returns all detected trackers
func (a *DetectionAggregator) GetTrackers() []*UnifiedTracker {
	a.mu.RLock()
	defer a.mu.RUnlock()

	result := make([]*UnifiedTracker, 0, len(a.trackers))
	for _, tracker := range a.trackers {
		result = append(result, tracker)
	}
	return result
}

// GetTechnologies returns all detected technologies
func (a *DetectionAggregator) GetTechnologies() []*UnifiedTechnology {
	a.mu.RLock()
	defer a.mu.RUnlock()

	result := make([]*UnifiedTechnology, 0, len(a.technologies))
	for _, tech := range a.technologies {
		result = append(result, tech)
	}
	return result
}

// GetAPIs returns all detected APIs
func (a *DetectionAggregator) GetAPIs() []*UnifiedAPI {
	a.mu.RLock()
	defer a.mu.RUnlock()

	result := make([]*UnifiedAPI, 0, len(a.apis))
	for _, api := range a.apis {
		result = append(result, api)
	}
	return result
}

// Helper methods

func (a *DetectionAggregator) updateDetectionSource(source *DetectionSource, detectionType string) {
	switch detectionType {
	case "static":
		source.Static = true
	case "runtime":
		source.Runtime = true
	case "network":
		source.Network = true
	}
}

func (a *DetectionAggregator) mergeEvidence(existing, new *DetectionEvidence) {
	existing.Signatures = a.mergeStringSlices(existing.Signatures, new.Signatures)
	existing.Scripts = a.mergeStringSlices(existing.Scripts, new.Scripts)
	existing.NetworkRequests = a.mergeStringSlices(existing.NetworkRequests, new.NetworkRequests)
	existing.HTMLPatterns = a.mergeStringSlices(existing.HTMLPatterns, new.HTMLPatterns)
	existing.UsageContext = a.mergeStringSlices(existing.UsageContext, new.UsageContext)

	// Merge headers
	if new.Headers != nil {
		if existing.Headers == nil {
			existing.Headers = make(map[string]string)
		}
		for k, v := range new.Headers {
			existing.Headers[k] = v
		}
	}

	// Merge meta tags
	if new.MetaTags != nil {
		if existing.MetaTags == nil {
			existing.MetaTags = make(map[string]string)
		}
		for k, v := range new.MetaTags {
			existing.MetaTags[k] = v
		}
	}
}

func (a *DetectionAggregator) mergeTechnologySecurity(existing, new *TechnologySecurity) {
	// Update risk level to highest
	if a.compareRiskLevel(new.RiskLevel, existing.RiskLevel) > 0 {
		existing.RiskLevel = new.RiskLevel
	}

	existing.Vulnerabilities = a.mergeStringSlices(existing.Vulnerabilities, new.Vulnerabilities)
	existing.Recommendations = a.mergeStringSlices(existing.Recommendations, new.Recommendations)
	existing.CVEs = a.mergeStringSlices(existing.CVEs, new.CVEs)
}

func (a *DetectionAggregator) mergeStringSlices(existing, new []string) []string {
	seen := make(map[string]bool)
	for _, s := range existing {
		seen[s] = true
	}

	for _, s := range new {
		if !seen[s] {
			existing = append(existing, s)
			seen[s] = true
		}
	}

	return existing
}

func (a *DetectionAggregator) compareRiskLevel(level1, level2 string) int {
	levels := map[string]int{
		"critical": 4,
		"high":     3,
		"medium":   2,
		"low":      1,
		"none":     0,
	}

	return levels[strings.ToLower(level1)] - levels[strings.ToLower(level2)]
}

func (a *DetectionAggregator) compareConfidence(conf1, conf2 string) int {
	levels := map[string]int{
		"high":   3,
		"medium": 2,
		"low":    1,
	}

	return levels[strings.ToLower(conf1)] - levels[strings.ToLower(conf2)]
}

// GenerateSummaries creates summary statistics for trackers and technologies
func (a *DetectionAggregator) GenerateSummaries() (trackerSummary map[string]interface{}, techSummary map[string][]string) {
	a.mu.RLock()
	defer a.mu.RUnlock()

	// Tracker summary
	byCategory := make(map[string]int)
	byRisk := make(map[string]int)

	for _, tracker := range a.trackers {
		byCategory[tracker.Category]++
		byRisk[tracker.RiskLevel]++
	}

	trackerSummary = map[string]interface{}{
		"total":       len(a.trackers),
		"by_category": byCategory,
		"by_risk":     byRisk,
	}

	// Technology summary
	techSummary = make(map[string][]string)
	for _, tech := range a.technologies {
		category := strings.ToLower(tech.Category)
		techSummary[category] = append(techSummary[category], tech.Name)
	}

	return trackerSummary, techSummary
}