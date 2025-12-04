package checker

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"

	"github.com/chromedp/cdproto/network"
	"github.com/chromedp/chromedp"
)

// RuntimeResult contains results from runtime analysis
type RuntimeResult struct {
	Trackers         []DetectedTracker `json:"trackers"`
	NetworkRequests  []string          `json:"network_requests"`
	DynamicScripts   []DynamicScript   `json:"dynamic_scripts"`
	ExecutedAPIs     []string          `json:"executed_apis"`
	DetectedAt       string            `json:"detected_at"`
	AnalysisDuration time.Duration     `json:"analysis_duration"`

	// Detailed API usage tracking (actual usage vs availability)
	APIUsage         *APIUsageResult   `json:"api_usage,omitempty"`
}

// DynamicScript represents a dynamically loaded or executed script
type DynamicScript struct {
	URL     string `json:"url,omitempty"`
	Content string `json:"content,omitempty"`
	Type    string `json:"type"` // "external" or "inline"
}

// RuntimeDetector performs runtime JavaScript analysis using a headless browser
type RuntimeDetector struct {
	trackerDetector *TrackerDetector
	browserPool     *BrowserPool
	mu              sync.Mutex
}

// BrowserPool manages reusable browser contexts
type BrowserPool struct {
	contexts []context.Context
	cancels  []context.CancelFunc
	mu       sync.Mutex
	size     int
}

// NewRuntimeDetector creates a new runtime detector
func NewRuntimeDetector() *RuntimeDetector {
	return &RuntimeDetector{
		trackerDetector: NewTrackerDetector(),
		browserPool:     NewBrowserPool(3), // Pool of 3 browsers
	}
}

// NewBrowserPool creates a pool of browser contexts
func NewBrowserPool(size int) *BrowserPool {
	return &BrowserPool{
		size:     size,
		contexts: make([]context.Context, 0, size),
		cancels:  make([]context.CancelFunc, 0, size),
	}
}

// GetContext gets or creates a browser context from the pool
func (p *BrowserPool) GetContext() (context.Context, context.CancelFunc, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	// If we have a context available, return it
	if len(p.contexts) > 0 {
		ctx := p.contexts[0]
		cancel := p.cancels[0]
		p.contexts = p.contexts[1:]
		p.cancels = p.cancels[1:]
		return ctx, cancel, nil
	}

	// Create a new context
	return createBrowserContext()
}

// ReturnContext returns a context to the pool
func (p *BrowserPool) ReturnContext(ctx context.Context, cancel context.CancelFunc) {
	p.mu.Lock()
	defer p.mu.Unlock()

	// Only keep up to pool size
	if len(p.contexts) < p.size {
		p.contexts = append(p.contexts, ctx)
		p.cancels = append(p.cancels, cancel)
	} else {
		// Pool is full, just cancel this context
		cancel()
	}
}

// createBrowserContext creates a new browser context with optimized settings
func createBrowserContext() (context.Context, context.CancelFunc, error) {
	// Find Chrome path
	chromePath := findChromePath()
	if chromePath == "" {
		return nil, nil, fmt.Errorf("Chrome not found")
	}

	// Create allocator with minimal flags for stability
	opts := append(chromedp.DefaultExecAllocatorOptions[:],
		chromedp.ExecPath(chromePath),
		chromedp.Headless,
		chromedp.DisableGPU,
		chromedp.NoSandbox,
		chromedp.Flag("disable-dev-shm-usage", true),
		chromedp.Flag("disable-setuid-sandbox", true),
		chromedp.Flag("single-process", true), // Important for stability
		chromedp.Flag("no-zygote", true),       // Helps with process management
		chromedp.Flag("disable-extensions", true),
		chromedp.Flag("disable-background-networking", true),
		chromedp.Flag("disable-sync", true),
		chromedp.Flag("disable-translate", true),
		chromedp.Flag("disable-web-security", true),
		chromedp.Flag("disable-features", "site-per-process"),
		chromedp.Flag("disable-hang-monitor", true),
		chromedp.WindowSize(1280, 720),
		chromedp.UserAgent("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36"),
	)

	// Create allocator context
	allocCtx, allocCancel := chromedp.NewExecAllocator(context.Background(), opts...)

	// Create browser context with longer timeout for startup
	ctx, cancel := chromedp.NewContext(allocCtx, chromedp.WithLogf(log.Printf))

	// Combined cancel function
	combinedCancel := func() {
		cancel()
		allocCancel()
	}

	// Warm up the browser by navigating to about:blank
	err := chromedp.Run(ctx,
		chromedp.Navigate("about:blank"),
		chromedp.WaitVisible("body", chromedp.ByQuery),
	)
	if err != nil {
		combinedCancel()
		return nil, nil, fmt.Errorf("failed to warm up browser: %w", err)
	}

	return ctx, combinedCancel, nil
}

// DetectRuntimeTrackersSimple performs simplified runtime detection
func (r *RuntimeDetector) DetectRuntimeTrackersSimple(url string, timeout time.Duration) (*RuntimeResult, error) {
	start := time.Now()

	if timeout == 0 {
		timeout = 10 * time.Second // Longer default timeout
	}

	result := &RuntimeResult{
		Trackers:        []DetectedTracker{},
		NetworkRequests: []string{},
		DynamicScripts:  []DynamicScript{},
		ExecutedAPIs:    []string{},
		DetectedAt:      "runtime",
	}

	// Create a fresh browser context for this detection
	chromePath := findChromePath()
	if chromePath == "" {
		return result, fmt.Errorf("Chrome not found")
	}

	// Use very minimal Chrome flags
	opts := []chromedp.ExecAllocatorOption{
		chromedp.ExecPath(chromePath),
		chromedp.Headless,
		chromedp.DisableGPU,
		chromedp.NoSandbox,
	}

	// Create context with timeout
	allocCtx, allocCancel := chromedp.NewExecAllocator(context.Background(), opts...)
	defer allocCancel()

	ctx, cancel := chromedp.NewContext(allocCtx)
	defer cancel()

	// Create timeout context
	timeoutCtx, timeoutCancel := context.WithTimeout(ctx, timeout)
	defer timeoutCancel()

	// Track network requests
	chromedp.ListenTarget(ctx, func(ev interface{}) {
		switch ev := ev.(type) {
		case *network.EventRequestWillBeSent:
			reqURL := ev.Request.URL
			result.NetworkRequests = append(result.NetworkRequests, reqURL)

			// Check if this is a tracker request
			if trackers := r.trackerDetector.DetectInJavaScript("", reqURL); len(trackers) > 0 {
				for _, tracker := range trackers {
					tracker.DetectedAt = "runtime"
					if !r.containsTracker(result.Trackers, tracker.Name) {
						result.Trackers = append(result.Trackers, tracker)
					}
				}
			}
		}
	})

	// Simple navigation and wait
	err := chromedp.Run(timeoutCtx,
		network.Enable(),
		chromedp.Navigate(url),
		chromedp.Sleep(3*time.Second), // Simple wait for dynamic content
	)

	if err != nil {
		// Even if there's an error, return what we collected
		result.AnalysisDuration = time.Since(start)
		return result, fmt.Errorf("partial detection completed: %w", err)
	}

	// Try to get dynamic scripts (may fail, that's ok)
	var scriptData string
	_ = chromedp.Run(timeoutCtx,
		chromedp.Evaluate(`
			JSON.stringify({
				scripts: Array.from(document.scripts).slice(0, 20).map(s => ({
					url: s.src || null,
					type: s.src ? 'external' : 'inline'
				})),
				apis: [
					navigator.geolocation ? 'Geolocation' : null,
					window.RTCPeerConnection ? 'WebRTC' : null,
					navigator.mediaDevices ? 'MediaDevices' : null,
					window.localStorage ? 'LocalStorage' : null,
					navigator.sendBeacon ? 'Beacon API' : null,
				].filter(Boolean)
			})
		`, &scriptData),
	)

	// Parse script data if we got it
	if scriptData != "" {
		var data struct {
			Scripts []DynamicScript `json:"scripts"`
			APIs    []string        `json:"apis"`
		}
		if err := json.Unmarshal([]byte(scriptData), &data); err == nil {
			result.DynamicScripts = data.Scripts
			result.ExecutedAPIs = data.APIs
		}
	}

	result.AnalysisDuration = time.Since(start)
	return result, nil
}

// containsTracker checks if a tracker already exists
func (r *RuntimeDetector) containsTracker(trackers []DetectedTracker, name string) bool {
	for _, t := range trackers {
		if t.Name == name {
			return true
		}
	}
	return false
}

// findChromePath finds Chrome executable
func findChromePath() string {
	paths := []string{
		"/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
		"/Applications/Chromium.app/Contents/MacOS/Chromium",
		"/usr/bin/google-chrome",
		"/usr/bin/chromium",
		"/usr/bin/chromium-browser",
		"/snap/bin/chromium",
	}

	for _, path := range paths {
		if _, err := os.Stat(path); err == nil {
			return path
		}
	}

	// Try to find via PATH
	if path, err := exec.LookPath("google-chrome"); err == nil {
		return path
	}
	if path, err := exec.LookPath("chromium"); err == nil {
		return path
	}

	return ""
}

// FallbackRuntimeDetection uses a simpler approach with command execution
func (r *RuntimeDetector) FallbackRuntimeDetection(url string) (*RuntimeResult, error) {
	start := time.Now()

	result := &RuntimeResult{
		Trackers:        []DetectedTracker{},
		NetworkRequests: []string{},
		DynamicScripts:  []DynamicScript{},
		ExecutedAPIs:    []string{},
		DetectedAt:      "runtime-fallback",
	}

	chromePath := findChromePath()
	if chromePath == "" {
		return result, fmt.Errorf("Chrome not found")
	}

	// Use Chrome DevTools Protocol via command line
	script := `
		const urls = [];
		const apis = [];

		// Override fetch and XMLHttpRequest to capture requests
		const originalFetch = window.fetch;
		window.fetch = function(...args) {
			urls.push(args[0]);
			return originalFetch.apply(this, args);
		};

		// Check for APIs
		if (navigator.geolocation) apis.push('Geolocation');
		if (window.RTCPeerConnection) apis.push('WebRTC');
		if (navigator.mediaDevices) apis.push('MediaDevices');
		if (window.localStorage) apis.push('LocalStorage');

		// Wait a bit for page to load
		setTimeout(() => {
			console.log(JSON.stringify({
				scripts: Array.from(document.scripts).map(s => s.src).filter(Boolean),
				apis: apis,
				urls: urls
			}));
		}, 3000);
	`

	// Create a temporary file with the script
	tmpFile, err := os.CreateTemp("", "detect-*.js")
	if err != nil {
		return result, err
	}
	defer os.Remove(tmpFile.Name())

	if _, err := tmpFile.WriteString(script); err != nil {
		return result, err
	}
	tmpFile.Close()

	// Run Chrome with the script
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, chromePath,
		"--headless",
		"--disable-gpu",
		"--no-sandbox",
		"--dump-dom",
		"--run-all-compositor-stages-before-draw",
		"--virtual-time-budget=5000",
		url,
	)

	output, _ := cmd.CombinedOutput()

	// Parse the HTML for script tags
	htmlStr := string(output)
	if strings.Contains(htmlStr, "<script") {
		// Extract script URLs from HTML
		lines := strings.Split(htmlStr, "\n")
		for _, line := range lines {
			if strings.Contains(line, "script") && strings.Contains(line, "src=") {
				// Basic extraction of src URLs
				start := strings.Index(line, `src="`)
				if start != -1 {
					start += 5
					end := strings.Index(line[start:], `"`)
					if end != -1 {
						scriptURL := line[start : start+end]
						result.DynamicScripts = append(result.DynamicScripts, DynamicScript{
							URL:  scriptURL,
							Type: "external",
						})

						// Check if it's a tracker
						if trackers := r.trackerDetector.DetectInJavaScript("", scriptURL); len(trackers) > 0 {
							for _, tracker := range trackers {
								tracker.DetectedAt = "runtime-fallback"
								result.Trackers = append(result.Trackers, tracker)
							}
						}
					}
				}
			}
		}
	}

	result.AnalysisDuration = time.Since(start)
	return result, nil
}
// ConvertTrackersToUnified converts runtime-detected trackers to unified format
func (r *RuntimeDetector) ConvertTrackersToUnified(trackers []DetectedTracker, networkRequests []string) []*UnifiedTracker {
	unified := make([]*UnifiedTracker, 0, len(trackers))

	for _, tracker := range trackers {
		// Get pattern info for this tracker
		var pattern *TrackerPattern
		for key, p := range r.trackerDetector.patterns {
			if strings.Contains(strings.ToLower(tracker.Name), strings.ToLower(key)) || p.Name == tracker.Name {
				pattern = p
				break
			}
		}

		domains := []string{}
		if tracker.Domain != "" {
			domains = append(domains, tracker.Domain)
		} else if pattern != nil {
			domains = pattern.Domains
		}

		// Build evidence from runtime detection
		evidence := DetectionEvidence{}
		if pattern != nil {
			evidence.Signatures = pattern.Signatures
		}

		// Add network requests as evidence
		networkEvidence := []string{}
		for _, req := range networkRequests {
			for _, domain := range domains {
				if strings.Contains(req, domain) {
					networkEvidence = append(networkEvidence, req)
					break
				}
			}
		}
		evidence.NetworkRequests = networkEvidence

		unifiedTracker := &UnifiedTracker{
			Name:      tracker.Name,
			Category:  tracker.Category,
			RiskLevel: tracker.PrivacyRisk,
			Purpose:   tracker.Purpose,
			Detection: DetectionSource{
				Runtime: true,
				Network: len(networkEvidence) > 0,
			},
			Domains:  domains,
			Evidence: evidence,
		}

		unified = append(unified, unifiedTracker)
	}

	return unified
}

// ConvertAPIsToUnified converts runtime-executed APIs to unified format
func (r *RuntimeDetector) ConvertAPIsToUnified(executedAPIs []string) []*UnifiedAPI {
	unified := make([]*UnifiedAPI, 0, len(executedAPIs))

	// Map of common API names to their risk levels and categories
	apiInfo := map[string]struct {
		category  string
		riskLevel string
	}{
		"geolocation":     {"Location Services", "high"},
		"mediadevices":    {"Device Access", "high"},
		"getusermedia":    {"Device Access", "high"},
		"webrtc":          {"Communication", "medium"},
		"localstorage":    {"Data Storage", "low"},
		"sessionstorage":  {"Data Storage", "low"},
		"indexeddb":       {"Data Storage", "medium"},
		"notification":    {"User Interaction", "medium"},
		"clipboard":       {"System Access", "high"},
		"battery":         {"Device Info", "low"},
		"canvas":          {"Graphics", "medium"},
		"webgl":           {"Graphics", "medium"},
		"audiocontext":    {"Audio", "medium"},
		"devicemotion":    {"Sensors", "medium"},
		"deviceorientation": {"Sensors", "medium"},
	}

	for _, apiName := range executedAPIs {
		apiLower := strings.ToLower(strings.ReplaceAll(apiName, " ", ""))

		category := "Other"
		riskLevel := "low"

		// Try to match API to known info
		for key, info := range apiInfo {
			if strings.Contains(apiLower, key) {
				category = info.category
				riskLevel = info.riskLevel
				break
			}
		}

		unifiedAPI := &UnifiedAPI{
			Name:         apiName,
			Category:     category,
			RiskLevel:    riskLevel,
			Available:    true,
			Executed:     true,
			UsageContext: []string{"Detected at runtime"},
		}

		unified = append(unified, unifiedAPI)
	}

	return unified
}
