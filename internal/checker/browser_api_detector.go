package checker

import (
	"regexp"
	"strings"
)

// BrowserAPIDetector detects browser API usage in JavaScript code
type BrowserAPIDetector struct {
	patterns map[string]*APIPattern
}

// APIPattern represents a pattern for detecting an API
type APIPattern struct {
	Name        string
	Category    string
	Patterns    []*regexp.Regexp
	RiskLevel   string
	Description string
}

// NewBrowserAPIDetector creates a new browser API detector
func NewBrowserAPIDetector() *BrowserAPIDetector {
	detector := &BrowserAPIDetector{
		patterns: make(map[string]*APIPattern),
	}
	detector.initPatterns()
	return detector
}

// initPatterns initializes all detection patterns
func (d *BrowserAPIDetector) initPatterns() {
	// Geolocation APIs
	d.addPattern("geolocation", &APIPattern{
		Name:     "Geolocation API",
		Category: "Location Services",
		Patterns: []*regexp.Regexp{
			regexp.MustCompile(`navigator\.geolocation`),
			regexp.MustCompile(`getCurrentPosition\s*\(`),
			regexp.MustCompile(`watchPosition\s*\(`),
			regexp.MustCompile(`clearWatch\s*\(`),
		},
		RiskLevel:   "high",
		Description: "Accesses user's geographic location",
	})

	// Media Devices
	d.addPattern("media_devices", &APIPattern{
		Name:     "Media Devices API",
		Category: "Device Access",
		Patterns: []*regexp.Regexp{
			regexp.MustCompile(`navigator\.mediaDevices`),
			regexp.MustCompile(`getUserMedia\s*\(`),
			regexp.MustCompile(`getDisplayMedia\s*\(`),
			regexp.MustCompile(`enumerateDevices\s*\(`),
			regexp.MustCompile(`getSupportedConstraints\s*\(`),
		},
		RiskLevel:   "high",
		Description: "Accesses camera, microphone, or screen",
	})

	// WebRTC
	d.addPattern("webrtc", &APIPattern{
		Name:     "WebRTC",
		Category: "Communication",
		Patterns: []*regexp.Regexp{
			regexp.MustCompile(`RTCPeerConnection`),
			regexp.MustCompile(`RTCDataChannel`),
			regexp.MustCompile(`RTCSessionDescription`),
			regexp.MustCompile(`RTCIceCandidate`),
			regexp.MustCompile(`webkitRTCPeerConnection`),
		},
		RiskLevel:   "medium",
		Description: "Enables real-time communication",
	})

	// Device Motion and Orientation
	d.addPattern("device_motion", &APIPattern{
		Name:     "Device Motion API",
		Category: "Sensors",
		Patterns: []*regexp.Regexp{
			regexp.MustCompile(`DeviceMotionEvent`),
			regexp.MustCompile(`DeviceOrientationEvent`),
			regexp.MustCompile(`addEventListener\s*\(\s*['"]devicemotion`),
			regexp.MustCompile(`addEventListener\s*\(\s*['"]deviceorientation`),
			regexp.MustCompile(`window\.ondevicemotion`),
			regexp.MustCompile(`window\.ondeviceorientation`),
		},
		RiskLevel:   "medium",
		Description: "Accesses device motion and orientation sensors",
	})

	// Storage APIs
	d.addPattern("storage", &APIPattern{
		Name:     "Storage APIs",
		Category: "Data Storage",
		Patterns: []*regexp.Regexp{
			regexp.MustCompile(`localStorage\.`),
			regexp.MustCompile(`sessionStorage\.`),
			regexp.MustCompile(`indexedDB\.`),
			regexp.MustCompile(`openDatabase\s*\(`),
			regexp.MustCompile(`navigator\.storage`),
		},
		RiskLevel:   "low",
		Description: "Stores data locally in the browser",
	})

	// Notifications
	d.addPattern("notifications", &APIPattern{
		Name:     "Notifications API",
		Category: "User Interaction",
		Patterns: []*regexp.Regexp{
			regexp.MustCompile(`Notification\.requestPermission`),
			regexp.MustCompile(`new\s+Notification\s*\(`),
			regexp.MustCompile(`navigator\.permissions\.query\s*\(\s*{\s*name\s*:\s*['"]notifications`),
		},
		RiskLevel:   "medium",
		Description: "Sends desktop notifications",
	})

	// Clipboard
	d.addPattern("clipboard", &APIPattern{
		Name:     "Clipboard API",
		Category: "System Access",
		Patterns: []*regexp.Regexp{
			regexp.MustCompile(`navigator\.clipboard`),
			regexp.MustCompile(`clipboard\.writeText`),
			regexp.MustCompile(`clipboard\.readText`),
			regexp.MustCompile(`clipboard\.write`),
			regexp.MustCompile(`clipboard\.read`),
			regexp.MustCompile(`document\.execCommand\s*\(\s*['"]copy`),
			regexp.MustCompile(`document\.execCommand\s*\(\s*['"]paste`),
		},
		RiskLevel:   "high",
		Description: "Accesses system clipboard",
	})

	// Battery
	d.addPattern("battery", &APIPattern{
		Name:     "Battery API",
		Category: "Device Info",
		Patterns: []*regexp.Regexp{
			regexp.MustCompile(`navigator\.getBattery`),
			regexp.MustCompile(`navigator\.battery`),
			regexp.MustCompile(`BatteryManager`),
		},
		RiskLevel:   "low",
		Description: "Accesses battery status",
	})

	// Canvas Fingerprinting
	d.addPattern("canvas_fingerprint", &APIPattern{
		Name:     "Canvas Fingerprinting",
		Category: "Fingerprinting",
		Patterns: []*regexp.Regexp{
			regexp.MustCompile(`canvas\.toDataURL`),
			regexp.MustCompile(`getImageData\s*\(`),
			regexp.MustCompile(`measureText\s*\(`),
			regexp.MustCompile(`getContext\s*\(\s*['"]2d`),
		},
		RiskLevel:   "high",
		Description: "Potential browser fingerprinting via canvas",
	})

	// WebGL Fingerprinting
	d.addPattern("webgl_fingerprint", &APIPattern{
		Name:     "WebGL Fingerprinting",
		Category: "Fingerprinting",
		Patterns: []*regexp.Regexp{
			regexp.MustCompile(`getContext\s*\(\s*['"]webgl`),
			regexp.MustCompile(`getContext\s*\(\s*['"]experimental-webgl`),
			regexp.MustCompile(`WebGLRenderingContext`),
			regexp.MustCompile(`WebGL2RenderingContext`),
			regexp.MustCompile(`getParameter\s*\(`),
			regexp.MustCompile(`getSupportedExtensions\s*\(`),
		},
		RiskLevel:   "high",
		Description: "Potential browser fingerprinting via WebGL",
	})

	// Audio Context
	d.addPattern("audio_context", &APIPattern{
		Name:     "Audio Context",
		Category: "Media",
		Patterns: []*regexp.Regexp{
			regexp.MustCompile(`AudioContext`),
			regexp.MustCompile(`webkitAudioContext`),
			regexp.MustCompile(`OfflineAudioContext`),
			regexp.MustCompile(`createOscillator\s*\(`),
			regexp.MustCompile(`createDynamicsCompressor\s*\(`),
		},
		RiskLevel:   "medium",
		Description: "Audio processing and potential fingerprinting",
	})

	// Screen Information
	d.addPattern("screen_info", &APIPattern{
		Name:     "Screen Information",
		Category: "Device Info",
		Patterns: []*regexp.Regexp{
			regexp.MustCompile(`screen\.width`),
			regexp.MustCompile(`screen\.height`),
			regexp.MustCompile(`screen\.availWidth`),
			regexp.MustCompile(`screen\.availHeight`),
			regexp.MustCompile(`screen\.colorDepth`),
			regexp.MustCompile(`screen\.pixelDepth`),
			regexp.MustCompile(`devicePixelRatio`),
		},
		RiskLevel:   "low",
		Description: "Accesses screen dimensions and properties",
	})

	// Web Workers
	d.addPattern("web_workers", &APIPattern{
		Name:     "Web Workers",
		Category: "Background Processing",
		Patterns: []*regexp.Regexp{
			regexp.MustCompile(`new\s+Worker\s*\(`),
			regexp.MustCompile(`new\s+SharedWorker\s*\(`),
			regexp.MustCompile(`new\s+ServiceWorker\s*\(`),
			regexp.MustCompile(`navigator\.serviceWorker`),
		},
		RiskLevel:   "low",
		Description: "Runs scripts in background threads",
	})

	// Payment Request
	d.addPattern("payment", &APIPattern{
		Name:     "Payment Request API",
		Category: "E-commerce",
		Patterns: []*regexp.Regexp{
			regexp.MustCompile(`PaymentRequest`),
			regexp.MustCompile(`new\s+PaymentRequest\s*\(`),
			regexp.MustCompile(`canMakePayment\s*\(`),
		},
		RiskLevel:   "medium",
		Description: "Handles payment information",
	})

	// Bluetooth
	d.addPattern("bluetooth", &APIPattern{
		Name:     "Web Bluetooth API",
		Category: "Device Access",
		Patterns: []*regexp.Regexp{
			regexp.MustCompile(`navigator\.bluetooth`),
			regexp.MustCompile(`requestDevice\s*\(`),
			regexp.MustCompile(`BluetoothDevice`),
		},
		RiskLevel:   "high",
		Description: "Accesses Bluetooth devices",
	})

	// USB
	d.addPattern("usb", &APIPattern{
		Name:     "WebUSB API",
		Category: "Device Access",
		Patterns: []*regexp.Regexp{
			regexp.MustCompile(`navigator\.usb`),
			regexp.MustCompile(`requestDevice\s*\(`),
			regexp.MustCompile(`getDevices\s*\(`),
		},
		RiskLevel:   "high",
		Description: "Accesses USB devices",
	})

	// Gamepad
	d.addPattern("gamepad", &APIPattern{
		Name:     "Gamepad API",
		Category: "Device Access",
		Patterns: []*regexp.Regexp{
			regexp.MustCompile(`navigator\.getGamepads`),
			regexp.MustCompile(`GamepadEvent`),
			regexp.MustCompile(`addEventListener\s*\(\s*['"]gamepad`),
		},
		RiskLevel:   "low",
		Description: "Accesses gamepad controllers",
	})

	// Permissions
	d.addPattern("permissions", &APIPattern{
		Name:     "Permissions API",
		Category: "System Access",
		Patterns: []*regexp.Regexp{
			regexp.MustCompile(`navigator\.permissions`),
			regexp.MustCompile(`permissions\.query\s*\(`),
			regexp.MustCompile(`permissions\.request\s*\(`),
		},
		RiskLevel:   "medium",
		Description: "Queries and requests permissions",
	})

	// Wake Lock
	d.addPattern("wake_lock", &APIPattern{
		Name:     "Wake Lock API",
		Category: "System Control",
		Patterns: []*regexp.Regexp{
			regexp.MustCompile(`navigator\.wakeLock`),
			regexp.MustCompile(`wakeLock\.request\s*\(`),
		},
		RiskLevel:   "low",
		Description: "Prevents screen from sleeping",
	})
}

// addPattern adds a pattern to the detector
func (d *BrowserAPIDetector) addPattern(key string, pattern *APIPattern) {
	d.patterns[key] = pattern
}

// Detect analyzes JavaScript content and returns detected APIs
func (d *BrowserAPIDetector) Detect(content string, source string) []DetectedAPI {
	var apis []DetectedAPI
	detectedKeys := make(map[string]bool)

	for key, pattern := range d.patterns {
		if detectedKeys[key] {
			continue
		}

		var usageExamples []string
		for _, regex := range pattern.Patterns {
			matches := regex.FindAllString(content, -1)
			if len(matches) > 0 {
				// Collect up to 3 usage examples
				for i, match := range matches {
					if i >= 3 {
						break
					}
					// Extract a bit of context around the match
					context := extractContext(content, match)
					if context != "" {
						usageExamples = append(usageExamples, context)
					}
				}
			}
		}

		if len(usageExamples) > 0 {
			detectedKeys[key] = true
			apis = append(apis, DetectedAPI{
				Name:        pattern.Name,
				Category:    pattern.Category,
				Usage:       usageExamples,
				RiskLevel:   pattern.RiskLevel,
				Description: pattern.Description,
				FoundIn:     source,
			})
		}
	}

	return apis
}

// extractContext extracts surrounding context for a match
func extractContext(content, match string) string {
	index := strings.Index(content, match)
	if index == -1 {
		return match
	}

	// Get up to 50 characters before and after
	start := index - 50
	if start < 0 {
		start = 0
	}
	end := index + len(match) + 50
	if end > len(content) {
		end = len(content)
	}

	context := content[start:end]
	// Clean up whitespace
	context = strings.TrimSpace(context)
	context = strings.ReplaceAll(context, "\n", " ")
	context = strings.ReplaceAll(context, "\t", " ")
	// Collapse multiple spaces
	for strings.Contains(context, "  ") {
		context = strings.ReplaceAll(context, "  ", " ")
	}

	return context
}

// AnalyzeFingerprinting checks for potential fingerprinting
func (d *BrowserAPIDetector) AnalyzeFingerprinting(apis []DetectedAPI) *FingerprintAnalysis {
	fingerprintTechniques := []string{}
	uniqueAPIs := make(map[string]bool)
	score := 0

	for _, api := range apis {
		uniqueAPIs[api.Name] = true

		// Check for known fingerprinting techniques
		if strings.Contains(api.Name, "Canvas") {
			fingerprintTechniques = append(fingerprintTechniques, "canvas")
			score += 20
		}
		if strings.Contains(api.Name, "WebGL") {
			fingerprintTechniques = append(fingerprintTechniques, "webgl")
			score += 20
		}
		if strings.Contains(api.Name, "Audio Context") {
			fingerprintTechniques = append(fingerprintTechniques, "audio")
			score += 15
		}
		if strings.Contains(api.Name, "Screen Information") {
			fingerprintTechniques = append(fingerprintTechniques, "screen")
			score += 10
		}
		if api.Category == "Device Info" {
			score += 5
		}
	}

	// Cap score at 100
	if score > 100 {
		score = 100
	}

	if score == 0 {
		return nil
	}

	// Calculate entropy (simplified)
	entropy := float64(len(uniqueAPIs)) * 1.5

	return &FingerprintAnalysis{
		Score:      score,
		Techniques: fingerprintTechniques,
		Entropy:    entropy,
		UniqueAPIs: len(uniqueAPIs),
	}
}

// ConvertToUnified converts detected APIs to unified format
func (d *BrowserAPIDetector) ConvertToUnified(apis []DetectedAPI, executed bool) []*UnifiedAPI {
	unified := make([]*UnifiedAPI, 0, len(apis))

	for _, api := range apis {
		usageContext := []string{}
		if api.Usage != nil {
			usageContext = api.Usage
		}

		unifiedAPI := &UnifiedAPI{
			Name:         api.Name,
			Category:     api.Category,
			RiskLevel:    api.RiskLevel,
			Available:    !executed,  // If not executed, means available only
			Executed:     executed,
			UsageContext: usageContext,
		}

		unified = append(unified, unifiedAPI)
	}

	return unified
}