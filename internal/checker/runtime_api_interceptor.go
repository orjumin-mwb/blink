package checker

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"time"

	"github.com/chromedp/cdproto/page"
	"github.com/chromedp/chromedp"
)

// RuntimeAPIInterceptor detects actual API usage through runtime interception
type RuntimeAPIInterceptor struct{}

// APIUsageResult contains detailed information about actual API usage
type APIUsageResult struct {
	Available   map[string]bool            `json:"available"`
	ActualUsage map[string]*APIUsageDetail `json:"actual_usage"`
	Permissions map[string]*PermissionInfo `json:"permissions"`
	Timeline    []APICallEvent             `json:"timeline"`
}

// APIUsageDetail contains details about a specific API usage
type APIUsageDetail struct {
	Used      bool     `json:"used"`
	CallCount int      `json:"call_count"`
	FirstSeen string   `json:"first_seen,omitempty"`
	LastSeen  string   `json:"last_seen,omitempty"`
	Examples  []string `json:"examples,omitempty"`
}

// PermissionInfo contains permission status for an API
type PermissionInfo struct {
	State          string `json:"state"`           // 'granted', 'denied', 'prompt'
	Requested      bool   `json:"requested"`       // Whether permission was requested
	Granted        bool   `json:"granted"`         // Whether permission was granted
	PromptShown    bool   `json:"prompt_shown"`    // Whether permission prompt was triggered (even if auto-denied in headless)
}

// APICallEvent represents a single API call event
type APICallEvent struct {
	Timestamp string                 `json:"timestamp"`
	API       string                 `json:"api"`
	Method    string                 `json:"method"`
	Details   map[string]interface{} `json:"details,omitempty"`
}

// NewRuntimeAPIInterceptor creates a new API interceptor
func NewRuntimeAPIInterceptor() *RuntimeAPIInterceptor {
	return &RuntimeAPIInterceptor{}
}

// DetectAPIUsage performs runtime interception to detect actual API usage
func (r *RuntimeAPIInterceptor) DetectAPIUsage(url string, timeout time.Duration) (*APIUsageResult, error) {
	if timeout == 0 {
		timeout = 15 * time.Second
	}

	result := &APIUsageResult{
		Available:   make(map[string]bool),
		ActualUsage: make(map[string]*APIUsageDetail),
		Permissions: make(map[string]*PermissionInfo),
		Timeline:    []APICallEvent{},
	}

	// Find Chrome
	chromePath := findChromePath()
	if chromePath == "" {
		return result, fmt.Errorf("Chrome not found")
	}

	// Create browser context
	opts := []chromedp.ExecAllocatorOption{
		chromedp.ExecPath(chromePath),
		chromedp.Headless,
		chromedp.DisableGPU,
		chromedp.NoSandbox,
		chromedp.Flag("disable-dev-shm-usage", true),
		chromedp.UserAgent("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36"),
	}

	allocCtx, allocCancel := chromedp.NewExecAllocator(context.Background(), opts...)
	defer allocCancel()

	ctx, cancel := chromedp.NewContext(allocCtx, chromedp.WithLogf(log.Printf))
	defer cancel()

	timeoutCtx, timeoutCancel := context.WithTimeout(ctx, timeout)
	defer timeoutCancel()

	// Get the interception script
	interceptScript := r.getInterceptionScript()

	// Navigate and inject interception
	err := chromedp.Run(timeoutCtx,
		chromedp.ActionFunc(func(ctx context.Context) error {
			// Enable Page domain to inject script before page loads
			return page.Enable().Do(ctx)
		}),
		chromedp.ActionFunc(func(ctx context.Context) error {
			// Add script to evaluate on new document
			_, err := page.AddScriptToEvaluateOnNewDocument(interceptScript).Do(ctx)
			return err
		}),
		chromedp.Navigate(url),
		chromedp.Sleep(5*time.Second), // Wait for page to load and APIs to be used
	)

	if err != nil {
		return result, fmt.Errorf("navigation failed: %w", err)
	}

	// Retrieve the collected data
	var resultJSON string
	err = chromedp.Run(timeoutCtx,
		chromedp.Evaluate(`JSON.stringify(window.__API_USAGE_DATA__ || {})`, &resultJSON),
	)

	if err != nil {
		return result, fmt.Errorf("failed to retrieve usage data: %w", err)
	}

	// Parse the result
	if resultJSON != "" && resultJSON != "{}" {
		err = json.Unmarshal([]byte(resultJSON), result)
		if err != nil {
			return result, fmt.Errorf("failed to parse usage data: %w", err)
		}
	}

	return result, nil
}

// getInterceptionScript returns the JavaScript code for API interception
func (r *RuntimeAPIInterceptor) getInterceptionScript() string {
	return `
(function() {
	'use strict';

	// Initialize tracking object
	window.__API_USAGE_DATA__ = {
		available: {},
		actual_usage: {},
		permissions: {},
		timeline: []
	};

	const data = window.__API_USAGE_DATA__;

	function logAPICall(api, method, details) {
		const now = new Date().toISOString();

		// Initialize API usage if not exists
		if (!data.actual_usage[api]) {
			data.actual_usage[api] = {
				used: true,
				call_count: 0,
				first_seen: now,
				last_seen: now,
				examples: []
			};
		}

		// Update usage
		const usage = data.actual_usage[api];
		usage.used = true;
		usage.call_count++;
		usage.last_seen = now;

		// Add example (limit to 5)
		if (usage.examples.length < 5) {
			const example = method + (details ? ': ' + JSON.stringify(details).substring(0, 100) : '');
			usage.examples.push(example);
		}

		// Add to timeline
		data.timeline.push({
			timestamp: now,
			api: api,
			method: method,
			details: details
		});

		console.log('[API INTERCEPTOR] ' + api + '.' + method, details);
	}

	// === GEOLOCATION API ===
	if (navigator.geolocation) {
		data.available.geolocation = true;

		const originalGetCurrentPosition = navigator.geolocation.getCurrentPosition;
		const originalWatchPosition = navigator.geolocation.watchPosition;
		const originalClearWatch = navigator.geolocation.clearWatch;

		navigator.geolocation.getCurrentPosition = function(...args) {
			logAPICall('geolocation', 'getCurrentPosition', {
				hasSuccessCallback: typeof args[0] === 'function',
				hasErrorCallback: typeof args[1] === 'function'
			});
			// Mark that permission prompt was triggered
			if (!data.permissions.geolocation) {
				data.permissions.geolocation = {};
			}
			data.permissions.geolocation.prompt_shown = true;
			return originalGetCurrentPosition.apply(this, args);
		};

		navigator.geolocation.watchPosition = function(...args) {
			logAPICall('geolocation', 'watchPosition', {
				hasSuccessCallback: typeof args[0] === 'function'
			});
			// Mark that permission prompt was triggered
			if (!data.permissions.geolocation) {
				data.permissions.geolocation = {};
			}
			data.permissions.geolocation.prompt_shown = true;
			return originalWatchPosition.apply(this, args);
		};

		navigator.geolocation.clearWatch = function(...args) {
			logAPICall('geolocation', 'clearWatch', { watchId: args[0] });
			return originalClearWatch.apply(this, args);
		};
	}

	// === MEDIA DEVICES API ===
	if (navigator.mediaDevices) {
		data.available.mediaDevices = true;

		const originalGetUserMedia = navigator.mediaDevices.getUserMedia;
		const originalGetDisplayMedia = navigator.mediaDevices.getDisplayMedia;
		const originalEnumerateDevices = navigator.mediaDevices.enumerateDevices;

		if (originalGetUserMedia) {
			navigator.mediaDevices.getUserMedia = function(constraints) {
				logAPICall('mediaDevices', 'getUserMedia', {
					video: !!constraints.video,
					audio: !!constraints.audio,
					constraints: constraints
				});
				// Mark that permission prompt was triggered
				if (constraints.video) {
					if (!data.permissions.camera) {
						data.permissions.camera = {};
					}
					data.permissions.camera.prompt_shown = true;
				}
				if (constraints.audio) {
					if (!data.permissions.microphone) {
						data.permissions.microphone = {};
					}
					data.permissions.microphone.prompt_shown = true;
				}
				return originalGetUserMedia.call(this, constraints);
			};
		}

		if (originalGetDisplayMedia) {
			navigator.mediaDevices.getDisplayMedia = function(constraints) {
				logAPICall('mediaDevices', 'getDisplayMedia', {
					video: !!constraints.video,
					audio: !!constraints.audio
				});
				return originalGetDisplayMedia.call(this, constraints);
			};
		}

		if (originalEnumerateDevices) {
			navigator.mediaDevices.enumerateDevices = function() {
				logAPICall('mediaDevices', 'enumerateDevices', {
					purpose: 'device_fingerprinting'
				});
				return originalEnumerateDevices.call(this);
			};
		}
	}

	// === WEBRTC API ===
	const originalRTCPeerConnection = window.RTCPeerConnection || window.webkitRTCPeerConnection;
	if (originalRTCPeerConnection) {
		data.available.webrtc = true;

		window.RTCPeerConnection = function(config) {
			logAPICall('webrtc', 'RTCPeerConnection', {
				iceServers: config && config.iceServers ? config.iceServers.length : 0,
				hasConfig: !!config
			});
			return new originalRTCPeerConnection(config);
		};

		// Copy prototype
		window.RTCPeerConnection.prototype = originalRTCPeerConnection.prototype;

		if (window.webkitRTCPeerConnection) {
			window.webkitRTCPeerConnection = window.RTCPeerConnection;
		}
	}

	// === BEACON API ===
	if (navigator.sendBeacon) {
		data.available.beacon = true;

		const originalSendBeacon = navigator.sendBeacon.bind(navigator);
		navigator.sendBeacon = function(url, data) {
			logAPICall('beacon', 'sendBeacon', {
				url: url,
				dataSize: data ? (typeof data === 'string' ? data.length : JSON.stringify(data).length) : 0
			});
			return originalSendBeacon(url, data);
		};
	}

	// === LOCAL STORAGE API ===
	if (window.localStorage) {
		data.available.localStorage = true;

		const originalSetItem = localStorage.setItem;
		const originalGetItem = localStorage.getItem;
		const originalRemoveItem = localStorage.removeItem;
		const originalClear = localStorage.clear;

		localStorage.setItem = function(key, value) {
			logAPICall('localStorage', 'setItem', {
				key: key,
				valueSize: value ? value.length : 0,
				isSensitive: /token|password|secret|key|auth|session/i.test(key)
			});
			return originalSetItem.call(this, key, value);
		};

		localStorage.getItem = function(key) {
			logAPICall('localStorage', 'getItem', { key: key });
			return originalGetItem.call(this, key);
		};

		localStorage.removeItem = function(key) {
			logAPICall('localStorage', 'removeItem', { key: key });
			return originalRemoveItem.call(this, key);
		};

		localStorage.clear = function() {
			logAPICall('localStorage', 'clear', {});
			return originalClear.call(this);
		};
	}

	// === SESSION STORAGE API ===
	if (window.sessionStorage) {
		data.available.sessionStorage = true;

		const originalSetItem = sessionStorage.setItem;
		const originalGetItem = sessionStorage.getItem;

		sessionStorage.setItem = function(key, value) {
			logAPICall('sessionStorage', 'setItem', {
				key: key,
				valueSize: value ? value.length : 0
			});
			return originalSetItem.call(this, key, value);
		};

		sessionStorage.getItem = function(key) {
			logAPICall('sessionStorage', 'getItem', { key: key });
			return originalGetItem.call(this, key);
		};
	}

	// === NOTIFICATIONS API ===
	if (window.Notification) {
		data.available.notifications = true;

		const originalRequestPermission = Notification.requestPermission;
		const originalNotification = window.Notification;

		if (originalRequestPermission) {
			Notification.requestPermission = function() {
				logAPICall('notifications', 'requestPermission', {
					currentState: Notification.permission
				});
				// Mark that permission prompt was triggered
				if (!data.permissions.notifications) {
					data.permissions.notifications = {};
				}
				data.permissions.notifications.prompt_shown = true;
				return originalRequestPermission.apply(this, arguments);
			};
		}

		window.Notification = function(title, options) {
			logAPICall('notifications', 'new Notification', {
				title: title,
				hasIcon: !!(options && options.icon),
				hasBody: !!(options && options.body)
			});
			return new originalNotification(title, options);
		};

		window.Notification.prototype = originalNotification.prototype;
		window.Notification.permission = originalNotification.permission;
		window.Notification.requestPermission = Notification.requestPermission;
	}

	// === CLIPBOARD API ===
	if (navigator.clipboard) {
		data.available.clipboard = true;

		const originalWriteText = navigator.clipboard.writeText;
		const originalReadText = navigator.clipboard.readText;
		const originalWrite = navigator.clipboard.write;
		const originalRead = navigator.clipboard.read;

		if (originalWriteText) {
			navigator.clipboard.writeText = function(text) {
				logAPICall('clipboard', 'writeText', { textLength: text ? text.length : 0 });
				return originalWriteText.call(this, text);
			};
		}

		if (originalReadText) {
			navigator.clipboard.readText = function() {
				logAPICall('clipboard', 'readText', {});
				return originalReadText.call(this);
			};
		}

		if (originalWrite) {
			navigator.clipboard.write = function(data) {
				logAPICall('clipboard', 'write', {});
				return originalWrite.call(this, data);
			};
		}

		if (originalRead) {
			navigator.clipboard.read = function() {
				logAPICall('clipboard', 'read', {});
				return originalRead.call(this);
			};
		}
	}

	// === PERMISSIONS API ===
	// Check permissions after page loads
	setTimeout(async function() {
		if (navigator.permissions && navigator.permissions.query) {
			const permissionNames = ['geolocation', 'camera', 'microphone', 'notifications'];

			for (const name of permissionNames) {
				try {
					const result = await navigator.permissions.query({ name: name });
					// Preserve prompt_shown flag if already set
					const promptShown = data.permissions[name]?.prompt_shown || false;
					data.permissions[name] = {
						state: result.state,
						requested: result.state !== 'prompt',
						granted: result.state === 'granted',
						prompt_shown: promptShown
					};
				} catch (e) {
					// Permission not supported or error
				}
			}

			// Notifications uses different API
			if (window.Notification) {
				// Preserve prompt_shown flag if already set
				const promptShown = data.permissions.notifications?.prompt_shown || false;
				data.permissions.notifications = {
					state: Notification.permission,
					requested: Notification.permission !== 'default',
					granted: Notification.permission === 'granted',
					prompt_shown: promptShown
				};
			}
		}
	}, 2000);

	console.log('[API INTERCEPTOR] Monitoring initialized');
})();
`
}
