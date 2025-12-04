package checker

import (
	"strings"
)

// TrackerDetector detects third-party tracking scripts
type TrackerDetector struct {
	patterns map[string]*TrackerPattern
}

// TrackerPattern represents a pattern for detecting a tracker
type TrackerPattern struct {
	Name        string
	Category    string   // Analytics, Advertising, Social, etc.
	Domains     []string // Known domains for this tracker
	Signatures  []string // Code signatures to look for
	Purpose     string   // What data it collects
	PrivacyRisk string   // "low", "medium", "high"
}

// NewTrackerDetector creates a new tracker detector
func NewTrackerDetector() *TrackerDetector {
	detector := &TrackerDetector{
		patterns: make(map[string]*TrackerPattern),
	}
	detector.initPatterns()
	return detector
}

// initPatterns initializes all tracker detection patterns
func (d *TrackerDetector) initPatterns() {
	// Google Analytics (GA4 and Universal Analytics)
	d.addPattern("google_analytics", &TrackerPattern{
		Name:     "Google Analytics",
		Category: "Analytics",
		Domains: []string{
			"www.google-analytics.com",
			"www.googletagmanager.com",
			"analytics.google.com",
			"ssl.google-analytics.com",
		},
		Signatures: []string{
			"gtag(",
			"ga(",
			"_gaq.push",
			"GoogleAnalyticsObject",
			"google_tag_manager",
			"dataLayer.push",
			"GA_MEASUREMENT_ID",
			"G-",
			"UA-",
		},
		Purpose:     "Tracks user behavior, page views, events, and conversions",
		PrivacyRisk: "medium",
	})

	// Facebook Pixel
	d.addPattern("facebook_pixel", &TrackerPattern{
		Name:     "Facebook Pixel",
		Category: "Advertising",
		Domains: []string{
			"connect.facebook.net",
			"www.facebook.com/tr",
		},
		Signatures: []string{
			"fbq(",
			"_fbq",
			"facebook.com/tr",
			"fbevents.js",
			"Facebook Pixel Code",
		},
		Purpose:     "Tracks conversions, builds audiences for ads, and remarketing",
		PrivacyRisk: "high",
	})

	// Google Tag Manager
	d.addPattern("google_tag_manager", &TrackerPattern{
		Name:     "Google Tag Manager",
		Category: "Tag Management",
		Domains: []string{
			"www.googletagmanager.com",
		},
		Signatures: []string{
			"gtm.js",
			"GTM-",
			"google_tag_manager",
			"dataLayer",
			"gtm.start",
		},
		Purpose:     "Manages multiple tracking and marketing tags",
		PrivacyRisk: "medium",
	})

	// Hotjar
	d.addPattern("hotjar", &TrackerPattern{
		Name:     "Hotjar",
		Category: "Analytics",
		Domains: []string{
			"static.hotjar.com",
			"script.hotjar.com",
			"vars.hotjar.com",
		},
		Signatures: []string{
			"hjid:",
			"hjsv:",
			"_hjSettings",
			"hotjar.com",
			"hj(",
		},
		Purpose:     "Records user sessions, creates heatmaps, and collects feedback",
		PrivacyRisk: "high",
	})

	// Mixpanel
	d.addPattern("mixpanel", &TrackerPattern{
		Name:     "Mixpanel",
		Category: "Analytics",
		Domains: []string{
			"cdn.mxpnl.com",
			"api.mixpanel.com",
			"cdn4.mxpnl.com",
		},
		Signatures: []string{
			"mixpanel.",
			"mixpanel.track",
			"mixpanel.identify",
			"mixpanel.init",
			"mxpnl.com",
		},
		Purpose:     "Tracks user interactions and behavior analytics",
		PrivacyRisk: "medium",
	})

	// Segment
	d.addPattern("segment", &TrackerPattern{
		Name:     "Segment",
		Category: "Analytics",
		Domains: []string{
			"cdn.segment.com",
			"api.segment.io",
		},
		Signatures: []string{
			"analytics.js",
			"analytics.track",
			"analytics.identify",
			"analytics.page",
			"segment.com/analytics.js",
		},
		Purpose:     "Collects and routes analytics data to multiple tools",
		PrivacyRisk: "medium",
	})

	// LinkedIn Insight Tag
	d.addPattern("linkedin_insight", &TrackerPattern{
		Name:     "LinkedIn Insight Tag",
		Category: "Advertising",
		Domains: []string{
			"snap.licdn.com",
			"px.ads.linkedin.com",
		},
		Signatures: []string{
			"_linkedin_partner_id",
			"linkedin.com/px",
			"snap.licdn.com/li.lms-analytics",
		},
		Purpose:     "Tracks conversions and retargeting for LinkedIn ads",
		PrivacyRisk: "medium",
	})

	// Twitter Analytics
	d.addPattern("twitter_analytics", &TrackerPattern{
		Name:     "Twitter Analytics",
		Category: "Social",
		Domains: []string{
			"static.ads-twitter.com",
			"analytics.twitter.com",
		},
		Signatures: []string{
			"twq(",
			"twitter.com/i/adsct",
			"static.ads-twitter.com/uwt.js",
		},
		Purpose:     "Tracks conversions and audience for Twitter ads",
		PrivacyRisk: "medium",
	})

	// Adobe Analytics
	d.addPattern("adobe_analytics", &TrackerPattern{
		Name:     "Adobe Analytics",
		Category: "Analytics",
		Domains: []string{
			"omtrdc.net",
			"omniture.com",
			"2o7.net",
		},
		Signatures: []string{
			"s_code.js",
			"s.t()",
			"s.tl()",
			"AppMeasurement",
			"omniture",
		},
		Purpose:     "Enterprise-level web analytics and marketing reports",
		PrivacyRisk: "medium",
	})

	// Matomo (formerly Piwik)
	d.addPattern("matomo", &TrackerPattern{
		Name:     "Matomo",
		Category: "Analytics",
		Domains: []string{
			"matomo.cloud",
			"piwik.pro",
		},
		Signatures: []string{
			"_paq.push",
			"matomo.js",
			"piwik.js",
			"Piwik.getTracker",
			"matomo.php",
		},
		Purpose:     "Open-source web analytics platform",
		PrivacyRisk: "low",
	})

	// Amplitude
	d.addPattern("amplitude", &TrackerPattern{
		Name:     "Amplitude",
		Category: "Analytics",
		Domains: []string{
			"cdn.amplitude.com",
			"api.amplitude.com",
		},
		Signatures: []string{
			"amplitude.getInstance",
			"amplitude.track",
			"amplitude.init",
			"amplitude.js",
		},
		Purpose:     "Product analytics and user behavior tracking",
		PrivacyRisk: "medium",
	})

	// Heap Analytics
	d.addPattern("heap", &TrackerPattern{
		Name:     "Heap Analytics",
		Category: "Analytics",
		Domains: []string{
			"cdn.heapanalytics.com",
			"heapanalytics.com",
		},
		Signatures: []string{
			"heap.track",
			"heap.identify",
			"heap.addUserProperties",
			"heap.load",
		},
		Purpose:     "Automatic event tracking and analytics",
		PrivacyRisk: "medium",
	})

	// Crazy Egg
	d.addPattern("crazy_egg", &TrackerPattern{
		Name:     "Crazy Egg",
		Category: "Analytics",
		Domains: []string{
			"script.crazyegg.com",
			"trk.cetrk.com",
		},
		Signatures: []string{
			"crazyegg.com/pages/scripts",
			"CE2.js",
			"cetrk.com",
		},
		Purpose:     "Heatmaps and user session recordings",
		PrivacyRisk: "high",
	})

	// FullStory
	d.addPattern("fullstory", &TrackerPattern{
		Name:     "FullStory",
		Category: "Analytics",
		Domains: []string{
			"fullstory.com/s/fs.js",
			"edge.fullstory.com",
		},
		Signatures: []string{
			"FS.identify",
			"window['_fs_",
			"fullstory.com",
		},
		Purpose:     "Session replay and user experience analytics",
		PrivacyRisk: "high",
	})

	// Intercom
	d.addPattern("intercom", &TrackerPattern{
		Name:     "Intercom",
		Category: "Customer Support",
		Domains: []string{
			"widget.intercom.io",
			"js.intercomcdn.com",
		},
		Signatures: []string{
			"Intercom(",
			"intercomSettings",
			"window.Intercom",
			"intercom.io",
		},
		Purpose:     "Customer messaging and support tracking",
		PrivacyRisk: "medium",
	})

	// Drift
	d.addPattern("drift", &TrackerPattern{
		Name:     "Drift",
		Category: "Customer Support",
		Domains: []string{
			"js.driftt.com",
		},
		Signatures: []string{
			"drift.load",
			"drift.on",
			"drift.identify",
			"driftt.com",
		},
		Purpose:     "Conversational marketing and sales",
		PrivacyRisk: "medium",
	})

	// HubSpot
	d.addPattern("hubspot", &TrackerPattern{
		Name:     "HubSpot",
		Category: "Marketing",
		Domains: []string{
			"js.hs-scripts.com",
			"js.hsforms.net",
			"track.hubspot.com",
		},
		Signatures: []string{
			"_hsq.push",
			"hubspot.com",
			"hs-scripts.com",
			"hsforms.net",
		},
		Purpose:     "Inbound marketing and CRM tracking",
		PrivacyRisk: "medium",
	})

	// Klaviyo
	d.addPattern("klaviyo", &TrackerPattern{
		Name:     "Klaviyo",
		Category: "Marketing",
		Domains: []string{
			"static.klaviyo.com",
			"a.klaviyo.com",
		},
		Signatures: []string{
			"klaviyo.push",
			"klaviyo.identify",
			"klaviyo.com",
		},
		Purpose:     "Email marketing and e-commerce tracking",
		PrivacyRisk: "medium",
	})

	// Pinterest Tag
	d.addPattern("pinterest", &TrackerPattern{
		Name:     "Pinterest Tag",
		Category: "Advertising",
		Domains: []string{
			"s.pinimg.com",
			"ct.pinterest.com",
		},
		Signatures: []string{
			"pintrk(",
			"pinterest.com/ct",
			"pinimg.com",
		},
		Purpose:     "Conversion tracking for Pinterest ads",
		PrivacyRisk: "medium",
	})

	// TikTok Pixel
	d.addPattern("tiktok", &TrackerPattern{
		Name:     "TikTok Pixel",
		Category: "Advertising",
		Domains: []string{
			"analytics.tiktok.com",
		},
		Signatures: []string{
			"ttq.track",
			"ttq.load",
			"analytics.tiktok.com",
		},
		Purpose:     "Tracks conversions for TikTok ads",
		PrivacyRisk: "high",
	})

	// VWO (Visual Website Optimizer)
	d.addPattern("vwo", &TrackerPattern{
		Name:     "VWO",
		Category: "A/B Testing",
		Domains: []string{
			"dev.visualwebsiteoptimizer.com",
			"cdn.visualwebsiteoptimizer.com",
			"vwo.com",
		},
		Signatures: []string{
			"_vwo_code",
			"VWO.push",
			"_vis_opt_",
			"visualwebsiteoptimizer.com",
		},
		Purpose:     "A/B testing and conversion optimization",
		PrivacyRisk: "medium",
	})

	// Plausible Analytics
	d.addPattern("plausible", &TrackerPattern{
		Name:     "Plausible Analytics",
		Category: "Analytics",
		Domains: []string{
			"plausible.io",
			"analytics.plausible.io",
			"cdn.plausible.io",
		},
		Signatures: []string{
			"plausible(",
			"plausible.js",
			"plausible.io/js/",
			"data-domain=",
		},
		Purpose:     "Privacy-focused web analytics",
		PrivacyRisk: "low",
	})

	// Umami Analytics
	d.addPattern("umami", &TrackerPattern{
		Name:     "Umami Analytics",
		Category: "Analytics",
		Domains: []string{
			"umami.is",
			"analytics.umami.is",
			"cloud.umami.is",
		},
		Signatures: []string{
			"umami.track",
			"umami.js",
			"data-website-id=",
			"umami.pageView",
		},
		Purpose:     "Privacy-focused, open-source analytics",
		PrivacyRisk: "low",
	})

	// Fathom Analytics
	d.addPattern("fathom", &TrackerPattern{
		Name:     "Fathom Analytics",
		Category: "Analytics",
		Domains: []string{
			"cdn.usefathom.com",
			"usefathom.com",
		},
		Signatures: []string{
			"fathom.trackGoal",
			"fathom.trackEvent",
			"fathom.js",
			"data-site=",
		},
		Purpose:     "Privacy-focused website analytics",
		PrivacyRisk: "low",
	})

	// Simple Analytics
	d.addPattern("simple_analytics", &TrackerPattern{
		Name:     "Simple Analytics",
		Category: "Analytics",
		Domains: []string{
			"simpleanalytics.com",
			"sa.example.com",
			"scripts.simpleanalyticscdn.com",
		},
		Signatures: []string{
			"sa_event",
			"sa.js",
			"simpleanalytics.com/hello.js",
		},
		Purpose:     "Privacy-friendly analytics",
		PrivacyRisk: "low",
	})

	// Countly
	d.addPattern("countly", &TrackerPattern{
		Name:     "Countly",
		Category: "Analytics",
		Domains: []string{
			"cdn.countly.com",
			"cloud.count.ly",
		},
		Signatures: []string{
			"Countly.init",
			"Countly.track_view",
			"Countly.track_errors",
			"countly.js",
		},
		Purpose:     "Product analytics and marketing platform",
		PrivacyRisk: "medium",
	})

	// PostHog
	d.addPattern("posthog", &TrackerPattern{
		Name:     "PostHog",
		Category: "Analytics",
		Domains: []string{
			"app.posthog.com",
			"eu.posthog.com",
			"us.posthog.com",
		},
		Signatures: []string{
			"posthog.init",
			"posthog.capture",
			"posthog.identify",
			"posthog.js",
		},
		Purpose:     "Product analytics and session recording",
		PrivacyRisk: "medium",
	})

	// LogRocket
	d.addPattern("logrocket", &TrackerPattern{
		Name:     "LogRocket",
		Category: "Session Recording",
		Domains: []string{
			"cdn.logrocket.io",
			"cdn.lr-intake.io",
			"cdn.lr-ingest.io",
		},
		Signatures: []string{
			"LogRocket.init",
			"LogRocket.identify",
			"LogRocket.track",
			"logrocket.com",
		},
		Purpose:     "Session replay and error tracking",
		PrivacyRisk: "high",
	})

	// Smartlook
	d.addPattern("smartlook", &TrackerPattern{
		Name:     "Smartlook",
		Category: "Session Recording",
		Domains: []string{
			"rec.smartlook.com",
			"assets.smartlook.com",
		},
		Signatures: []string{
			"smartlook(",
			"smartlookClient.init",
			"smartlook.js",
		},
		Purpose:     "Session recording and heatmaps",
		PrivacyRisk: "high",
	})

	// Microsoft Clarity
	d.addPattern("clarity", &TrackerPattern{
		Name:     "Microsoft Clarity",
		Category: "Analytics",
		Domains: []string{
			"clarity.ms",
			"www.clarity.ms",
		},
		Signatures: []string{
			"clarity(",
			"clarity.js",
			"clarity.ms/tag",
		},
		Purpose:     "Session recording and heatmaps by Microsoft",
		PrivacyRisk: "medium",
	})

	// Optimizely
	d.addPattern("optimizely", &TrackerPattern{
		Name:     "Optimizely",
		Category: "A/B Testing",
		Domains: []string{
			"cdn.optimizely.com",
			"logx.optimizely.com",
		},
		Signatures: []string{
			"optimizely.push",
			"optimizelyEndUserId",
			"window.optimizely",
			"optimizely.js",
		},
		Purpose:     "A/B testing and experimentation platform",
		PrivacyRisk: "medium",
	})

	// LaunchDarkly
	d.addPattern("launchdarkly", &TrackerPattern{
		Name:     "LaunchDarkly",
		Category: "Feature Flags",
		Domains: []string{
			"app.launchdarkly.com",
			"events.launchdarkly.com",
			"cdn.launchdarkly.com",
		},
		Signatures: []string{
			"LDClient",
			"launchdarkly-js-client-sdk",
			"ldclient.js",
		},
		Purpose:     "Feature flag management and experimentation",
		PrivacyRisk: "low",
	})

	// Sentry
	d.addPattern("sentry", &TrackerPattern{
		Name:     "Sentry",
		Category: "Error Tracking",
		Domains: []string{
			"sentry.io",
			"browser.sentry-cdn.com",
			"o1.ingest.sentry.io",
		},
		Signatures: []string{
			"Sentry.init",
			"Sentry.captureException",
			"@sentry/browser",
			"sentry-cdn.com",
		},
		Purpose:     "Error tracking and performance monitoring",
		PrivacyRisk: "low",
	})

	// Rollbar
	d.addPattern("rollbar", &TrackerPattern{
		Name:     "Rollbar",
		Category: "Error Tracking",
		Domains: []string{
			"api.rollbar.com",
			"cdn.rollbar.com",
		},
		Signatures: []string{
			"Rollbar.init",
			"Rollbar.error",
			"rollbar.js",
			"_rollbarConfig",
		},
		Purpose:     "Error tracking and monitoring",
		PrivacyRisk: "low",
	})

	// Bugsnag
	d.addPattern("bugsnag", &TrackerPattern{
		Name:     "Bugsnag",
		Category: "Error Tracking",
		Domains: []string{
			"d2wy8f7a9ursnm.cloudfront.net",
			"sessions.bugsnag.com",
			"notify.bugsnag.com",
		},
		Signatures: []string{
			"Bugsnag.start",
			"bugsnag.js",
			"bugsnagClient",
		},
		Purpose:     "Error monitoring and crash reporting",
		PrivacyRisk: "low",
	})
}

// addPattern adds a tracker pattern to the detector
func (d *TrackerDetector) addPattern(key string, pattern *TrackerPattern) {
	d.patterns[key] = pattern
}

// DetectInHTML detects trackers in HTML content (script tags and sources)
func (d *TrackerDetector) DetectInHTML(html string) []DetectedTracker {
	var trackers []DetectedTracker
	detectedKeys := make(map[string]bool)

	htmlLower := strings.ToLower(html)

	for key, pattern := range d.patterns {
		if detectedKeys[key] {
			continue
		}

		// Check for domains in script src attributes
		for _, domain := range pattern.Domains {
			if strings.Contains(htmlLower, domain) {
				detectedKeys[key] = true
				trackers = append(trackers, DetectedTracker{
					Name:        pattern.Name,
					Category:    pattern.Category,
					Domain:      domain,
					Purpose:     pattern.Purpose,
					PrivacyRisk: pattern.PrivacyRisk,
				})
				break
			}
		}

		// Check for signatures in inline scripts
		if !detectedKeys[key] {
			for _, signature := range pattern.Signatures {
				if strings.Contains(html, signature) {
					detectedKeys[key] = true
					trackers = append(trackers, DetectedTracker{
						Name:        pattern.Name,
						Category:    pattern.Category,
						Domain:      "",
						Purpose:     pattern.Purpose,
						PrivacyRisk: pattern.PrivacyRisk,
					})
					break
				}
			}
		}
	}

	return trackers
}

// DetectInJavaScript detects trackers in JavaScript content
func (d *TrackerDetector) DetectInJavaScript(js string, scriptURL string) []DetectedTracker {
	var trackers []DetectedTracker
	detectedKeys := make(map[string]bool)

	// Check the script URL itself
	for key, pattern := range d.patterns {
		for _, domain := range pattern.Domains {
			if strings.Contains(scriptURL, domain) {
				detectedKeys[key] = true
				trackers = append(trackers, DetectedTracker{
					Name:        pattern.Name,
					Category:    pattern.Category,
					Domain:      domain,
					Purpose:     pattern.Purpose,
					PrivacyRisk: pattern.PrivacyRisk,
				})
				break
			}
		}
	}

	// Check JavaScript content for signatures
	for key, pattern := range d.patterns {
		if detectedKeys[key] {
			continue
		}

		for _, signature := range pattern.Signatures {
			if strings.Contains(js, signature) {
				detectedKeys[key] = true
				trackers = append(trackers, DetectedTracker{
					Name:        pattern.Name,
					Category:    pattern.Category,
					Domain:      extractDomainFromScript(js, pattern.Domains),
					Purpose:     pattern.Purpose,
					PrivacyRisk: pattern.PrivacyRisk,
				})
				break
			}
		}
	}

	return trackers
}

// extractDomainFromScript tries to find a matching domain in the script content
func extractDomainFromScript(script string, domains []string) string {
	for _, domain := range domains {
		if strings.Contains(script, domain) {
			return domain
		}
	}
	return ""
}

// AnalyzePrivacyRisks analyzes detected trackers for privacy risks
func (d *TrackerDetector) AnalyzePrivacyRisks(trackers []DetectedTracker, apis []DetectedAPI) []PrivacyRisk {
	var risks []PrivacyRisk

	// Check for multiple high-risk trackers
	highRiskCount := 0
	var highRiskTrackers []string
	for _, tracker := range trackers {
		if tracker.PrivacyRisk == "high" {
			highRiskCount++
			highRiskTrackers = append(highRiskTrackers, tracker.Name)
		}
	}

	if highRiskCount > 2 {
		risks = append(risks, PrivacyRisk{
			Type:        "excessive_tracking",
			Severity:    "high",
			Description: "Multiple high-risk tracking services detected",
			APIs:        highRiskTrackers,
			Mitigation:  "Consider using privacy-focused alternatives or reducing tracking",
		})
	}

	// Check for session recording tools
	sessionRecorders := []string{}
	for _, tracker := range trackers {
		if strings.Contains(strings.ToLower(tracker.Purpose), "session") ||
			strings.Contains(strings.ToLower(tracker.Purpose), "recording") ||
			strings.Contains(strings.ToLower(tracker.Purpose), "heatmap") {
			sessionRecorders = append(sessionRecorders, tracker.Name)
		}
	}

	if len(sessionRecorders) > 0 {
		risks = append(risks, PrivacyRisk{
			Type:        "session_recording",
			Severity:    "high",
			Description: "Session recording tools can capture sensitive user data",
			APIs:        sessionRecorders,
			Mitigation:  "Ensure user consent and mask sensitive information",
		})
	}

	// Check for advertising trackers combined with personal data APIs
	hasAdTrackers := false
	hasPersonalDataAPIs := false
	for _, tracker := range trackers {
		if tracker.Category == "Advertising" {
			hasAdTrackers = true
			break
		}
	}
	for _, api := range apis {
		if api.Category == "Location Services" || api.Category == "Device Access" {
			hasPersonalDataAPIs = true
			break
		}
	}

	if hasAdTrackers && hasPersonalDataAPIs {
		risks = append(risks, PrivacyRisk{
			Type:        "data_correlation",
			Severity:    "high",
			Description: "Advertising trackers combined with personal data access",
			APIs:        []string{},
			Mitigation:  "Review data sharing practices and privacy policy",
		})
	}

	return risks
}

// ConvertToUnified converts detected trackers to unified format with evidence
func (d *TrackerDetector) ConvertToUnified(trackers []DetectedTracker) []*UnifiedTracker {
	unified := make([]*UnifiedTracker, 0, len(trackers))

	for _, tracker := range trackers {
		// Get pattern info for this tracker
		var pattern *TrackerPattern
		for _, p := range d.patterns {
			if p.Name == tracker.Name {
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

		evidence := DetectionEvidence{}
		if pattern != nil {
			evidence.Signatures = pattern.Signatures
			evidence.Scripts = make([]string, 0)
		}

		unifiedTracker := &UnifiedTracker{
			Name:      tracker.Name,
			Category:  tracker.Category,
			RiskLevel: tracker.PrivacyRisk,
			Purpose:   tracker.Purpose,
			Detection: DetectionSource{
				Static: true, // Trackers detected from static analysis
			},
			Domains:  domains,
			Evidence: evidence,
		}

		unified = append(unified, unifiedTracker)
	}

	return unified
}