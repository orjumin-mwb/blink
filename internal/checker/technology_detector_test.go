package checker

import (
	"net/http"
	"strings"
	"testing"
)

// Sample HTML with multiple technologies
const sampleHTML = `
<!DOCTYPE html>
<html>
<head>
	<meta name="generator" content="WordPress 6.4.2">
	<link rel="stylesheet" href="https://cdn.shopify.com/assets/bootstrap.min.css">
	<script src="https://code.jquery.com/jquery-3.6.0.min.js"></script>
	<script src="https://cdn.jsdelivr.net/npm/lodash@4.17.21/lodash.min.js"></script>
	<script src="https://js.stripe.com/v3/"></script>
	<script src="https://www.google-analytics.com/analytics.js"></script>
</head>
<body>
	<div id="__next">
		<div class="container">
			<div class="flex grid p-4 m-2 text-center bg-blue-500">
				Tailwind content
			</div>
		</div>
	</div>
	<script src="/_next/static/chunks/main.js"></script>
</body>
</html>
`

func BenchmarkTechnologyDetection(b *testing.B) {
	headers := http.Header{}
	headers.Set("Server", "nginx/1.24.0")
	headers.Set("X-Powered-By", "PHP/8.2.0")
	headers.Set("cf-ray", "12345")

	cookies := "session_id=abc123; _ga=GA1.2.123456789"

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		detector := NewTechnologyDetector()
		_ = detector.DetectTechnologies(sampleHTML, headers, cookies)
	}
}

func BenchmarkTechnologyDetectionReused(b *testing.B) {
	headers := http.Header{}
	headers.Set("Server", "nginx/1.24.0")
	headers.Set("X-Powered-By", "PHP/8.2.0")
	headers.Set("cf-ray", "12345")

	cookies := "session_id=abc123; _ga=GA1.2.123456789"

	// Create detector once, reuse many times
	detector := NewTechnologyDetector()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = detector.DetectTechnologies(sampleHTML, headers, cookies)
	}
}

func BenchmarkDetectorInitialization(b *testing.B) {
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = NewTechnologyDetector()
	}
}

func TestTechnologyDetection(t *testing.T) {
	headers := http.Header{}
	headers.Set("Server", "nginx/1.24.0")
	headers.Set("X-Powered-By", "PHP/8.2.0")
	headers.Set("cf-ray", "12345")

	cookies := "session_id=abc123"

	detector := NewTechnologyDetector()
	technologies := detector.DetectTechnologies(sampleHTML, headers, cookies)

	if len(technologies) == 0 {
		t.Error("Expected to detect some technologies")
	}

	// Check for expected technologies
	found := make(map[string]bool)
	for _, tech := range technologies {
		found[tech.Name] = true
		t.Logf("Detected: %s (%s) - confidence: %s", tech.Name, tech.Category, tech.Confidence)
	}

	expected := []string{"nginx", "PHP", "Cloudflare", "WordPress"}
	for _, name := range expected {
		if !found[name] {
			t.Errorf("Expected to detect %s", name)
		}
	}

	// Should detect at least 10 technologies from the sample
	if len(technologies) < 10 {
		t.Errorf("Expected to detect at least 10 technologies, got %d", len(technologies))
	}
}

func TestLargeHTML(t *testing.T) {
	// Simulate large HTML (100KB)
	largeHTML := strings.Repeat(sampleHTML, 100)

	headers := http.Header{}
	headers.Set("Server", "nginx")

	detector := NewTechnologyDetector()

	// This shouldn't take too long
	technologies := detector.DetectTechnologies(largeHTML, headers, "")

	if len(technologies) == 0 {
		t.Error("Expected to detect technologies even in large HTML")
	}

	t.Logf("Detected %d technologies in %d KB HTML", len(technologies), len(largeHTML)/1024)
}
