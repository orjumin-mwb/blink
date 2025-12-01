package checker

import (
	"strings"
)

// ImageAnalyzer analyzes extracted images for accessibility and SEO
type ImageAnalyzer struct {
	images []Image
}

// NewImageAnalyzer creates a new image analyzer
func NewImageAnalyzer(images []Image) *ImageAnalyzer {
	return &ImageAnalyzer{
		images: images,
	}
}

// Analyze performs comprehensive analysis on the extracted images
func (a *ImageAnalyzer) Analyze() *ImageAnalysis {
	if len(a.images) == 0 {
		return nil
	}

	analysis := &ImageAnalysis{
		TotalImages:  len(a.images),
		MissingAlt:   make([]string, 0),
		MissingSizes: make([]string, 0),
		Formats:      make(map[string]int),
	}

	imagesWithAlt := 0

	for _, img := range a.images {
		// Check for missing alt text (not applicable to CSS backgrounds)
		if img.SourceType != "css" {
			if img.Alt == "" {
				analysis.MissingAlt = append(analysis.MissingAlt, img.AbsoluteURL)
			} else {
				imagesWithAlt++
			}
		}

		// Check for missing dimensions
		if img.Width == 0 || img.Height == 0 {
			// Don't flag inline SVGs or CSS backgrounds for missing sizes
			if img.SourceType != "svg" && img.SourceType != "css" {
				analysis.MissingSizes = append(analysis.MissingSizes, img.AbsoluteURL)
			}
		}

		// Count lazy loading usage
		if strings.ToLower(img.Loading) == "lazy" {
			analysis.LazyLoadedCount++
		}

		// Track format distribution
		format := img.Format
		if format == "" {
			format = "unknown"
		}
		analysis.Formats[format]++

		// Count WebP usage
		if format == "webp" {
			analysis.WebPUsage++
		}
	}

	// Calculate accessibility score (simple percentage)
	// Only count images that should have alt text (exclude CSS backgrounds)
	imagesRequiringAlt := 0
	for _, img := range a.images {
		if img.SourceType != "css" {
			imagesRequiringAlt++
		}
	}

	if imagesRequiringAlt > 0 {
		analysis.AccessibilityScore = (imagesWithAlt * 100) / imagesRequiringAlt
	} else {
		// If only CSS background images, score is 100
		analysis.AccessibilityScore = 100
	}

	// Clean up empty slices to reduce JSON output
	if len(analysis.MissingAlt) == 0 {
		analysis.MissingAlt = nil
	}
	if len(analysis.MissingSizes) == 0 {
		analysis.MissingSizes = nil
	}

	return analysis
}