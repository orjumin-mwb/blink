package checker

// DeepCheckResult extends CheckResult with deep analysis
type DeepCheckResult struct {
	// Embed basic check result
	CheckResult

	// Deep analysis fields
	OutgoingLinks []OutgoingLink `json:"outgoing_links,omitempty"`
	Technologies  []Technology   `json:"technologies,omitempty"`
	HTMLMetadata  *HTMLMetadata  `json:"html_metadata,omitempty"`
	Images        []Image        `json:"images"`
	ImageAnalysis *ImageAnalysis `json:"image_analysis,omitempty"`
}

// OutgoingLink represents a link found in the HTML
type OutgoingLink struct {
	Href        string `json:"href"`                // Original href attribute
	AbsoluteURL string `json:"absolute_url"`        // Resolved to absolute URL
	Text        string `json:"text,omitempty"`      // Link text content
	Rel         string `json:"rel,omitempty"`       // rel attribute if present
}

// Technology represents detected technology
type Technology struct {
	Name       string   `json:"name"`                 // e.g., "nginx"
	Category   string   `json:"category"`             // e.g., "Web Server"
	Version    string   `json:"version,omitempty"`    // e.g., "1.21.0"
	Confidence string   `json:"confidence,omitempty"` // "high", "medium", "low"
	Evidence   []string `json:"evidence,omitempty"`   // What detected it
}

// HTMLMetadata holds HTML meta information
type HTMLMetadata struct {
	Title       string            `json:"title,omitempty"`
	Description string            `json:"description,omitempty"`
	Keywords    string            `json:"keywords,omitempty"`
	Author      string            `json:"author,omitempty"`
	Canonical   string            `json:"canonical,omitempty"`
	OpenGraph   map[string]string `json:"open_graph,omitempty"`
	TwitterCard map[string]string `json:"twitter_card,omitempty"`
}

// Image represents an extracted image from HTML
type Image struct {
	Src         string `json:"src"`                  // Original src attribute
	AbsoluteURL string `json:"absolute_url"`         // Resolved to absolute URL
	Alt         string `json:"alt,omitempty"`       // Alt text for accessibility
	Title       string `json:"title,omitempty"`     // Title attribute
	Width       int    `json:"width,omitempty"`      // Width attribute
	Height      int    `json:"height,omitempty"`     // Height attribute
	Loading     string `json:"loading,omitempty"`    // lazy/eager
	Format      string `json:"format,omitempty"`     // jpg/png/webp/svg
	SourceType  string `json:"source_type"`         // "img"/"css"/"picture"/"svg"
}

// ImageAnalysis provides insights about images
type ImageAnalysis struct {
	TotalImages        int              `json:"total_images"`
	MissingAlt         []string         `json:"missing_alt,omitempty"`
	LazyLoadedCount    int              `json:"lazy_loaded_count"`
	MissingSizes       []string         `json:"missing_sizes,omitempty"`
	WebPUsage          int              `json:"webp_usage"`
	Formats            map[string]int   `json:"formats"`
	AccessibilityScore int              `json:"accessibility_score"` // 0-100
}

// HTMLParseResult holds parsing results (internal use)
type HTMLParseResult struct {
	Links    []OutgoingLink
	Metadata *HTMLMetadata
	Images   []Image
}