package checker

import (
	"io"
	"net/url"
	"path"
	"regexp"
	"strconv"
	"strings"

	"golang.org/x/net/html"
)

// HTMLParser handles HTML parsing and link extraction
type HTMLParser struct {
	baseURL   *url.URL
	maxLinks  int
	maxImages int
}

// NewHTMLParser creates a new HTML parser
func NewHTMLParser(baseURL string) (*HTMLParser, error) {
	u, err := url.Parse(baseURL)
	if err != nil {
		return nil, err
	}
	return &HTMLParser{
		baseURL:   u,
		maxLinks:  10000, // Safety limit
		maxImages: 100,   // Increased limit for better coverage
	}, nil
}

// Parse parses HTML content and extracts links and metadata
func (p *HTMLParser) Parse(body io.Reader) (*HTMLParseResult, error) {
	doc, err := html.Parse(body)
	if err != nil {
		return nil, err
	}

	result := &HTMLParseResult{
		Links:    make([]OutgoingLink, 0),
		Images:   make([]Image, 0),
		Metadata: &HTMLMetadata{
			OpenGraph:   make(map[string]string),
			TwitterCard: make(map[string]string),
		},
	}

	// Traverse the HTML tree
	p.traverse(doc, result)

	return result, nil
}

// traverse recursively walks the HTML tree
func (p *HTMLParser) traverse(n *html.Node, result *HTMLParseResult) {
	// Process the current node
	if n.Type == html.ElementNode {
		switch n.Data {
		case "a":
			if len(result.Links) < p.maxLinks {
				p.extractLink(n, result)
			}
		case "title":
			// Only extract title from head section (check parent hierarchy)
			if n.FirstChild != nil && n.FirstChild.Type == html.TextNode && p.isInHead(n) {
				result.Metadata.Title = strings.TrimSpace(n.FirstChild.Data)
			}
		case "meta":
			p.extractMeta(n, result)
		case "link":
			p.extractLinkTag(n, result)
		case "img":
			// Skip img tags that are inside picture elements (handled by extractPicture)
			if len(result.Images) < p.maxImages && !p.isInPicture(n) {
				p.extractImage(n, result)
			}
		case "picture":
			if len(result.Images) < p.maxImages {
				p.extractPicture(n, result)
			}
		case "svg":
			if len(result.Images) < p.maxImages {
				p.extractSVG(n, result)
			}
		}

		// Check for CSS background images in style attributes
		if len(result.Images) < p.maxImages {
			p.extractCSSBackgrounds(n, result)
		}
	}

	// Recursively traverse children
	for c := n.FirstChild; c != nil; c = c.NextSibling {
		p.traverse(c, result)
	}
}

// extractLink extracts information from <a> tags
func (p *HTMLParser) extractLink(n *html.Node, result *HTMLParseResult) {
	link := OutgoingLink{}

	// Extract attributes
	for _, attr := range n.Attr {
		switch attr.Key {
		case "href":
			link.Href = attr.Val
		case "rel":
			link.Rel = attr.Val
		}
	}

	// Skip if no href or if it's an anchor/javascript link
	if link.Href == "" || strings.HasPrefix(link.Href, "#") || strings.HasPrefix(link.Href, "javascript:") {
		return
	}

	// Resolve to absolute URL
	link.AbsoluteURL = p.resolveURL(link.Href)

	// Extract link text
	link.Text = p.extractText(n)

	result.Links = append(result.Links, link)
}

// extractMeta extracts information from <meta> tags
func (p *HTMLParser) extractMeta(n *html.Node, result *HTMLParseResult) {
	var name, property, content string

	for _, attr := range n.Attr {
		switch attr.Key {
		case "name":
			name = strings.ToLower(attr.Val)
		case "property":
			property = strings.ToLower(attr.Val)
		case "content":
			content = attr.Val
		}
	}

	if content == "" {
		return
	}

	// Standard meta tags
	switch name {
	case "description":
		result.Metadata.Description = content
	case "keywords":
		result.Metadata.Keywords = content
	case "author":
		result.Metadata.Author = content
	}

	// Open Graph tags
	if strings.HasPrefix(property, "og:") {
		result.Metadata.OpenGraph[property] = content
	}

	// Twitter Card tags
	if strings.HasPrefix(name, "twitter:") || strings.HasPrefix(property, "twitter:") {
		key := name
		if key == "" {
			key = property
		}
		result.Metadata.TwitterCard[key] = content
	}
}

// extractLinkTag extracts canonical URL from <link> tags
func (p *HTMLParser) extractLinkTag(n *html.Node, result *HTMLParseResult) {
	var rel, href string

	for _, attr := range n.Attr {
		switch attr.Key {
		case "rel":
			rel = strings.ToLower(attr.Val)
		case "href":
			href = attr.Val
		}
	}

	if rel == "canonical" && href != "" {
		result.Metadata.Canonical = p.resolveURL(href)
	}
}

// extractText recursively extracts text content from a node
func (p *HTMLParser) extractText(n *html.Node) string {
	var text strings.Builder

	var extract func(*html.Node)
	extract = func(node *html.Node) {
		if node.Type == html.TextNode {
			text.WriteString(node.Data)
		}
		for c := node.FirstChild; c != nil; c = c.NextSibling {
			extract(c)
		}
	}

	extract(n)
	return strings.TrimSpace(text.String())
}

// isInHead checks if a node is within the <head> section
func (p *HTMLParser) isInHead(n *html.Node) bool {
	for parent := n.Parent; parent != nil; parent = parent.Parent {
		if parent.Type == html.ElementNode && parent.Data == "head" {
			return true
		}
	}
	return false
}

// isInPicture checks if a node is within a <picture> element
func (p *HTMLParser) isInPicture(n *html.Node) bool {
	for parent := n.Parent; parent != nil; parent = parent.Parent {
		if parent.Type == html.ElementNode && parent.Data == "picture" {
			return true
		}
	}
	return false
}

// resolveURL resolves a potentially relative URL to absolute
func (p *HTMLParser) resolveURL(href string) string {
	u, err := url.Parse(href)
	if err != nil {
		return href
	}
	return p.baseURL.ResolveReference(u).String()
}

// CSS background image regex pattern
var cssBackgroundRegex = regexp.MustCompile(`url\s*\(\s*['"]?([^'")]+)['"]?\s*\)`)

// extractImage extracts information from <img> tags
func (p *HTMLParser) extractImage(n *html.Node, result *HTMLParseResult) {
	image := Image{
		SourceType: "img",
	}

	// Extract attributes
	for _, attr := range n.Attr {
		switch attr.Key {
		case "src":
			image.Src = attr.Val
		case "alt":
			image.Alt = attr.Val
		case "title":
			image.Title = attr.Val
		case "width":
			if w, err := strconv.Atoi(attr.Val); err == nil {
				image.Width = w
			}
		case "height":
			if h, err := strconv.Atoi(attr.Val); err == nil {
				image.Height = h
			}
		case "loading":
			image.Loading = attr.Val
		}
	}

	// Skip if no src or if it's a data URI
	if image.Src == "" || strings.HasPrefix(image.Src, "data:") {
		return
	}

	// Resolve to absolute URL
	image.AbsoluteURL = p.resolveURL(image.Src)

	// Detect format from URL
	image.Format = p.detectImageFormat(image.Src)

	result.Images = append(result.Images, image)
}

// extractPicture extracts the fallback <img> from <picture> elements
func (p *HTMLParser) extractPicture(n *html.Node, result *HTMLParseResult) {
	// Find the nested <img> tag
	for c := n.FirstChild; c != nil; c = c.NextSibling {
		if c.Type == html.ElementNode && c.Data == "img" {
			// Extract the img but mark it as from a picture element
			image := Image{
				SourceType: "picture",
			}

			for _, attr := range c.Attr {
				switch attr.Key {
				case "src":
					image.Src = attr.Val
				case "alt":
					image.Alt = attr.Val
				case "title":
					image.Title = attr.Val
				case "width":
					if w, err := strconv.Atoi(attr.Val); err == nil {
						image.Width = w
					}
				case "height":
					if h, err := strconv.Atoi(attr.Val); err == nil {
						image.Height = h
					}
				case "loading":
					image.Loading = attr.Val
				}
			}

			if image.Src != "" && !strings.HasPrefix(image.Src, "data:") {
				image.AbsoluteURL = p.resolveURL(image.Src)
				image.Format = p.detectImageFormat(image.Src)
				result.Images = append(result.Images, image)
			}
			break // Only process the first img
		}
	}
}

// extractSVG extracts inline SVG elements
func (p *HTMLParser) extractSVG(n *html.Node, result *HTMLParseResult) {
	image := Image{
		SourceType: "svg",
		Format:     "svg",
		Src:        "inline-svg",
		AbsoluteURL: "inline-svg",
	}

	// Extract attributes
	for _, attr := range n.Attr {
		switch attr.Key {
		case "width":
			if w, err := strconv.Atoi(strings.TrimSuffix(attr.Val, "px")); err == nil {
				image.Width = w
			}
		case "height":
			if h, err := strconv.Atoi(strings.TrimSuffix(attr.Val, "px")); err == nil {
				image.Height = h
			}
		case "viewBox":
			// Parse viewBox if width/height not set
			if image.Width == 0 || image.Height == 0 {
				parts := strings.Fields(attr.Val)
				if len(parts) == 4 {
					if w, err := strconv.ParseFloat(parts[2], 64); err == nil && image.Width == 0 {
						image.Width = int(w)
					}
					if h, err := strconv.ParseFloat(parts[3], 64); err == nil && image.Height == 0 {
						image.Height = int(h)
					}
				}
			}
		}
	}

	// Look for <title> element for accessibility
	for c := n.FirstChild; c != nil; c = c.NextSibling {
		if c.Type == html.ElementNode && c.Data == "title" {
			if c.FirstChild != nil && c.FirstChild.Type == html.TextNode {
				image.Alt = strings.TrimSpace(c.FirstChild.Data)
			}
			break
		}
	}

	result.Images = append(result.Images, image)
}

// extractCSSBackgrounds extracts background images from style attributes
func (p *HTMLParser) extractCSSBackgrounds(n *html.Node, result *HTMLParseResult) {
	// Look for style attribute
	var styleValue string
	for _, attr := range n.Attr {
		if attr.Key == "style" {
			styleValue = attr.Val
			break
		}
	}

	if styleValue == "" {
		return
	}

	// Find all url() occurrences
	matches := cssBackgroundRegex.FindAllStringSubmatch(styleValue, -1)
	for _, match := range matches {
		if len(match) > 1 {
			url := match[1]

			// Skip data URIs and empty URLs
			if url == "" || strings.HasPrefix(url, "data:") {
				continue
			}

			image := Image{
				Src:        url,
				AbsoluteURL: p.resolveURL(url),
				SourceType: "css",
				Format:     p.detectImageFormat(url),
			}

			result.Images = append(result.Images, image)

			// Check if we've reached the limit
			if len(result.Images) >= p.maxImages {
				return
			}
		}
	}
}

// detectImageFormat detects the image format from the URL
func (p *HTMLParser) detectImageFormat(imageURL string) string {
	// Get the file extension
	ext := strings.ToLower(path.Ext(imageURL))

	// Remove query parameters if present
	if idx := strings.Index(ext, "?"); idx > 0 {
		ext = ext[:idx]
	}

	switch ext {
	case ".jpg", ".jpeg":
		return "jpg"
	case ".png":
		return "png"
	case ".gif":
		return "gif"
	case ".webp":
		return "webp"
	case ".svg":
		return "svg"
	case ".avif":
		return "avif"
	case ".ico":
		return "ico"
	default:
		return "unknown"
	}
}