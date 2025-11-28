package checker

import (
	"io"
	"net/url"
	"strings"

	"golang.org/x/net/html"
)

// HTMLParser handles HTML parsing and link extraction
type HTMLParser struct {
	baseURL  *url.URL
	maxLinks int
}

// NewHTMLParser creates a new HTML parser
func NewHTMLParser(baseURL string) (*HTMLParser, error) {
	u, err := url.Parse(baseURL)
	if err != nil {
		return nil, err
	}
	return &HTMLParser{
		baseURL:  u,
		maxLinks: 10000, // Safety limit
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
	// Safety check for link count
	if len(result.Links) >= p.maxLinks {
		return
	}

	// Process the current node
	if n.Type == html.ElementNode {
		switch n.Data {
		case "a":
			p.extractLink(n, result)
		case "title":
			if n.FirstChild != nil && n.FirstChild.Type == html.TextNode {
				result.Metadata.Title = strings.TrimSpace(n.FirstChild.Data)
			}
		case "meta":
			p.extractMeta(n, result)
		case "link":
			p.extractLinkTag(n, result)
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

// resolveURL resolves a potentially relative URL to absolute
func (p *HTMLParser) resolveURL(href string) string {
	u, err := url.Parse(href)
	if err != nil {
		return href
	}
	return p.baseURL.ResolveReference(u).String()
}