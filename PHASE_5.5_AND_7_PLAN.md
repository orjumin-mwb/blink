# Implementation Plan: Redirect Chain & Deep-Check Endpoint

## Overview

This plan adds two enhancements to the blink link checker:

1. **Phase 5.5**: Add redirect chain tracking to existing `/check` endpoint (minimal overhead)
2. **Phase 7**: New `/deep-check` endpoint with HTML parsing, link extraction, and technology detection

## User Requirements (Confirmed)

- **Speed Priority**: Critical (<100ms) for `/check` endpoint - must stay minimal
- **Separate Endpoint**: `/deep-check` for detailed analysis (200ms-2s acceptable)
- **Features Priority**:
  1. Redirect chain details
  2. Outgoing links extraction
  3. Technology detection (Wappalyzer-style)
  4. HTML metadata (title, meta tags, Open Graph)

---

## Phase 5.5: Redirect Chain Tracking

### Goal
Add detailed redirect chain to `/check` endpoint response with minimal performance impact (<1ms overhead).

### Data Structure

Add to `internal/checker/result.go`:

```go
// RedirectHop represents a single redirect in the chain
type RedirectHop struct {
    URL      string `json:"url"`      // The URL that redirected
    Status   int    `json:"status"`   // HTTP status (301, 302, 307, 308)
    Location string `json:"location"` // Value of Location header
}
```

Add field to `CheckResult` struct (after line 15):
```go
RedirectChain []RedirectHop `json:"redirect_chain,omitempty"`
```

### Implementation

**File: `internal/checker/checker.go`**

In the `CheckURL` method, modify the redirect loop (lines 62-122):

1. Before the loop, initialize: `redirectChain := make([]RedirectHop, 0, opts.MaxRedirects)`
2. Inside redirect detection block (after line 91), capture hop:
   ```go
   redirectChain = append(redirectChain, RedirectHop{
       URL:      currentURL,
       Status:   resp.StatusCode,
       Location: location,
   })
   ```
3. After the loop (before line 124), assign to result:
   ```go
   if len(redirectChain) > 0 {
       result.RedirectChain = redirectChain
   }
   ```

### Example Response

**No redirects:**
```json
{
  "url": "https://github.com",
  "redirect_count": 0
  // redirect_chain omitted
}
```

**With redirects:**
```json
{
  "url": "http://google.com",
  "redirect_count": 2,
  "final_url": "https://www.google.com/",
  "redirect_chain": [
    {
      "url": "http://google.com",
      "status": 301,
      "location": "http://www.google.com/"
    },
    {
      "url": "http://www.google.com/",
      "status": 301,
      "location": "https://www.google.com/"
    }
  ]
}
```

### Testing

```bash
# No redirects
curl -X POST http://localhost:8080/check \
  -H "Content-Type: application/json" \
  -d '{"url":"https://github.com"}'

# Single redirect
curl -X POST http://localhost:8080/check \
  -H "Content-Type: application/json" \
  -d '{"url":"http://github.com"}'

# Multiple redirects
curl -X POST http://localhost:8080/check \
  -H "Content-Type: application/json" \
  -d '{"url":"http://google.com"}'
```

### Files Modified
- `internal/checker/result.go` - Add RedirectHop struct and RedirectChain field
- `internal/checker/checker.go` - Track redirects in loop

### Commit Message
```
feat: add redirect chain tracking to /check endpoint

- Add RedirectHop struct to capture redirect details
- Track redirect chain in CheckURL method
- Include chain in CheckResult (only if redirects occur)
- Minimal performance impact (~1ms per redirect)
```

---

## Phase 7: Deep-Check Endpoint

### Goal
Create `/deep-check` endpoint that returns comprehensive URL analysis including all `/check` data plus HTML parsing, link extraction, technology detection, and metadata.

### Architecture Decision

**Approach: Reuse and Extend**
- Reuse existing checker for basic HTTP/timing/TLS analysis
- Add new components for deep analysis (HTMLParser, TechDetector)
- Deep check runs basic check first, then adds analysis

**Rationale:**
- DRY principle - no duplication of HTTP client logic
- Consistent data - same timings, TLS info, redirect chain
- Performance - early exit if basic check fails
- Maintainability - improvements to basic check benefit deep check

### Data Structures

**File: `internal/checker/deep_result.go` (NEW)**

```go
package checker

// DeepCheckResult extends CheckResult with deep analysis
type DeepCheckResult struct {
    // Embed basic check result
    CheckResult

    // Deep analysis fields
    OutgoingLinks []OutgoingLink `json:"outgoing_links,omitempty"`
    Technologies  []Technology   `json:"technologies,omitempty"`
    HTMLMetadata  *HTMLMetadata  `json:"html_metadata,omitempty"`
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

// HTMLParseResult holds parsing results (internal use)
type HTMLParseResult struct {
    Links    []OutgoingLink
    Metadata *HTMLMetadata
}
```

### HTML Parser Implementation

**File: `internal/checker/html_parser.go` (NEW)**

Uses `golang.org/x/net/html` for parsing (Go extended stdlib, minimal dependency).

**Key Features:**
- Single-pass tree traversal
- Extract `<a>` tags with href, text, rel
- Resolve relative URLs to absolute
- Extract `<title>`, `<meta>` tags
- Parse Open Graph and Twitter Card metadata
- Filter invalid links (javascript:, #anchors)

**Core Methods:**
- `Parse(body io.Reader, baseURL string) (*HTMLParseResult, error)` - Main entry point
- `traverse(n *html.Node, result *HTMLParseResult)` - Recursive tree walk
- `extractLink(n *html.Node, result *HTMLParseResult)` - Extract <a> tags
- `extractMeta(n *html.Node, result *HTMLParseResult)` - Extract <meta> tags
- `resolveURL(href string) string` - Resolve relative URLs

**Safety Limits:**
- Max links: 10,000 (prevent slice exhaustion)
- Body size: 5MB limit (handled by checker)

### Technology Detection

**File: `internal/checker/tech_detector.go` (NEW)**

Pattern-based detection inspired by Wappalyzer.

**Detection Methods:**
1. HTTP headers (Server, X-Powered-By, CF-Ray, etc.)
2. HTML patterns (framework-specific tags, classes)
3. Version extraction via regex

**Built-in Patterns:**
- **Web Servers**: nginx, Apache, Cloudflare
- **Frameworks**: Next.js, React, Vue.js
- **CMS**: WordPress, Drupal
- **Hosting**: Vercel, Netlify
- **CDN**: Cloudflare, Fastly

**Core Structure:**
```go
type TechPattern struct {
    Name          string
    Category      string
    HeaderMatches map[string]*regexp.Regexp
    BodyMatches   []*regexp.Regexp
    VersionRegex  *regexp.Regexp
}
```

**Extensibility**: Easy to add new patterns by extending the patterns slice in `NewTechDetector()`.

### Deep Check Flow

**File: `internal/checker/checker.go` (MODIFIED)**

Add method:
```go
func (c *Checker) DeepCheckURL(ctx context.Context, rawURL string, opts CheckOptions) *DeepCheckResult
```

**Steps:**
1. Run basic check first (reuse `CheckURL` method)
2. If failed or non-200, return early with basic result only
3. Fetch HTML body with GET request (use FinalURL to avoid re-redirecting)
4. Read body with 5MB size limit
5. Parse HTML (HTMLParser)
6. Detect technologies (TechDetector)
7. Build DeepCheckResult with all data
8. Update total_ms to include deep analysis time

**Safety:**
- Body size limit: 5MB
- Link count limit: 10,000
- Graceful failures: If HTML parsing fails, return basic result

### Service Layer

**File: `internal/service/service.go` (MODIFIED)**

Add method:
```go
func (s *Service) DeepCheckURL(ctx context.Context, url string, opts *checker.CheckOptions) *checker.DeepCheckResult {
    finalOpts := s.mergeOptions(opts)
    ctx, cancel := context.WithTimeout(ctx, finalOpts.Timeout)
    defer cancel()

    s.logger.Info("Deep checking URL", "url", url)
    result := s.checker.DeepCheckURL(ctx, url, finalOpts)

    s.logger.Info("Deep check completed",
        "url", url,
        "ok", result.OK,
        "links_found", len(result.OutgoingLinks),
        "technologies", len(result.Technologies),
        "total_ms", result.TotalMs,
    )

    return result
}
```

### HTTP Handler

**File: `internal/httpapi/handlers.go` (MODIFIED)**

Add request struct:
```go
type deepCheckRequest struct {
    URL             string `json:"url"`
    FollowRedirects *bool  `json:"follow_redirects,omitempty"`
    MaxRedirects    *int   `json:"max_redirects,omitempty"`
    TimeoutMs       *int   `json:"timeout_ms,omitempty"`
    // Note: Method is always GET for deep check
}
```

Add handler function:
```go
func deepCheckHandler(svc *service.Service) http.HandlerFunc {
    return func(w http.ResponseWriter, r *http.Request) {
        // Validate POST method
        // Parse JSON request
        // Validate URL
        // Build options (force GET method)
        // Call service
        // Return DeepCheckResult as JSON
    }
}
```

### Route Registration

**File: `internal/httpapi/server.go` (MODIFIED)**

In `NewServer`, add route:
```go
mux.HandleFunc("/deep-check", deepCheckHandler(svc))
```

### Dependencies

**File: `go.mod` (MODIFIED)**

Add:
```
golang.org/x/net v0.30.0
```

Run: `go get golang.org/x/net/html && go mod tidy`

### Example Response

```json
{
  "url": "https://github.com",
  "ok": true,
  "status": 200,
  "final_url": "https://github.com/",
  "redirect_count": 0,
  "total_ms": 856,
  "ttfb_ms": 234,
  "speed_class": "ok",
  "protocol": "https",
  "tls_version": "TLS1.3",
  "cert_valid": true,
  "content_type": "text/html; charset=utf-8",
  "outgoing_links": [
    {
      "href": "/features",
      "absolute_url": "https://github.com/features",
      "text": "Features"
    },
    {
      "href": "https://docs.github.com",
      "absolute_url": "https://docs.github.com",
      "text": "Documentation",
      "rel": "external"
    }
  ],
  "technologies": [
    {
      "name": "nginx",
      "category": "Web Server",
      "version": "1.21.0",
      "confidence": "high",
      "evidence": ["Header: Server"]
    },
    {
      "name": "React",
      "category": "JavaScript Library",
      "confidence": "medium",
      "evidence": ["HTML content"]
    }
  ],
  "html_metadata": {
    "title": "GitHub: Let's build from here",
    "description": "GitHub is where over 100 million developers...",
    "canonical": "https://github.com/",
    "open_graph": {
      "og:title": "GitHub",
      "og:type": "website"
    }
  }
}
```

### Testing

```bash
# Successful deep check
curl -X POST http://localhost:8080/deep-check \
  -H "Content-Type: application/json" \
  -d '{"url":"https://github.com"}'

# Failed basic check (should return early)
curl -X POST http://localhost:8080/deep-check \
  -H "Content-Type: application/json" \
  -d '{"url":"https://invalid-xyz-abc.com"}'

# WordPress detection
curl -X POST http://localhost:8080/deep-check \
  -H "Content-Type: application/json" \
  -d '{"url":"https://wordpress.com"}'

# Many links (HN)
curl -X POST http://localhost:8080/deep-check \
  -H "Content-Type: application/json" \
  -d '{"url":"https://news.ycombinator.com"}'
```

### Files Modified/Created

**New Files:**
- `internal/checker/deep_result.go` - DeepCheckResult and related structs
- `internal/checker/html_parser.go` - HTML parsing logic
- `internal/checker/tech_detector.go` - Technology detection

**Modified Files:**
- `internal/checker/checker.go` - Add DeepCheckURL method
- `internal/service/service.go` - Add DeepCheckURL method
- `internal/httpapi/handlers.go` - Add deepCheckHandler
- `internal/httpapi/server.go` - Register /deep-check route
- `go.mod` - Add golang.org/x/net dependency

### Commit Message
```
feat: add /deep-check endpoint with HTML analysis

- Create DeepCheckResult extending CheckResult
- Implement HTML parser using golang.org/x/net/html
- Extract outgoing links with absolute URL resolution
- Add technology detection (Wappalyzer-style patterns)
- Extract HTML metadata (title, description, Open Graph, Twitter Card)
- Add DeepCheckURL method reusing basic checker
- Create /deep-check HTTP endpoint
- Include safety limits (5MB body, 10K links max)
```

---

## Performance Characteristics

### /check Endpoint
- **Current**: 40-100ms
- **After Phase 5.5**: 41-101ms (~1ms overhead)
- **Method**: HEAD (with GET fallback)
- **Use Case**: Fast link validation, monitoring, uptime checks

### /deep-check Endpoint
- **Expected**: 200ms - 2000ms
- **Method**: Always GET (fetches full HTML)
- **Breakdown**:
  - Basic check: 100-500ms
  - HTML fetch: 100-500ms
  - HTML parse: 10-100ms
  - Link extraction: 5-50ms
  - Tech detection: 5-20ms
  - JSON serialize: 10-50ms
- **Use Case**: Detailed analysis, SEO audits, tech stack discovery

### Safety Measures
- Body size limit: 5MB (prevents memory exhaustion)
- Link count limit: 10,000 (prevents slice exhaustion)
- Timeout configurable via request
- Graceful failures (return basic result if deep analysis fails)

---

## Implementation Order

### Phase 5.5 (Quick Win)
1. Modify `internal/checker/result.go` - Add RedirectHop struct and field
2. Modify `internal/checker/checker.go` - Track chain in redirect loop
3. Test manually with curl
4. Commit

### Phase 7 (Comprehensive)
1. Add dependency: `go get golang.org/x/net/html && go mod tidy`
2. Create `internal/checker/deep_result.go`
3. Create `internal/checker/html_parser.go`
4. Create `internal/checker/tech_detector.go`
5. Modify `internal/checker/checker.go` - Add DeepCheckURL method
6. Modify `internal/service/service.go` - Add DeepCheckURL method
7. Modify `internal/httpapi/handlers.go` - Add deepCheckHandler
8. Modify `internal/httpapi/server.go` - Register route
9. Test manually with various URLs
10. Commit

---

## Key Design Decisions

1. **Separate Endpoints**: Keep /check fast, /deep-check detailed (user requirement)
2. **Reuse Logic**: Deep check uses basic check, no duplication
3. **Minimal Dependencies**: Only golang.org/x/net (Go extended stdlib)
4. **Safety First**: Size limits, count limits, graceful failures
5. **Extensible Patterns**: Easy to add new technology detection patterns
6. **Single Pass**: HTML parser walks tree once, extracting everything

---

## Future Enhancements (Not in This Phase)

- Caching layer for deep check results
- Batch /deep-check endpoint
- Custom technology patterns via config file
- Screenshot capture
- Accessibility analysis
- Performance scoring (like Lighthouse)
