# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## IMPORTANT: Documentation Policy

**⚠️ DO NOT CREATE MARKDOWN DOCUMENTATION FILES UNLESS EXPLICITLY REQUESTED**

- Do NOT create .md files in docs/ or elsewhere after completing implementations
- Do NOT create summary documents, status documents, or final reports
- Focus on code implementation only
- Only create documentation when the user explicitly asks for it

## Project Overview

Blink is a Go-based link checker API service that validates URLs, follows redirects, checks TLS certificates, and provides detailed timing information. The service exposes an HTTP API for checking link health.

## IMPORTANT: Template Changes Require Server Restart

**⚠️ CRITICAL:** HTML templates in `internal/httpapi/templates/` are embedded into the Go binary using `//go:embed` directives. This means:

1. **Any changes to HTML template files will NOT take effect until the server is restarted**
2. The templates are compiled into the executable at build time
3. You must stop and restart the server after modifying templates

### How to restart after template changes:
```bash
# Kill the running server (Ctrl+C or kill the process)
# Then restart:
go run cmd/linkchecker-api/main.go
```

This applies to:
- `internal/httpapi/templates/ui_form.html`
- `internal/httpapi/templates/ui_result.html`
- Any other embedded templates

## Build and Development Commands

### Run the service
```bash
go run cmd/linkchecker-api/main.go
```

### Build the binary
```bash
go build -o blink cmd/linkchecker-api/main.go
```

### Run with custom configuration
```bash
PORT=9000 REQUEST_TIMEOUT=5000 go run cmd/linkchecker-api/main.go
```

### Test the API
```bash
# Health check
curl http://localhost:8080/health

# Check a URL
curl -X POST http://localhost:8080/check \
  -H "Content-Type: application/json" \
  -d '{"url":"https://example.com"}'

# Check with options
curl -X POST http://localhost:8080/check \
  -H "Content-Type: application/json" \
  -d '{"url":"https://example.com","follow_redirects":true,"max_redirects":10,"timeout_ms":5000}'
```

## Architecture

### Entry Point
- `cmd/linkchecker-api/main.go` - Initializes all components, starts HTTP server with graceful shutdown

### Core Components

**Service Layer** (`internal/service/`)
- Orchestrates checker operations and manages default options
- Bridges HTTP handlers with checker logic

**Checker** (`internal/checker/`)
- `checker.go` - Main URL validation and checking logic
- `result.go` - Result types and structures
- `errors.go` - Error types and classification
- `tls.go` - TLS certificate validation
- `timings.go` - Detailed timing measurements
- `options.go` - Check configuration options

**HTTP Layer** (`internal/httpapi/`)
- `server.go` - HTTP server setup and routing
- `handlers.go` - Request handlers for `/health` and `/check` endpoints
- `middleware.go` - Request logging middleware

**HTTP Client** (`internal/httpclient/`)
- `client.go` - Custom HTTP client wrapper with redirect handling
- `transport.go` - Custom transport for timing measurements

**Configuration** (`internal/config/`)
- Loads environment variables with defaults
- Available variables: `PORT`, `REQUEST_TIMEOUT`, `MAX_REDIRECTS`, `DEFAULT_USER_AGENT`, `DEFAULT_METHOD`

**Logging** (`internal/logging/`)
- Structured logging wrapper using standard library

## API Endpoints

### POST /check
Checks a URL and returns detailed results including:
- Status code and OK flag
- Response timings (DNS, TCP, TLS, first byte, total)
- Redirect chain with individual status codes
- TLS certificate details (if HTTPS)
- Error classification
- MWB malicious URL detection result

Request body:
```json
{
  "url": "string",
  "follow_redirects": bool,
  "max_redirects": int,
  "method": "HEAD|GET",
  "timeout_ms": int
}
```

### GET /health
Returns service health status.

## Key Implementation Details

- The checker performs comprehensive URL validation including scheme and host verification
- Supports both HEAD and GET methods (HEAD by default for efficiency)
- Tracks detailed timing for each phase: DNS lookup, TCP connection, TLS handshake, first byte
- Follows redirects with configurable limits and tracks the full redirect chain
- Validates TLS certificates including expiration warnings (30 days)
- Classifies errors into types: Invalid URL, DNS failure, Connection failure, Timeout, TLS error, HTTP error
- Uses context for timeout management throughout the request lifecycle
- Implements graceful shutdown with signal handling