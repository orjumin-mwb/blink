# Blink

Fast Go-based link checker API with URL validation, redirect following, TLS verification, and malicious URL detection.

## Quick Start

```bash
# Run
go run cmd/linkchecker-api/main.go

# Build
go build -o blink cmd/linkchecker-api/main.go

# Configure
PORT=9000 REQUEST_TIMEOUT=5000 go run cmd/linkchecker-api/main.go
```

## API

### `POST /check`
Check URL health with detailed metrics.

```bash
curl -X POST http://localhost:8080/check \
  -H "Content-Type: application/json" \
  -d '{"url":"https://example.com"}'
```

**Request:**
```json
{
  "url": "string",
  "follow_redirects": bool,
  "max_redirects": int,
  "method": "HEAD|GET",
  "timeout_ms": int
}
```

**Response:**
- Status code & OK flag
- Response timings (DNS, TCP, TLS, first byte, total)
- Redirect chain
- TLS certificate details
- Error classification
- Malicious URL detection

### `GET /health`
Service health check.

## Features

- ✅ URL validation & health checking
- ✅ Redirect chain tracking
- ✅ TLS certificate verification (30-day expiry warning)
- ✅ Detailed timing metrics
- ✅ Malicious URL detection (ScamGuard integration)
- ✅ Screenshot capture with AI analysis
- ✅ Error classification (DNS, Connection, Timeout, TLS, HTTP)
- ✅ Graceful shutdown

## Configuration

Environment variables:
- `PORT` - Server port (default: 8080)
- `REQUEST_TIMEOUT` - Request timeout in ms (default: 10000)
- `MAX_REDIRECTS` - Max redirect follows (default: 10)
- `DEFAULT_USER_AGENT` - User agent string
- `DEFAULT_METHOD` - HTTP method (HEAD/GET)

## Architecture

```
cmd/linkchecker-api/    # Entry point
internal/
  ├── checker/          # Core checking logic
  ├── httpapi/          # HTTP handlers & server
  ├── service/          # Service orchestration
  ├── scamguardapi/     # Malicious URL detection
  ├── screenshot/       # Screenshot capture
  └── config/           # Configuration
```
