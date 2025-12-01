# Phased Implementation Plan: Go Link Checker API

## Overview

This plan breaks down the link checker service into **6 progressive phases**. Each phase produces a **runnable service** that builds on the previous one, allowing you to learn Go concepts incrementally while building production-ready code.

**Approach:** Start with a minimal HTTP server, then gradually add configuration, core checking logic, advanced features (redirects, TLS), and finally observability (metrics). Tests will be added in a dedicated phase after core functionality is complete.

**Commitment per phase:** Implement → Test manually → Commit → Push to repository

---

## Phase 1: Minimal HTTP Server with Health Check

**Goal:** Get a basic HTTP server running. Learn Go project structure and HTTP fundamentals.

### Deliverables
- Go module initialization (`go.mod`)
- HTTP server on port 8080
- `/health` endpoint returning JSON status
- Graceful shutdown on SIGINT/SIGTERM

### Files to Create
```
cmd/linkchecker-api/main.go           # Application entry point
internal/httpapi/server.go            # HTTP server setup and handlers
```

### What's Runnable
```bash
go run cmd/linkchecker-api/main.go
curl http://localhost:8080/health
# Returns: {"status":"ok","service":"linkchecker-api"}
```

### Key Go Concepts
- Go modules and package organization (`cmd/` vs `internal/`)
- HTTP server basics (`http.ListenAndServe`, `http.HandlerFunc`)
- JSON encoding (`json.NewEncoder`)
- Context and graceful shutdown
- Goroutines and channels for signal handling

### Commit Message
```
feat: add minimal HTTP server with health endpoint

- Initialize Go module
- Create basic HTTP server on port 8080
- Add /health endpoint returning JSON status
- Implement graceful shutdown with signal handling
```

---

## Phase 2: Configuration Management and Logging

**Goal:** Add environment-based configuration and request logging. Learn config patterns and middleware.

### Deliverables
- Configuration loading from environment variables
- Standard library logger with structured output
- Configurable port, timeouts, and checker options
- Request logging middleware

### Files to Create/Modify
```
internal/config/config.go             # Configuration struct and loading
internal/logging/logger.go            # Logging wrapper
internal/httpapi/middleware.go        # Request logging middleware
cmd/linkchecker-api/main.go          # Modified: load config
internal/httpapi/server.go           # Modified: use config
```

### Configuration Fields
- `PORT` - Server port (default: 8080)
- `REQUEST_TIMEOUT` - Per-request timeout (default: 3000ms)
- `MAX_REDIRECTS` - Max redirects to follow (default: 5)
- `DEFAULT_USER_AGENT` - User-Agent header (default: "blink-checker/1.0")
- `DEFAULT_METHOD` - HTTP method (default: "HEAD")

### What's Runnable
```bash
PORT=9000 go run cmd/linkchecker-api/main.go
# Logs: [INFO] Starting server on :9000

curl http://localhost:9000/health
# Logs: [INFO] method=GET path=/health status=200 duration_ms=0
```

### Key Go Concepts
- Environment variables (`os.Getenv`, `os.LookupEnv`)
- Type conversion (`strconv.Atoi`)
- HTTP middleware pattern (wrapping handlers)
- `defer` statement for timing
- `time.Duration` and `time.Since`

### Commit Message
```
feat: add configuration management and structured logging

- Add config package to load settings from environment
- Create logging wrapper with structured output
- Add request logging middleware
- Make server port and timeouts configurable
```

---

## Phase 3: Core HTTP Client and Basic URL Check

**Goal:** Build HTTP client infrastructure and implement basic URL checking. Learn HTTP client, tracing, and error handling.

### Deliverables
- Shared HTTP client with connection pooling
- HTTP tracing for basic performance metrics
- URL validation and error classification
- `/check` endpoint (POST, single URL)

### Files to Create/Modify
```
internal/httpclient/client.go         # HTTP client with tracing
internal/httpclient/transport.go      # Configured HTTP transport
internal/checker/checker.go           # Core check logic
internal/checker/result.go            # CheckResult struct
internal/checker/errors.go            # Error classification
internal/httpapi/handlers.go          # /check handler
internal/httpapi/server.go           # Modified: add /check route
cmd/linkchecker-api/main.go          # Modified: initialize HTTP client
```

### CheckResult (Basic Version)
```json
{
  "url": "https://www.google.com",
  "ok": true,
  "status": 200,
  "error_type": "none",
  "final_url": "https://www.google.com",
  "redirect_count": 0,
  "total_ms": 245,
  "protocol": "https",
  "mwb_url_checker": false
}
```

### Error Types
- `none` - No error
- `invalid_url` - URL parse/validation error
- `timeout` - Request timeout
- `dns_error` - DNS lookup failure
- `network_error` - Connection failure
- `http_error` - HTTP-level error

### What's Runnable
```bash
go run cmd/linkchecker-api/main.go

curl -X POST http://localhost:8080/check \
  -H "Content-Type: application/json" \
  -d '{"url":"https://www.google.com"}'
# Returns CheckResult with status, timing, protocol
```

### Key Go Concepts
- `net/http.Client` and `http.Transport` configuration
- Connection pooling (`MaxIdleConns`, `MaxIdleConnsPerHost`)
- Context with timeout (`context.WithTimeout`)
- `httptrace` package for performance metrics
- URL parsing and validation (`url.Parse`)
- Error wrapping (`fmt.Errorf` with `%w`)
- Type assertions for error classification
- HTTP request building (`http.NewRequestWithContext`)

### Commit Message
```
feat: implement core HTTP client and basic URL checking

- Add HTTP client with connection pooling and tracing
- Implement URL validation and normalization
- Create core checker with error classification
- Add /check endpoint for single URL validation
- Return basic check results with status and timing
```

---

## Phase 4: Service Layer, Redirect Handling, and Enhanced Timings

**Goal:** Add service layer for clean architecture, implement redirect following, and capture detailed performance metrics.

### Deliverables
- Service layer separating business logic from HTTP
- Redirect following with chain tracking
- Detailed timings (DNS, connect, TLS, TTFB)
- HEAD request with GET fallback on 405
- Speed classification (fast/ok/slow)
- Request-level options support

### Files to Create/Modify
```
internal/service/service.go           # Service interface & implementation
internal/service/options.go           # Request options struct
internal/checker/checker.go          # Modified: redirects & timings
internal/checker/result.go           # Modified: add performance fields
internal/checker/timings.go          # Timing collection logic
internal/httpclient/client.go        # Modified: HEAD/GET, redirects
internal/httpapi/handlers.go         # Modified: use service layer
cmd/linkchecker-api/main.go          # Modified: initialize service
```

### Enhanced CheckResult
```json
{
  "url": "http://google.com",
  "ok": true,
  "status": 200,
  "error_type": "none",
  "final_url": "https://www.google.com/",
  "redirect_count": 1,
  "total_ms": 342,
  "dns_ms": 12,
  "connect_ms": 45,
  "tls_ms": 89,
  "ttfb_ms": 156,
  "speed_class": "ok",
  "protocol": "https",
  "http_version": "2",
  "mwb_url_checker": false
}
```

### Speed Classification
- `fast` - total_ms < 300
- `ok` - 300 ≤ total_ms < 1000
- `slow` - total_ms ≥ 1000

### Request Options (Optional in API)
```json
{
  "url": "https://example.com",
  "follow_redirects": false,
  "max_redirects": 3,
  "method": "GET",
  "timeout_ms": 5000
}
```

### What's Runnable
```bash
go run cmd/linkchecker-api/main.go

curl -X POST http://localhost:8080/check \
  -H "Content-Type: application/json" \
  -d '{"url":"http://google.com"}'
# Returns full timing breakdown, redirect chain, speed class
```

### Key Go Concepts
- Dependency injection (passing service to handlers)
- Method receivers (`func (s *Service) CheckURL(...)`)
- Pointer vs value receivers
- Custom redirect policy (`http.Client.CheckRedirect`)
- HTTP response header parsing
- Precise timing with `httptrace` callbacks
- Slice management (collecting redirect chain)
- HTTP version detection (`resp.Proto`)

### Commit Message
```
feat: add service layer with redirect handling and detailed timings

- Create service layer for business logic separation
- Implement redirect following with configurable max
- Add HEAD request with automatic GET fallback on 405
- Capture detailed performance timings (DNS, connect, TLS, TTFB)
- Add speed classification based on total response time
- Support request-level options
```

---

## Phase 5: TLS/Certificate Information and Response Metadata

**Goal:** Add TLS certificate analysis and response metadata. Learn Go's crypto/tls and certificate handling.

### Deliverables
- TLS version detection
- Certificate validation and expiry checking
- Certificate issuer extraction
- Days until expiry calculation
- Expiring soon flag (< 30 days)
- Response metadata (Content-Type, Content-Length)
- Enhanced TLS error handling

### Files to Create/Modify
```
internal/checker/tls.go              # TLS/certificate analysis
internal/checker/result.go           # Modified: add TLS fields
internal/checker/errors.go           # Modified: add tls_error type
internal/httpclient/client.go        # Modified: capture TLS state
```

### Complete CheckResult
```json
{
  "url": "https://github.com",
  "ok": true,
  "status": 200,
  "error_type": "none",
  "final_url": "https://github.com/",
  "redirect_count": 0,
  "total_ms": 289,
  "dns_ms": 8,
  "connect_ms": 52,
  "tls_ms": 94,
  "ttfb_ms": 123,
  "speed_class": "fast",
  "protocol": "https",
  "http_version": "2",
  "tls_version": "TLS1.3",
  "cert_valid": true,
  "cert_expires_at": "2025-03-15T12:00:00Z",
  "cert_days_remaining": 108,
  "cert_expiring_soon": false,
  "cert_issuer": "DigiCert Inc",
  "content_type": "text/html; charset=utf-8",
  "size_bytes": 123456,
  "mwb_url_checker": false
}
```

### What's Runnable
```bash
go run cmd/linkchecker-api/main.go

curl -X POST http://localhost:8080/check \
  -H "Content-Type: application/json" \
  -d '{"url":"https://github.com"}'
# Returns complete technical analysis including TLS/cert info
```

### Key Go Concepts
- `crypto/tls` package (TLS connection state)
- `crypto/x509` certificates (parsing and validation)
- Certificate chain access (`resp.TLS.PeerCertificates`)
- Time operations (`time.Until` for expiry calculation)
- Nil checking (safe access to optional TLS state)
- String manipulation (extracting issuer CN)
- HTTP header parsing (`resp.Header.Get()`)
- Integer parsing (`strconv.ParseInt` for Content-Length)

### Commit Message
```
feat: add TLS certificate analysis and response metadata

- Extract TLS version from connection state
- Analyze certificate validity and expiration
- Calculate days remaining until certificate expiry
- Flag certificates expiring within 30 days
- Extract certificate issuer information
- Capture Content-Type and Content-Length headers
- Add tls_error classification for handshake failures
```

---

## Phase 6: Metrics, Enhanced Observability, and Production Readiness

**Goal:** Add Prometheus metrics, correlation IDs, and final production polish. Learn observability patterns.

### Deliverables
- Prometheus metrics endpoint (`/metrics`)
- Counters (total, ok, failed, errors by type)
- Histogram for check duration
- Correlation IDs for request tracing
- Enhanced logging with structured fields
- Server timeout configuration

### Files to Create/Modify
```
go.mod                               # Modified: add prometheus dependency
internal/metrics/metrics.go          # Metrics definitions
internal/metrics/collector.go        # Metrics collection
internal/logging/logger.go           # Modified: correlation IDs
internal/service/service.go          # Modified: emit metrics
internal/httpapi/server.go           # Modified: add /metrics endpoint
internal/httpapi/middleware.go       # Modified: add correlation ID
cmd/linkchecker-api/main.go          # Modified: initialize metrics
```

### Metrics Exposed
```
# Counters
linkchecker_checks_total
linkchecker_checks_ok_total
linkchecker_checks_failed_total
linkchecker_check_errors_total{type="timeout"}
linkchecker_check_errors_total{type="dns_error"}
linkchecker_check_errors_total{type="tls_error"}
# ... other error types

# Histograms
linkchecker_check_duration_ms (buckets: 100, 300, 1000, 3000, +Inf)
linkchecker_http_request_duration_ms

# Optional
linkchecker_cert_expiring_soon_total
linkchecker_https_checks_total
```

### What's Runnable
```bash
go run cmd/linkchecker-api/main.go

# Use the service
curl -X POST http://localhost:8080/check \
  -H "Content-Type: application/json" \
  -d '{"url":"https://example.com"}'
# Logs: [INFO] request_id=abc123 method=POST path=/check
# Logs: [INFO] request_id=abc123 url=https://example.com status=200 duration_ms=234

# View metrics
curl http://localhost:8080/metrics
# Returns Prometheus-formatted metrics
```

### Key Go Concepts
- External dependencies (first non-stdlib import)
- `go mod tidy` for dependency management
- Prometheus client library (`prometheus/client_golang`)
- Metric types (Counter, Histogram, Gauge)
- Metric labels for classification
- Correlation ID generation
- Context values (passing data through call stack)
- `defer` for metric timing

### Commit Message
```
feat: add Prometheus metrics and enhanced observability

- Add Prometheus metrics endpoint at /metrics
- Implement counters for total/ok/failed checks
- Add error counters by error type
- Create histogram for check duration distribution
- Add correlation IDs to all requests for tracing
- Enhance logging with structured fields
- Configure server read/write timeouts
```

---

## Phase Summary

| Phase | Focus | Runnable Feature | LOC |
|-------|-------|------------------|-----|
| 1 | HTTP server basics | Health endpoint | ~100 |
| 2 | Config & logging | Configured server with logs | ~200 |
| 3 | Core checking | Basic URL check with errors | ~500 |
| 4 | Service layer | Redirects, timings, speed class | ~700 |
| 5 | TLS analysis | Complete technical analysis | ~850 |
| 6 | Observability | Production-ready with metrics | ~1000 |

---

## Critical Files (Architecture Backbone)

These 5 files represent the layered architecture and will be built progressively:

1. **cmd/linkchecker-api/main.go**
   - Application entry point
   - Orchestrates all components (config, logger, metrics, HTTP client, service, server)
   - Manages application lifecycle

2. **internal/checker/checker.go**
   - Core domain logic
   - Implements URL checking algorithm
   - Error classification and timing collection
   - Pure business logic (no HTTP/JSON knowledge)

3. **internal/httpclient/client.go**
   - HTTP infrastructure layer
   - Connection pooling and reuse
   - HTTP tracing integration
   - Timeout and redirect handling

4. **internal/service/service.go**
   - Business logic / use case layer
   - Applies defaults and options
   - Manages request lifecycle
   - Emits metrics and logs
   - Bridges HTTP transport and domain logic

5. **internal/httpapi/handlers.go**
   - HTTP transport layer
   - Request parsing and validation
   - Response serialization (JSON)
   - Maps HTTP errors to status codes

---

## After Phase 6: Production Service Complete

The service will be **production-ready** with:
- ✅ Clean layered architecture
- ✅ Comprehensive URL checking (status, redirects, performance, TLS)
- ✅ Error handling and classification
- ✅ Configuration via environment
- ✅ Structured logging with correlation IDs
- ✅ Prometheus metrics
- ✅ Graceful shutdown
- ✅ Optimized HTTP client (connection pooling, HTTP/2)

### Future Enhancements (Not in These Phases)
- Testing phase (unit tests, integration tests, table-driven tests)
- Batch endpoint (`/check-batch` for multiple URLs)
- Caching layer (Redis-based)
- Rate limiting
- Docker deployment
- Kubernetes manifests

---

## Workflow Per Phase

1. **Implement** - Create/modify files as specified
2. **Test manually** - Use `curl` commands to verify functionality
3. **Verify logs** - Check that logging works as expected
4. **Commit** - Use the suggested commit message format
5. **Push** - Push to remote repository
6. **Learn** - Review the Go concepts introduced

Each phase builds on the previous, maintaining a **runnable state** throughout development.
