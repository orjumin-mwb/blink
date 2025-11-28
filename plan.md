Here’s a clean, self-contained plan for the Go service, focused on **speed, scalability, and clean architecture**.

---

## 1. Scope & Role of the Go Service

**Service name (working):** `linkchecker-api`

**Primary responsibility:**

* Provide a **fast, technical URL check**.
* One endpoint: `/check`
* Input: **one URL**
* Output: detailed JSON with:

  * HTTP reachability
  * status & redirects
  * performance timings
  * protocol & HTTP version
  * TLS / certificate info
  * basic response headers

**Out of scope for this Go service:**

* Malicious/ phishing detection
* AI analysis / scoring
* HTML parsing, tech detection, screenshots, images
* WHOIS / DNS SPF/DMARC / domain age

Those are handled by **other services**. This service remains a **pure, stateless “fast technical checker”**.

---

## 2. Functional Requirements

### Endpoint

* `POST /check` **or** `GET /check?url=...` (choose one, but the logic is the same)
* Accepts **one URL** per request
* Validates URL, executes check, returns JSON

### What a check must do

For a given URL:

1. Validate URL format (scheme `http/https`, host present).
2. Perform a single HTTP request:

   * Default method: `HEAD`
   * Fallback to `GET` if `HEAD` is not allowed / fails in specific ways.
3. Follow redirects up to configured `max_redirects`.
4. Measure performance timings (via HTTP tracing).
5. Collect metadata:

   * HTTP status
   * Redirect chain length
   * Protocol / HTTP version
   * TLS info (if HTTPS)
   * `Content-Type`, `Content-Length`

### What the response must contain (conceptually)

**Core fields:**

* `url` — original URL
* `ok` — boolean (true if we consider the link “working”, e.g. HTTP 2xx/3xx)
* `status` — HTTP status code (0 if no HTTP response)
* `error_type` — one of:
  `none | invalid_url | dns_error | timeout | tls_error | http_error | network_error`
* `error_message` — optional human-readable error (for UI / logs)

**Redirects:**

* `final_url` — URL after redirects (or same as original)
* `redirect_count` — number of redirects encountered

**Performance:**

* `total_ms` — total elapsed time for the request
* `dns_ms` — DNS lookup time (if available)
* `connect_ms` — TCP connect time
* `tls_ms` — TLS handshake time
* `ttfb_ms` — time to first byte
* `speed_class` — `"fast" | "ok" | "slow"` based on thresholds (e.g. <300 / 300–1000 / >1000 ms)

**Protocol / HTTP:**

* `protocol` — `"http"` or `"https"`
* `http_version` — e.g. `"1.1"` or `"2"`

**TLS / certificate (if HTTPS):**

* `tls_version` — e.g. `"TLS1.2"`, `"TLS1.3"`
* `cert_valid` — boolean (currently valid or not)
* `cert_expires_at` — ISO8601 string
* `cert_days_remaining` — integer days until expiry
* `cert_expiring_soon` — boolean (`true` if below some threshold, e.g. <30 days)
* `cert_issuer` — certificate issuer CN (string)

**Response metadata:**

* `content_type` — from `Content-Type` header
* `size_bytes` — from `Content-Length` if present

All of this is **purely technical** data, no HTML content.

---

## 3. Non-Functional Requirements

* **High throughput**: able to handle many concurrent checks.
* **Low latency**: minimal overhead beyond network delay.
* **Stateless**: no persistent state per request → easy horizontal scaling.
* **Clean architecture**: SRP, reusable core, testable components.
* **Config-driven**: timeouts, UA, redirect behavior from config.
* **Observable**: logs + metrics for latency and error types.

---

## 4. High-Level Architecture (Layers)

Use a layered, clean architecture:

1. **Transport Layer (HTTP API)**

   * Exposes `/check` via HTTP.
   * Parses incoming request (URL, options).
   * Validates basic input (non-empty, etc.).
   * Calls the service layer.
   * Serializes responses to JSON, maps errors to HTTP codes.

2. **Service / Application Layer**

   * Main entrypoint for “use case”: `CheckURL(ctx, url, options)`.
   * Responsibilities:

     * Apply default options (timeouts, redirects, methods, user-agent).
     * Wrap context with per-request timeout.
     * Call the **checker core**.
     * Log high-level info (URL, result summary).
     * Increment metrics (latency, error counts).
   * Knows nothing about HTTP transport details.

3. **Domain / Core (Checker Engine)**

   * Pure logic of “how to check a URL”:

     * URL normalization,
     * calling the HTTP client abstraction,
     * collecting timings,
     * classifying errors,
     * building `CheckResult`.
   * Independent from:

     * JSON / HTTP server,
     * logging frameworks,
     * metrics systems.

4. **Infrastructure Layer**

   * Concrete implementations for:

     * HTTP client (wrapper around `net/http` with a **shared Transport**),
     * config loader,
     * logging,
     * metrics.
   * Core uses interfaces; infra provides the actual implementations.

This separation lets you:

* reuse the core checker for CLI tools, batch jobs, cron, etc.
* later add other transports (gRPC, message queues) if needed.

---

## 5. Package / Module Structure

Suggested layout:

* `cmd/linkchecker-api/`

  * `main.go`:

    * Load config (env/flags).
    * Initialize logger, metrics, HTTP client, service.
    * Start HTTP server.

* `internal/config/`

  * Reads configuration:

    * server port,
    * per-request timeout,
    * max redirects,
    * default user-agent,
    * HTTP client tuning (idle conns, TLS timeouts, etc.).

* `internal/httpapi/`

  * HTTP handlers:

    * `/check` endpoint.
  * Responsibilities:

    * Map HTTP requests → `CheckURL` call.
    * Handle validation errors (400) vs internal (500).
    * Marshal `CheckResult` to JSON.

* `internal/service/`

  * `URLCheckService` interface & implementation.
  * `CheckURL(ctx, url, options) → CheckResult`.
  * Applies defaults & timeouts.
  * Calls domain/checker.
  * Writes high-level logs.
  * Emits metrics.

* `internal/checker/`

  * Core engine:

    * Interface for HTTP client abstraction.
    * Main function: `CheckURL(ctx, url, options) → CheckResult`.
  * Responsibilities:

    * Normalize URL (scheme/host).
    * Build request.
    * Use HTTP client to perform request.
    * Use http tracing info for timings.
    * Interpret response (status, headers, TLS).
    * Classify errors into `error_type`.
    * Build final `CheckResult`.

* `internal/httpclient/`

  * Implementation of HTTP client:

    * Shared `http.Transport` tuned for performance:

      * `MaxIdleConns`, `MaxIdleConnsPerHost`, `IdleConnTimeout`,
      * `TLSHandshakeTimeout`,
      * HTTP/2 enabled.
    * Provides a method like:

      * `Do(ctx, method, url, options) → response struct + timing info + TLS info + error`.
    * Sets per-request timeout via context, not via client’s global Timeout.

* `internal/logging/`

  * Wrapper/adapter for chosen logging library.
  * Unified log formatting (structured logs).

* `internal/metrics/`

  * Integration with Prometheus / StatsD / etc.
  * Exposes metrics collection functions:

    * increment counters,
    * observe histograms, etc.

This gives you SRP and reusability across the codebase.

---

## 6. Config & Options

### Configurable via environment / config file

* Server:

  * HTTP port
  * read/write timeouts
* Checker:

  * default per-request timeout (e.g. 3000 ms)
  * default max redirects (e.g. 5)
  * default HTTP method (`HEAD`)
  * default user-agent string
* HTTP Transport:

  * max idle connections
  * max idle per host
  * max total connections per host
  * TLS handshake timeout
  * enable HTTP/2

These are loaded into a `Config` struct and passed down to the relevant layers.

### Request-level options

Even if you don’t expose all of these in the first UI, design the service to **accept options**:

* `timeout_ms`
* `follow_redirects`
* `max_redirects`
* `method`
* `user_agent`

The service layer applies defaults; the core uses the final merged options.

---

## 7. Error Handling & Classification

Have a dedicated small module/function that maps Go errors to your domain `error_type`.

Examples:

* `invalid_url`: URL parse errors / missing scheme/host.
* `timeout`: `context.DeadlineExceeded` or `net.Error` with `Timeout() == true`.
* `dns_error`: `*net.DNSError`.
* `tls_error`: TLS handshake failures (can inspect error type or content).
* `network_error`: connection resets, refused connections, generic I/O errors.
* `http_error`: if needed, for non-2xx/3xx status codes (or just use `ok`+`status`).

This gives clean, stable categories for UI and metrics.

---

## 8. Performance Strategy

Key decisions for speed:

1. **Single shared HTTP Transport**

   * Avoid recreating `http.Client`/`Transport` per request.
   * Reuse TCP connections, leverage HTTP/2.
   * Tune idle connections and timeouts for high concurrency.

2. **Per-request Context Timeout**

   * The service layer creates `context.WithTimeout` for each check.
   * The HTTP client uses that context → all network ops obey it.

3. **HEAD before GET**

   * Default to `HEAD` to avoid downloading bodies.
   * Fallback to `GET` only when needed (e.g. `405 Method Not Allowed`).

4. **Minimal allocations**

   * Don’t buffer bodies.
   * Only read headers / limited info.
   * Use simple types and avoid unnecessary copies in hot paths.

5. **Stateless**

   * No per-request shared state.
   * No internal queues or background goroutines in MVP.
   * Easy to scale horizontally: just add more instances.

---

## 9. Observability

### Logging

* Log per request (at info level):

  * URL,
  * status,
  * `ok`,
  * `error_type` (if any),
  * total_ms.
* Log internal errors with stack/context (at error level).

### Metrics

Expose metrics endpoint (e.g., `/metrics` for Prometheus) and track:

* Counters:

  * `checks_total`
  * `checks_ok_total`
  * `checks_failed_total`
  * `checks_error_type_total{type=...}`
* Histogram:

  * `check_latency_ms` (bucketed)
* Optional:

  * `tls_cert_expiring_soon_total`
  * `https_checks_total`

### Healthcheck

* `/health` endpoint:

  * Returns simple JSON or 200 OK if:

    * process alive,
    * config loaded,
    * HTTP client initialized.

This helps with Kubernetes / Docker health probes.

---

## 10. Future Extensions (designed in from the start)

Because you keep the core clean and layered, you can later:

1. **Add batch checks**

   * New endpoint: `POST /check-batch` with a list of URLs.
   * Internally, iterate over URLs and call the existing `CheckURL` core.
   * Use a worker pool for concurrency, but reuse the same core & HTTP client.

2. **Add job + polling (async)**

   * New endpoints: `/check/start`, `/check/status`.
   * Implementation:

     * Job manager that stores job state (in memory or Redis/DB).
     * Each job calls `CheckURL` for many URLs in parallel.
   * Current `/check` stays as synchronous single-URL endpoint.

3. **Add caching**

   * Wrap the core checker with a “cache decorator”:

     * Check cache by URL key first.
     * If miss or stale → call real checker, store result.
   * This is a separate layer; does not change the core or HTTP API.

4. **Integrate with malicious/AI services**

   * Either from frontend (separate calls) or via a new BFF-style service.
   * Go `/check` remains unchanged and is just another “technical info source” others use.

---

## 11. Implementation Order

1. **Lock the API contract**

   * Define the JSON request and JSON response schema for `/check`.
   * Write it down in a simple spec (markdown / internal doc).

2. **Bootstrap project**

   * Create `cmd/linkchecker-api` and `internal/...` structure.
   * Add config loading and a simple health endpoint.

3. **Implement HTTP client (infra)**

   * Shared `Transport`, tuned timeouts.
   * Basic `Do` method with tracing support.

4. **Implement core checker (domain)**

   * Normalize URL.
   * Call HTTP client.
   * Collect timings.
   * Classify errors.
   * Build `CheckResult`.

5. **Implement service layer**

   * `CheckURL(ctx, url, options)`:

     * apply defaults,
     * create timeout context,
     * call checker,
     * log & emit metrics.

6. **Implement `/check` HTTP handler**

   * Parse input URL.
   * Call service.
   * Return JSON.

7. **Add observability**

   * Logs structured.
   * Basic metrics exposed.
   * Healthcheck endpoint.

8. **Perf sanity check**

   * Hit `/check` concurrently with many URLs.
   * Adjust timeouts & HTTP transport config if needed.

---

That’s the full Go service plan: **clean layers, high-performance HTTP client, single-URL `/check` endpoint, stateless and ready for future batch/polling/caching/AI integration.**
