package checker

import (
	"github.com/olegrjumin/blink/internal/httpclient"
)

// PerformanceTimings holds detailed timing information in milliseconds
type PerformanceTimings struct {
	DNSMs     int64 // DNS lookup time
	ConnectMs int64 // TCP connection time
	TLSMs     int64 // TLS handshake time
	TTFBMs    int64 // Time to first byte
}

// ExtractTimings converts httpclient.TimingInfo to PerformanceTimings
// Calculates the duration of each phase in milliseconds
func ExtractTimings(timings *httpclient.TimingInfo) PerformanceTimings {
	perf := PerformanceTimings{}

	// Calculate DNS time
	if !timings.DNSStart.IsZero() && !timings.DNSDone.IsZero() {
		perf.DNSMs = timings.DNSDone.Sub(timings.DNSStart).Milliseconds()
	}

	// Calculate connect time
	if !timings.ConnectStart.IsZero() && !timings.ConnectDone.IsZero() {
		perf.ConnectMs = timings.ConnectDone.Sub(timings.ConnectStart).Milliseconds()
	}

	// Calculate TLS handshake time
	if !timings.TLSStart.IsZero() && !timings.TLSDone.IsZero() {
		perf.TLSMs = timings.TLSDone.Sub(timings.TLSStart).Milliseconds()
	}

	// Calculate time to first byte (from request start)
	if !timings.RequestStart.IsZero() && !timings.GotFirstByte.IsZero() {
		perf.TTFBMs = timings.GotFirstByte.Sub(timings.RequestStart).Milliseconds()
	}

	return perf
}

// ClassifySpeed returns a speed classification based on total response time
// "fast" = < 300ms, "ok" = 300-1000ms, "slow" = > 1000ms
func ClassifySpeed(totalMs int64) string {
	if totalMs < 300 {
		return "fast"
	} else if totalMs < 1000 {
		return "ok"
	}
	return "slow"
}
