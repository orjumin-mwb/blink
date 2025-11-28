package checker

import (
	"crypto/tls"
	"crypto/x509"
	"strings"
	"time"
)

// TLSInfo holds TLS and certificate information
type TLSInfo struct {
	TLSVersion        string
	CertValid         bool
	CertExpiresAt     string // ISO8601 format
	CertDaysRemaining int
	CertExpiringSoon  bool // true if < 30 days
	CertIssuer        string
}

// ExtractTLSInfo analyzes TLS connection state and extracts certificate information
// Returns nil if the connection is not TLS/HTTPS
func ExtractTLSInfo(tlsState *tls.ConnectionState) *TLSInfo {
	if tlsState == nil {
		return nil
	}

	info := &TLSInfo{}

	// Extract TLS version
	info.TLSVersion = tlsVersionString(tlsState.Version)

	// Extract certificate information if available
	if len(tlsState.PeerCertificates) > 0 {
		cert := tlsState.PeerCertificates[0] // First cert is the server's certificate

		// Check if certificate is currently valid
		now := time.Now()
		info.CertValid = now.After(cert.NotBefore) && now.Before(cert.NotAfter)

		// Extract expiration date
		info.CertExpiresAt = cert.NotAfter.UTC().Format(time.RFC3339)

		// Calculate days remaining
		daysRemaining := int(time.Until(cert.NotAfter).Hours() / 24)
		info.CertDaysRemaining = daysRemaining

		// Check if expiring soon (< 30 days)
		info.CertExpiringSoon = daysRemaining < 30 && daysRemaining >= 0

		// Extract issuer information
		info.CertIssuer = extractIssuerCN(cert)
	}

	return info
}

// tlsVersionString converts TLS version constant to string
func tlsVersionString(version uint16) string {
	switch version {
	case tls.VersionTLS10:
		return "TLS1.0"
	case tls.VersionTLS11:
		return "TLS1.1"
	case tls.VersionTLS12:
		return "TLS1.2"
	case tls.VersionTLS13:
		return "TLS1.3"
	default:
		return "unknown"
	}
}

// extractIssuerCN extracts the Common Name (CN) from the certificate issuer
// Falls back to Organization if CN is not available
func extractIssuerCN(cert *x509.Certificate) string {
	// Try to get Common Name
	if cert.Issuer.CommonName != "" {
		return cert.Issuer.CommonName
	}

	// Fallback to Organization
	if len(cert.Issuer.Organization) > 0 {
		return strings.Join(cert.Issuer.Organization, ", ")
	}

	// Last resort: use the full DN string
	return cert.Issuer.String()
}
