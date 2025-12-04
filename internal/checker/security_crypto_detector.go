package checker

import (
	"fmt"
	"regexp"
	"strings"
)

// SecurityCryptoDetector detects cryptographic vulnerabilities
type SecurityCryptoDetector struct {
	weakHashPatterns       []*regexp.Regexp
	weakCipherPatterns     []*regexp.Regexp
	weakRandomPatterns     []*regexp.Regexp
	hardcodedKeyPatterns   []*regexp.Regexp
	passwordHashPatterns   []*regexp.Regexp
}

// NewSecurityCryptoDetector creates a new cryptography security detector
func NewSecurityCryptoDetector() *SecurityCryptoDetector {
	return &SecurityCryptoDetector{
		weakHashPatterns: []*regexp.Regexp{
			// Weak hash algorithms
			regexp.MustCompile(`(?i)crypto\.createHash\s*\(\s*['"]md5['"]`),
			regexp.MustCompile(`(?i)crypto\.createHash\s*\(\s*['"]md4['"]`),
			regexp.MustCompile(`(?i)crypto\.createHash\s*\(\s*['"]sha1['"]`),
			regexp.MustCompile(`(?i)crypto\.createHash\s*\(\s*['"]sha-1['"]`),
			regexp.MustCompile(`(?i)CryptoJS\.MD5\s*\(`),
			regexp.MustCompile(`(?i)CryptoJS\.SHA1\s*\(`),
			regexp.MustCompile(`(?i)hashlib\.md5\s*\(`),
			regexp.MustCompile(`(?i)hashlib\.sha1\s*\(`),
			regexp.MustCompile(`(?i)MessageDigest\.getInstance\s*\(\s*['"]MD5['"]`),
			regexp.MustCompile(`(?i)MessageDigest\.getInstance\s*\(\s*['"]SHA-1['"]`),
		},
		weakCipherPatterns: []*regexp.Regexp{
			// Deprecated/weak ciphers
			regexp.MustCompile(`(?i)crypto\.createCipher\s*\(\s*['"]des['"]`),
			regexp.MustCompile(`(?i)crypto\.createCipher\s*\(\s*['"]des-ede['"]`),
			regexp.MustCompile(`(?i)crypto\.createCipher\s*\(\s*['"]des-ede3['"]`),
			regexp.MustCompile(`(?i)crypto\.createCipher\s*\(\s*['"]rc4['"]`),
			regexp.MustCompile(`(?i)crypto\.createCipher\s*\(\s*['"]rc2['"]`),
			regexp.MustCompile(`(?i)crypto\.createCipher\s*\(\s*['"]blowfish['"]`),
			regexp.MustCompile(`(?i)crypto\.createCipheriv\s*\(\s*['"]des['"]`),
			regexp.MustCompile(`(?i)crypto\.createCipheriv\s*\(\s*['"]rc4['"]`),
			regexp.MustCompile(`(?i)CryptoJS\.DES\.encrypt`),
			regexp.MustCompile(`(?i)CryptoJS\.TripleDES\.encrypt`),
			regexp.MustCompile(`(?i)CryptoJS\.RC4\.encrypt`),
			regexp.MustCompile(`(?i)Cipher\.getInstance\s*\(\s*['"]DES[/'"]`),
			regexp.MustCompile(`(?i)Cipher\.getInstance\s*\(\s*['"]RC4[/'"]`),
		},
		weakRandomPatterns: []*regexp.Regexp{
			// Math.random() for security tokens/secrets
			regexp.MustCompile(`(?i)(?:token|secret|key|password|session|nonce|salt)\s*=\s*[^;]*Math\.random\(\)`),
			regexp.MustCompile(`(?i)Math\.random\(\)[^;]*(?:toString|substr|substring)[^;]*\d+[^;]*(?:token|secret|key|password|session)`),
			regexp.MustCompile(`(?i)(?:csrf|xsrf)[_-]?token\s*=\s*[^;]*Math\.random\(\)`),
			regexp.MustCompile(`(?i)(?:api|auth)[_-]?key\s*=\s*[^;]*Math\.random\(\)`),
			// Common weak random patterns
			regexp.MustCompile(`(?i)sessionId\s*=\s*[^;]*Math\.random\(\)`),
			regexp.MustCompile(`(?i)sessionToken\s*=\s*[^;]*Math\.random\(\)`),
		},
		hardcodedKeyPatterns: []*regexp.Regexp{
			// Hardcoded encryption keys and IVs
			regexp.MustCompile(`(?i)(?:encryption|crypto)[_-]?key\s*[=:]\s*['"][a-zA-Z0-9+/=]{16,}['"]`),
			regexp.MustCompile(`(?i)secret[_-]?key\s*[=:]\s*['"][a-zA-Z0-9+/=]{16,}['"]`),
			regexp.MustCompile(`(?i)(?:aes|des)[_-]?key\s*[=:]\s*['"][a-zA-Z0-9+/=]{16,}['"]`),
			regexp.MustCompile(`(?i)iv\s*[=:]\s*['"][a-zA-Z0-9+/=]{16,}['"]`),
			regexp.MustCompile(`(?i)initialization[_-]?vector\s*[=:]\s*['"][a-zA-Z0-9+/=]{16,}['"]`),
			regexp.MustCompile(`(?i)Buffer\.from\s*\(\s*['"][a-zA-Z0-9+/=]{16,}['"]\s*,\s*['"](?:hex|base64)['"]`),
			regexp.MustCompile(`(?i)crypto\.createCipher(?:iv)?\s*\([^,]+,\s*['"][a-zA-Z0-9+/=]{16,}['"]`),
			regexp.MustCompile(`(?i)CryptoJS\.(?:AES|DES)\.(?:encrypt|decrypt)\s*\([^,]+,\s*['"][a-zA-Z0-9+/=]{8,}['"]`),
		},
		passwordHashPatterns: []*regexp.Regexp{
			// Client-side password hashing (bad practice)
			regexp.MustCompile(`(?i)(?:hash|md5|sha1|sha256)\s*\(\s*password`),
			regexp.MustCompile(`(?i)password\s*=\s*[^;]*(?:md5|sha1|sha256|hash)\s*\(`),
			regexp.MustCompile(`(?i)CryptoJS\.(?:MD5|SHA1|SHA256)\s*\(\s*password`),
		},
	}
}

// Detect analyzes JavaScript for cryptographic vulnerabilities
func (d *SecurityCryptoDetector) Detect(html string, scripts []string) []SecurityIssue {
	issues := []SecurityIssue{}

	// Combine all content for analysis
	allContent := html
	for _, script := range scripts {
		allContent += "\n" + script
	}

	// Detect weak hash algorithms
	issues = append(issues, d.detectWeakHashing(allContent)...)

	// Detect weak/deprecated ciphers
	issues = append(issues, d.detectWeakCiphers(allContent)...)

	// Detect weak random number generation for security
	issues = append(issues, d.detectWeakRandom(allContent)...)

	// Detect hardcoded encryption keys
	issues = append(issues, d.detectHardcodedKeys(allContent)...)

	// Detect client-side password hashing
	issues = append(issues, d.detectClientSidePasswordHashing(allContent)...)

	return issues
}

// detectWeakHashing finds use of weak hashing algorithms
func (d *SecurityCryptoDetector) detectWeakHashing(content string) []SecurityIssue {
	issues := []SecurityIssue{}
	foundHashes := make(map[string][]string)

	for _, pattern := range d.weakHashPatterns {
		matches := pattern.FindAllString(content, -1)
		if len(matches) > 0 {
			// Extract algorithm name
			for _, match := range matches {
				matchLower := strings.ToLower(match)
				var algo string
				if strings.Contains(matchLower, "md5") || strings.Contains(matchLower, "md4") {
					algo = "MD5"
				} else if strings.Contains(matchLower, "sha1") || strings.Contains(matchLower, "sha-1") {
					algo = "SHA-1"
				}

				if algo != "" {
					foundHashes[algo] = append(foundHashes[algo], match)
				}
			}
		}
	}

	for algo, matches := range foundHashes {
		// Check if it's used in password context (higher severity)
		severity := "medium"
		description := fmt.Sprintf("Weak hashing algorithm %s detected in code", algo)
		impact := fmt.Sprintf("%s is cryptographically broken and vulnerable to collision attacks", algo)

		// Check if used for passwords
		for _, match := range matches {
			context := d.getContextAround(content, match, 100)
			if strings.Contains(strings.ToLower(context), "password") ||
			   strings.Contains(strings.ToLower(context), "passwd") ||
			   strings.Contains(strings.ToLower(context), "credential") {
				severity = "critical"
				description = fmt.Sprintf("%s used for password hashing", algo)
				impact = fmt.Sprintf("%s is completely insecure for password hashing - passwords can be cracked", algo)
				break
			}
		}

		remediation := "SHA-256 or SHA-512"
		if severity == "critical" {
			remediation = "bcrypt, scrypt, Argon2, or PBKDF2 for passwords"
		}

		issues = append(issues, SecurityIssue{
			Type:        "weak-crypto",
			Title:       fmt.Sprintf("Weak hashing algorithm: %s", algo),
			Description: description,
			Severity:    severity,
			Evidence:    d.limitEvidence(matches, 3),
			Impact:      impact,
			Remediation: fmt.Sprintf("Replace %s with %s", algo, remediation),
			Verified:    true,
		})
	}

	return issues
}

// detectWeakCiphers finds use of weak/deprecated encryption algorithms
func (d *SecurityCryptoDetector) detectWeakCiphers(content string) []SecurityIssue {
	issues := []SecurityIssue{}
	foundCiphers := make(map[string][]string)

	for _, pattern := range d.weakCipherPatterns {
		matches := pattern.FindAllString(content, -1)
		if len(matches) > 0 {
			for _, match := range matches {
				matchLower := strings.ToLower(match)
				var cipher string

				if strings.Contains(matchLower, "des-ede3") || strings.Contains(matchLower, "tripledes") {
					cipher = "3DES"
				} else if strings.Contains(matchLower, "des-ede") {
					cipher = "DES-EDE"
				} else if strings.Contains(matchLower, "des") {
					cipher = "DES"
				} else if strings.Contains(matchLower, "rc4") {
					cipher = "RC4"
				} else if strings.Contains(matchLower, "rc2") {
					cipher = "RC2"
				} else if strings.Contains(matchLower, "blowfish") {
					cipher = "Blowfish"
				}

				if cipher != "" {
					foundCiphers[cipher] = append(foundCiphers[cipher], match)
				}
			}
		}
	}

	for cipher, matches := range foundCiphers {
		severity := "high"
		if cipher == "DES" || cipher == "RC4" {
			severity = "critical"
		}

		cve := ""
		if cipher == "RC4" {
			cve = "CVE-2013-2566, CVE-2015-2808"
		}

		issues = append(issues, SecurityIssue{
			Type:        "weak-crypto",
			Title:       fmt.Sprintf("Weak encryption algorithm: %s", cipher),
			Description: fmt.Sprintf("%s cipher is deprecated and insecure", cipher),
			Severity:    severity,
			Evidence:    d.limitEvidence(matches, 3),
			Impact:      fmt.Sprintf("%s encryption can be broken - data can be decrypted by attackers", cipher),
			Remediation: fmt.Sprintf("Replace %s with AES-256-GCM or ChaCha20-Poly1305", cipher),
			Verified:    true,
			CVE:         cve,
		})
	}

	return issues
}

// detectWeakRandom finds Math.random() used for security purposes
func (d *SecurityCryptoDetector) detectWeakRandom(content string) []SecurityIssue {
	issues := []SecurityIssue{}
	matches := []string{}

	for _, pattern := range d.weakRandomPatterns {
		found := pattern.FindAllString(content, -1)
		matches = append(matches, found...)
	}

	if len(matches) > 0 {
		issues = append(issues, SecurityIssue{
			Type:        "weak-crypto",
			Title:       "Weak random number generation for security",
			Description: fmt.Sprintf("Math.random() used for security tokens/secrets (%d instances)", len(matches)),
			Severity:    "critical",
			Evidence:    d.limitEvidence(matches, 3),
			Impact:      "Math.random() is not cryptographically secure - tokens/secrets are predictable",
			Remediation: "Use crypto.getRandomValues() or crypto.randomBytes() for security purposes",
			Verified:    true,
		})
	}

	return issues
}

// detectHardcodedKeys finds hardcoded encryption keys and IVs
func (d *SecurityCryptoDetector) detectHardcodedKeys(content string) []SecurityIssue {
	issues := []SecurityIssue{}
	foundKeys := []string{}

	for _, pattern := range d.hardcodedKeyPatterns {
		matches := pattern.FindAllString(content, -1)
		for _, match := range matches {
			// Mask the key for evidence
			masked := d.maskSecret(match)
			foundKeys = append(foundKeys, masked)
		}
	}

	if len(foundKeys) > 0 {
		issues = append(issues, SecurityIssue{
			Type:        "hardcoded-secret",
			Title:       "Hardcoded encryption keys detected",
			Description: fmt.Sprintf("Found %d hardcoded encryption keys or IVs in code", len(foundKeys)),
			Severity:    "critical",
			Evidence:    d.limitEvidence(foundKeys, 3),
			Impact:      "Hardcoded keys can be extracted from code - all encrypted data can be decrypted",
			Remediation: "Store encryption keys in environment variables or secure key management systems (KMS)",
			Verified:    true,
		})
	}

	return issues
}

// detectClientSidePasswordHashing finds password hashing in client code
func (d *SecurityCryptoDetector) detectClientSidePasswordHashing(content string) []SecurityIssue {
	issues := []SecurityIssue{}
	matches := []string{}

	for _, pattern := range d.passwordHashPatterns {
		found := pattern.FindAllString(content, -1)
		matches = append(matches, found...)
	}

	if len(matches) > 0 {
		issues = append(issues, SecurityIssue{
			Type:        "weak-crypto",
			Title:       "Client-side password hashing",
			Description: "Passwords hashed in client-side JavaScript",
			Severity:    "high",
			Evidence:    d.limitEvidence(matches, 3),
			Impact:      "Client-side hashing doesn't protect passwords - hash can be replayed as password",
			Remediation: "Hash passwords server-side only using bcrypt, scrypt, or Argon2",
			Verified:    true,
		})
	}

	return issues
}

// getContextAround extracts context around a match
func (d *SecurityCryptoDetector) getContextAround(content, match string, length int) string {
	index := strings.Index(content, match)
	if index == -1 {
		return ""
	}

	start := index - length
	if start < 0 {
		start = 0
	}
	end := index + len(match) + length
	if end > len(content) {
		end = len(content)
	}

	return content[start:end]
}

// maskSecret masks sensitive data for evidence
func (d *SecurityCryptoDetector) maskSecret(s string) string {
	// Find the string literal
	pattern := regexp.MustCompile(`['"][a-zA-Z0-9+/=]{16,}['"]`)
	return pattern.ReplaceAllStringFunc(s, func(match string) string {
		if len(match) > 16 {
			return match[:8] + "..." + match[len(match)-4:]
		}
		return match[:4] + "..."
	})
}

// limitEvidence limits evidence to a maximum number of items
func (d *SecurityCryptoDetector) limitEvidence(evidence []string, max int) []string {
	if len(evidence) <= max {
		return evidence
	}
	return evidence[:max]
}
