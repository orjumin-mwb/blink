package checker

import (
	"testing"
)

func TestWeakCryptoDetection(t *testing.T) {
	detector := NewSecurityCryptoDetector()

	testCases := []struct {
		name          string
		code          string
		expectedCount int
		expectedType  string
		expectedTitle string
	}{
		{
			name: "MD5 hash detection",
			code: `
				const crypto = require('crypto');
				const hash = crypto.createHash('md5').update(data).digest('hex');
			`,
			expectedCount: 1,
			expectedType:  "weak-crypto",
			expectedTitle: "Weak hashing algorithm: MD5",
		},
		{
			name: "SHA1 for passwords - critical",
			code: `
				const hash = crypto.createHash('sha1');
				hash.update(password);
				const hashedPassword = hash.digest('hex');
			`,
			expectedCount: 1,
			expectedType:  "weak-crypto",
			expectedTitle: "Weak hashing algorithm: SHA-1",
		},
		{
			name: "DES cipher detection",
			code: `
				const cipher = crypto.createCipher('des', password);
				const encrypted = cipher.update(data, 'utf8', 'hex');
			`,
			expectedCount: 1,
			expectedType:  "weak-crypto",
			expectedTitle: "Weak encryption algorithm: DES",
		},
		{
			name: "RC4 cipher detection",
			code: `
				const cipher = crypto.createCipheriv('rc4', key, iv);
			`,
			expectedCount: 1,
			expectedType:  "weak-crypto",
			expectedTitle: "Weak encryption algorithm: RC4",
		},
		{
			name: "Math.random for token",
			code: `
				const token = Math.random().toString(36).substring(7);
				const sessionId = 'sess_' + Math.random();
			`,
			expectedCount: 1,
			expectedType:  "weak-crypto",
			expectedTitle: "Weak random number generation for security",
		},
		{
			name: "Hardcoded encryption key",
			code: `
				const secretKey = "abcdef1234567890abcdef1234567890";
				const cipher = crypto.createCipheriv('aes-256-cbc', secretKey, iv);
			`,
			expectedCount: 1,
			expectedType:  "hardcoded-secret",
			expectedTitle: "Hardcoded encryption keys detected",
		},
		{
			name: "Client-side password hashing",
			code: `
				const hashedPassword = sha256(password);
				fetch('/api/login', {
					body: JSON.stringify({ password: hashedPassword })
				});
			`,
			expectedCount: 1,
			expectedType:  "weak-crypto",
			expectedTitle: "Client-side password hashing",
		},
		{
			name: "CryptoJS MD5",
			code: `
				const hash = CryptoJS.MD5(message).toString();
			`,
			expectedCount: 1,
			expectedType:  "weak-crypto",
			expectedTitle: "Weak hashing algorithm: MD5",
		},
		{
			name: "Safe crypto - should not detect",
			code: `
				const crypto = require('crypto');
				const hash = crypto.createHash('sha256').update(data).digest('hex');
				const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
			`,
			expectedCount: 0,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			issues := detector.Detect(tc.code, []string{tc.code})

			if len(issues) != tc.expectedCount {
				t.Errorf("Expected %d issues, got %d", tc.expectedCount, len(issues))
				for i, issue := range issues {
					t.Logf("Issue %d: %s - %s", i, issue.Type, issue.Title)
				}
				return
			}

			if tc.expectedCount > 0 {
				found := false
				for _, issue := range issues {
					if issue.Type == tc.expectedType && issue.Title == tc.expectedTitle {
						found = true
						break
					}
				}
				if !found {
					t.Errorf("Expected issue with type '%s' and title '%s' not found", tc.expectedType, tc.expectedTitle)
					for i, issue := range issues {
						t.Logf("Issue %d: Type=%s, Title=%s", i, issue.Type, issue.Title)
					}
				}
			}
		})
	}
}

func TestWebSocketDetection(t *testing.T) {
	detector := NewSecurityClientDetector()

	testCases := []struct {
		name          string
		code          string
		expectedCount int
		expectedTitle string
	}{
		{
			name: "Insecure WebSocket protocol",
			code: `
				const ws = new WebSocket('ws://example.com/socket');
			`,
			expectedCount: 1,
			expectedTitle: "Insecure WebSocket connection",
		},
		{
			name: "Secure WebSocket - should not detect",
			code: `
				const ws = new WebSocket('wss://example.com/socket');
			`,
			expectedCount: 0,
		},
		{
			name: "WebSocket with user-controlled URL (direct)",
			code: `
				const ws = new WebSocket(window.location.hash.substring(1));
			`,
			expectedCount: 1,
			expectedTitle: "WebSocket with user-controlled URL",
		},
		{
			name: "WebSocket without origin check",
			code: `
				const ws = new WebSocket('wss://example.com');
				ws.onmessage = function(event) {
					processData(event.data);
				};
			`,
			expectedCount: 1,
			expectedTitle: "WebSocket without origin validation",
		},
		{
			name: "WebSocket with origin check - should detect secure",
			code: `
				const ws = new WebSocket('wss://example.com');
				ws.onmessage = function(event) {
					if (event.origin !== 'https://trusted.com') return;
					processData(event.data);
				};
			`,
			expectedCount: 0,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			issues := detector.Detect(tc.code, []string{tc.code})

			if len(issues) != tc.expectedCount {
				t.Errorf("Expected %d issues, got %d", tc.expectedCount, len(issues))
				for i, issue := range issues {
					t.Logf("Issue %d: %s", i, issue.Title)
				}
				return
			}

			if tc.expectedCount > 0 {
				found := false
				for _, issue := range issues {
					if issue.Title == tc.expectedTitle {
						found = true
						break
					}
				}
				if !found {
					t.Errorf("Expected issue with title '%s' not found", tc.expectedTitle)
					for i, issue := range issues {
						t.Logf("Issue %d: %s", i, issue.Title)
					}
				}
			}
		})
	}
}
