package config

import (
	"os"
	"strconv"
	"time"
)

// Config holds all configuration for the application
type Config struct {
	// Server configuration
	Port int // HTTP server port

	// Checker configuration
	RequestTimeout   time.Duration // Per-request timeout
	MaxRedirects     int           // Maximum number of redirects to follow
	DefaultUserAgent string        // Default User-Agent header
	DefaultMethod    string        // Default HTTP method (HEAD or GET)
}

// Load reads configuration from environment variables
// and returns a Config struct with defaults applied
func Load() *Config {
	return &Config{
		Port:             getEnvAsInt("PORT", 8080),
		RequestTimeout:   getEnvAsDuration("REQUEST_TIMEOUT", 3000*time.Millisecond),
		MaxRedirects:     getEnvAsInt("MAX_REDIRECTS", 5),
		DefaultUserAgent: getEnv("DEFAULT_USER_AGENT", "blink-checker/1.0"),
		DefaultMethod:    getEnv("DEFAULT_METHOD", "HEAD"),
	}
}

// getEnv reads an environment variable or returns a default value
func getEnv(key, defaultValue string) string {
	if value, exists := os.LookupEnv(key); exists {
		return value
	}
	return defaultValue
}

// getEnvAsInt reads an environment variable as an integer
// If the variable doesn't exist or can't be parsed, returns the default
func getEnvAsInt(key string, defaultValue int) int {
	valueStr := getEnv(key, "")
	if valueStr == "" {
		return defaultValue
	}

	value, err := strconv.Atoi(valueStr)
	if err != nil {
		return defaultValue
	}

	return value
}

// getEnvAsDuration reads an environment variable as milliseconds and converts to time.Duration
// If the variable doesn't exist or can't be parsed, returns the default
func getEnvAsDuration(key string, defaultValue time.Duration) time.Duration {
	valueStr := getEnv(key, "")
	if valueStr == "" {
		return defaultValue
	}

	// Parse as milliseconds
	ms, err := strconv.Atoi(valueStr)
	if err != nil {
		return defaultValue
	}

	return time.Duration(ms) * time.Millisecond
}
