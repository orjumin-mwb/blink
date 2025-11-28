package mwbapi

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

// Client handles requests to MWB Swamp Intel API
type Client struct {
	baseURL    string
	httpClient *http.Client
	userAgent  string
}

// MWBResponse represents the response from MWB API
type MWBResponse struct {
	IsMalicious bool `json:"is_malicious"`
	// Add other fields as needed when we know the full API response
}

// New creates a new MWB API client
func New() *Client {
	return &Client{
		baseURL:   "https://swamp-intel.mwbsys-prod.com",
		userAgent: "ScamGuard/v2.0 (MBIOS 5.0.1)",
		httpClient: &http.Client{
			Timeout: 5 * time.Second, // 5 second timeout for MWB API calls
		},
	}
}

// CheckURL calls the MWB API to check if a URL is malicious
func (c *Client) CheckURL(ctx context.Context, targetURL string) (bool, error) {
	// Build the API URL
	apiURL := fmt.Sprintf("%s/url/check", c.baseURL)
	
	// Create request with URL parameter
	req, err := http.NewRequestWithContext(ctx, "GET", apiURL, nil)
	if err != nil {
		return false, fmt.Errorf("failed to create request: %w", err)
	}

	// Add URL as query parameter
	q := req.URL.Query()
	q.Add("url", targetURL)
	req.URL.RawQuery = q.Encode()

	// Set headers
	req.Header.Set("Product-User-Agent", c.userAgent)
	req.Header.Set("User-Agent", c.userAgent)

	// Make the request
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return false, fmt.Errorf("failed to call MWB API: %w", err)
	}
	defer resp.Body.Close()

	// Check for non-200 status codes
	if resp.StatusCode != http.StatusOK {
		return false, fmt.Errorf("MWB API returned status %d", resp.StatusCode)
	}

	// Parse the response
	var mwbResp MWBResponse
	if err := json.NewDecoder(resp.Body).Decode(&mwbResp); err != nil {
		return false, fmt.Errorf("failed to parse MWB API response: %w", err)
	}

	return mwbResp.IsMalicious, nil
}