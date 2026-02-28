// Package servicenow implements the ServiceNow API client and collector.
package servicenow

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/PiotrMackowski/ClosedSSPM/internal/collector"
	"golang.org/x/time/rate"
)

const (
	// version is used in the User-Agent header.
	version = "0.1.0"

	// maxResponseBodySize limits API response bodies to 50MB to prevent memory exhaustion.
	maxResponseBodySize = 50 * 1024 * 1024

	// maxRedirects limits the number of HTTP redirects followed.
	maxRedirects = 5
)

const (
	defaultPageSize    = 1000
	defaultConcurrency = 5
	defaultRateLimit   = 10.0 // requests per second
)

// OAuthToken represents an OAuth 2.0 access token response.
type OAuthToken struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	ExpiresIn   int    `json:"expires_in"`
	Scope       string `json:"scope"`
	expiresAt   time.Time
}

// IsExpired returns true if the token is expired or about to expire.
func (t *OAuthToken) IsExpired() bool {
	// Consider expired 60 seconds before actual expiry.
	return time.Now().After(t.expiresAt.Add(-60 * time.Second))
}

// Client is the ServiceNow REST API client.
type Client struct {
	baseURL     string
	httpClient  *http.Client
	rateLimiter *rate.Limiter
	pageSize    int

	// Auth
	authMethod   string // "basic" or "oauth"
	username     string
	password     string
	clientID     string
	clientSecret string

	// OAuth token state (protected by mutex)
	mu    sync.Mutex
	token *OAuthToken
}

// NewClient creates a new ServiceNow API client.
func NewClient(config collector.ConnectorConfig) (*Client, error) {
	if config.InstanceURL == "" {
		return nil, fmt.Errorf("instance URL is required")
	}

	// Normalize URL: ensure HTTPS and no trailing slash.
	instanceURL := strings.TrimRight(config.InstanceURL, "/")
	if !strings.HasPrefix(instanceURL, "https://") {
		if strings.HasPrefix(instanceURL, "http://") {
			return nil, fmt.Errorf("HTTP is not allowed; use HTTPS for instance URL")
		}
		instanceURL = "https://" + instanceURL
	}

	rl := config.RateLimit
	if rl <= 0 {
		rl = defaultRateLimit
	}

	pageSize := defaultPageSize

	// Build a hardened HTTP client:
	// - TLS 1.2 minimum (API Security Checklist)
	// - Controlled redirect policy (prevent SSRF via open redirects)
	// - Reasonable timeout
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{
			MinVersion: tls.VersionTLS12,
		},
	}

	redirectCount := 0
	checkRedirect := func(req *http.Request, via []*http.Request) error {
		redirectCount++
		if redirectCount > maxRedirects {
			return fmt.Errorf("exceeded maximum redirects (%d)", maxRedirects)
		}
		// Only allow redirects to the same host to prevent SSRF.
		if len(via) > 0 && req.URL.Host != via[0].URL.Host {
			return fmt.Errorf("redirect to different host %q blocked", req.URL.Host)
		}
		return nil
	}

	c := &Client{
		baseURL: instanceURL,
		httpClient: &http.Client{
			Timeout:       30 * time.Second,
			Transport:     transport,
			CheckRedirect: checkRedirect,
		},
		rateLimiter:  rate.NewLimiter(rate.Limit(rl), 1),
		pageSize:     pageSize,
		authMethod:   config.AuthMethod,
		username:     config.Username,
		password:     config.Password,
		clientID:     config.ClientID,
		clientSecret: config.ClientSecret,
	}

	// Validate auth config
	switch c.authMethod {
	case "basic", "":
		if c.username == "" || c.password == "" {
			return nil, fmt.Errorf("username and password are required for basic auth")
		}
		if c.authMethod == "" {
			c.authMethod = "basic"
		}
	case "oauth":
		if c.clientID == "" || c.clientSecret == "" {
			return nil, fmt.Errorf("client_id and client_secret are required for OAuth")
		}
	default:
		return nil, fmt.Errorf("unsupported auth method: %s", c.authMethod)
	}

	return c, nil
}

// authenticate sets authentication and standard headers on the request.
func (c *Client) authenticate(ctx context.Context, req *http.Request) error {
	// Always set User-Agent for auditability and rate-limit identification.
	req.Header.Set("User-Agent", "ClosedSSPM/"+version)

	switch c.authMethod {
	case "basic":
		req.SetBasicAuth(c.username, c.password)
	case "oauth":
		token, err := c.getOAuthToken(ctx)
		if err != nil {
			return fmt.Errorf("obtaining OAuth token: %w", err)
		}
		req.Header.Set("Authorization", "Bearer "+token.AccessToken)
	}
	return nil
}

// readLimitedBody reads at most maxResponseBodySize bytes from the response body.
// Returns an error if the body exceeds the limit.
func readLimitedBody(body io.Reader) ([]byte, error) {
	limited := io.LimitReader(body, maxResponseBodySize+1)
	data, err := io.ReadAll(limited)
	if err != nil {
		return nil, err
	}
	if len(data) > maxResponseBodySize {
		return nil, errors.New("response body exceeds maximum allowed size")
	}
	return data, nil
}

// sanitizeErrorBody truncates and sanitizes response bodies for error messages
// to prevent leaking sensitive information in logs.
func sanitizeErrorBody(body []byte) string {
	const maxErrorBodyLen = 256
	s := string(body)
	if len(s) > maxErrorBodyLen {
		s = s[:maxErrorBodyLen] + "...(truncated)"
	}
	return s
}

// getOAuthToken returns a valid OAuth token, refreshing if necessary.
func (c *Client) getOAuthToken(ctx context.Context) (*OAuthToken, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.token != nil && !c.token.IsExpired() {
		return c.token, nil
	}

	// Request new token via client credentials flow.
	tokenURL := c.baseURL + "/oauth_token.do"
	data := url.Values{
		"grant_type":    {"client_credentials"},
		"client_id":     {c.clientID},
		"client_secret": {c.clientSecret},
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, tokenURL, strings.NewReader(data.Encode()))
	if err != nil {
		return nil, fmt.Errorf("creating token request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("User-Agent", "ClosedSSPM/"+version)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("requesting token: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := readLimitedBody(resp.Body)
		return nil, fmt.Errorf("OAuth token request failed (status %d): %s", resp.StatusCode, sanitizeErrorBody(body))
	}

	var token OAuthToken
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxResponseBodySize)).Decode(&token); err != nil {
		return nil, fmt.Errorf("decoding token response: %w", err)
	}
	token.expiresAt = time.Now().Add(time.Duration(token.ExpiresIn) * time.Second)

	c.token = &token
	return c.token, nil
}

// QueryTableResponse represents the ServiceNow Table API response.
type QueryTableResponse struct {
	Result []collector.Record `json:"result"`
}

// QueryTable queries a ServiceNow table and returns all records with pagination.
func (c *Client) QueryTable(ctx context.Context, table string, fields []string) ([]collector.Record, error) {
	var allRecords []collector.Record
	offset := 0

	for {
		// Respect rate limit.
		if err := c.rateLimiter.Wait(ctx); err != nil {
			return nil, fmt.Errorf("rate limiter: %w", err)
		}

		apiURL := fmt.Sprintf("%s/api/now/table/%s", c.baseURL, url.PathEscape(table))
		params := url.Values{
			"sysparm_limit":  {strconv.Itoa(c.pageSize)},
			"sysparm_offset": {strconv.Itoa(offset)},
		}
		if len(fields) > 0 {
			params.Set("sysparm_fields", strings.Join(fields, ","))
		}
		// Return display values alongside sys_id references.
		params.Set("sysparm_display_value", "all")
		// Exclude XML attributes for cleaner JSON.
		params.Set("sysparm_exclude_reference_link", "true")

		reqURL := apiURL + "?" + params.Encode()
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL, nil)
		if err != nil {
			return nil, fmt.Errorf("creating request for %s: %w", table, err)
		}
		req.Header.Set("Accept", "application/json")

		if err := c.authenticate(ctx, req); err != nil {
			return nil, fmt.Errorf("authenticating request: %w", err)
		}

		resp, err := c.httpClient.Do(req)
		if err != nil {
			return nil, fmt.Errorf("querying table %s: %w", table, err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			body, _ := readLimitedBody(resp.Body)
			return nil, fmt.Errorf("table %s query failed (status %d): %s", table, resp.StatusCode, sanitizeErrorBody(body))
		}

		var result QueryTableResponse
		if err := json.NewDecoder(io.LimitReader(resp.Body, maxResponseBodySize)).Decode(&result); err != nil {
			return nil, fmt.Errorf("decoding response for %s: %w", table, err)
		}

		allRecords = append(allRecords, result.Result...)

		// If we got fewer records than the page size, we're done.
		if len(result.Result) < c.pageSize {
			break
		}
		offset += c.pageSize
	}

	return allRecords, nil
}
