// Package servicenow implements the ServiceNow API client and collector.
package servicenow

import (
	"context"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/PiotrMackowski/ClosedSSPM/internal/collector"
	"github.com/PiotrMackowski/ClosedSSPM/internal/httputil"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"golang.org/x/time/rate"
)

const (
	// version is used in the User-Agent header.
	version = "0.1.0"
)

const (
	defaultPageSize    = 1000
	defaultConcurrency = 5
	defaultRateLimit   = 10.0 // requests per second
)

// Client is the ServiceNow REST API client.
type Client struct {
	baseURL     string
	httpClient  *http.Client
	rateLimiter *rate.Limiter
	pageSize    int

	// Auth
	authMethod   string // "basic", "oauth", "keypair", or "apikey"
	username     string
	password     string
	clientID     string
	clientSecret string
	apiKey       string

	// Key pair auth
	privateKey *rsa.PrivateKey
	keyID      string
	jwtUser    string

	// OAuth token state (protected by mutex)
	mu    sync.Mutex
	token *httputil.OAuthToken
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

	checkRedirect := func(req *http.Request, via []*http.Request) error {
		if len(via) >= httputil.MaxRedirects {
			return fmt.Errorf("exceeded maximum redirects (%d)", httputil.MaxRedirects)
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
		privateKey:   nil, // set below for keypair
		keyID:        config.KeyID,
		jwtUser:      config.JWTUser,
		apiKey:       config.APIKey,
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
	case "apikey":
		if c.apiKey == "" {
			return nil, fmt.Errorf("api_key is required for apikey auth")
		}
	case "keypair":
		if c.clientID == "" || c.clientSecret == "" {
			return nil, fmt.Errorf("client_id and client_secret are required for key pair auth")
		}
		if config.PrivateKeyPath == "" {
			return nil, fmt.Errorf("private key path is required for key pair auth")
		}
		if c.keyID == "" {
			return nil, fmt.Errorf("key_id is required for key pair auth")
		}
		if c.jwtUser == "" {
			return nil, fmt.Errorf("jwt_user is required for key pair auth")
		}
		pk, err := loadPrivateKey(config.PrivateKeyPath)
		if err != nil {
			return nil, fmt.Errorf("loading private key: %w", err)
		}
		c.privateKey = pk
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
	case "keypair":
		token, err := c.getKeyPairToken(ctx)
		if err != nil {
			return fmt.Errorf("obtaining key pair token: %w", err)
		}
		req.Header.Set("Authorization", "Bearer "+token.AccessToken)
	case "apikey":
		req.Header.Set("x-sn-apikey", c.apiKey)
	}
	return nil
}

// getOAuthToken returns a valid OAuth token, refreshing if necessary.
func (c *Client) getOAuthToken(ctx context.Context) (*httputil.OAuthToken, error) {
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
		body, _ := httputil.ReadLimitedBody(resp.Body)
		return nil, fmt.Errorf("OAuth token request failed (status %d): %s", resp.StatusCode, httputil.SanitizeErrorBody(body))
	}

	var token httputil.OAuthToken
	if err := json.NewDecoder(io.LimitReader(resp.Body, httputil.MaxResponseBodySize)).Decode(&token); err != nil {
		return nil, fmt.Errorf("decoding token response: %w", err)
	}
	token.ExpiresAt = time.Now().Add(time.Duration(token.ExpiresIn) * time.Second)

	c.token = &token
	return c.token, nil
}

// loadPrivateKey reads and parses an RSA private key from a PEM file.
func loadPrivateKey(path string) (*rsa.PrivateKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading private key file: %w", err)
	}

	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("no PEM block found in %s", path)
	}

	// Try PKCS#8 first (modern format), fall back to PKCS#1.
	if key, err := x509.ParsePKCS8PrivateKey(block.Bytes); err == nil {
		rsaKey, ok := key.(*rsa.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("private key is not RSA")
		}
		return rsaKey, nil
	}

	return x509.ParsePKCS1PrivateKey(block.Bytes)
}

// signJWT creates a signed JWT assertion for ServiceNow key pair authentication.
func (c *Client) signJWT() (string, error) {
	now := time.Now()
	claims := jwt.RegisteredClaims{
		Issuer:    c.clientID,
		Subject:   c.jwtUser,
		Audience:  jwt.ClaimStrings{c.clientID},
		IssuedAt:  jwt.NewNumericDate(now),
		ExpiresAt: jwt.NewNumericDate(now.Add(5 * time.Minute)),
		ID:        uuid.New().String(),
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = c.keyID

	return token.SignedString(c.privateKey)
}

// getKeyPairToken returns a valid OAuth token using JWT bearer grant, refreshing if necessary.
func (c *Client) getKeyPairToken(ctx context.Context) (*httputil.OAuthToken, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.token != nil && !c.token.IsExpired() {
		return c.token, nil
	}

	assertion, err := c.signJWT()
	if err != nil {
		return nil, fmt.Errorf("signing JWT assertion: %w", err)
	}

	tokenURL := c.baseURL + "/oauth_token.do"
	data := url.Values{
		"grant_type":    {"urn:ietf:params:oauth:grant-type:jwt-bearer"},
		"assertion":     {assertion},
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
		body, _ := httputil.ReadLimitedBody(resp.Body)
		return nil, fmt.Errorf("key pair token request failed (status %d): %s", resp.StatusCode, httputil.SanitizeErrorBody(body))
	}

	var token httputil.OAuthToken
	if err := json.NewDecoder(io.LimitReader(resp.Body, httputil.MaxResponseBodySize)).Decode(&token); err != nil {
		return nil, fmt.Errorf("decoding token response: %w", err)
	}
	token.ExpiresAt = time.Now().Add(time.Duration(token.ExpiresIn) * time.Second)

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
			body, _ := httputil.ReadLimitedBody(resp.Body)
			return nil, fmt.Errorf("table %s query failed (status %d): %s", table, resp.StatusCode, httputil.SanitizeErrorBody(body))
		}

		var result QueryTableResponse
		if err := json.NewDecoder(io.LimitReader(resp.Body, httputil.MaxResponseBodySize)).Decode(&result); err != nil {
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
