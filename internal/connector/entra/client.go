package entra

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/PiotrMackowski/ClosedSSPM/internal/collector"
	"golang.org/x/time/rate"
)

const (
	version             = "0.1.0"
	maxResponseBodySize = 50 * 1024 * 1024
	defaultConcurrency  = 5
	defaultRateLimit    = 10.0
	maxRedirects        = 5
	graphV1BaseURL      = "https://graph.microsoft.com/v1.0"
	graphRootURL        = "https://graph.microsoft.com"
)

type OAuthToken struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	ExpiresIn   int    `json:"expires_in"`
	Scope       string `json:"scope"`
	expiresAt   time.Time
}

func (t *OAuthToken) IsExpired() bool {
	return time.Now().After(t.expiresAt.Add(-60 * time.Second))
}

type Client struct {
	baseURL     string
	tokenURL    string
	httpClient  *http.Client
	rateLimiter *rate.Limiter

	tenantID     string
	clientID     string
	clientSecret string

	mu    sync.Mutex
	token *OAuthToken
}

func NewClient(config collector.ConnectorConfig) (*Client, error) {
	tenantID := strings.TrimSpace(config.Account)
	if tenantID == "" {
		return nil, fmt.Errorf("tenant ID is required")
	}
	if strings.TrimSpace(config.ClientID) == "" || strings.TrimSpace(config.ClientSecret) == "" {
		return nil, fmt.Errorf("client_id and client_secret are required for OAuth")
	}

	rl := config.RateLimit
	if rl <= 0 {
		rl = defaultRateLimit
	}

	transport := &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12}}
	redirectCount := 0
	checkRedirect := func(req *http.Request, via []*http.Request) error {
		redirectCount++
		if redirectCount > maxRedirects {
			return fmt.Errorf("exceeded maximum redirects (%d)", maxRedirects)
		}
		if len(via) > 0 && req.URL.Host != via[0].URL.Host {
			return fmt.Errorf("redirect to different host %q blocked", req.URL.Host)
		}
		return nil
	}

	return &Client{
		baseURL:      graphV1BaseURL,
		tokenURL:     fmt.Sprintf("https://login.microsoftonline.com/%s/oauth2/v2.0/token", url.PathEscape(tenantID)),
		httpClient:   &http.Client{Timeout: 30 * time.Second, Transport: transport, CheckRedirect: checkRedirect},
		rateLimiter:  rate.NewLimiter(rate.Limit(rl), 1),
		tenantID:     tenantID,
		clientID:     config.ClientID,
		clientSecret: config.ClientSecret,
	}, nil
}

func (c *Client) authenticate(ctx context.Context, req *http.Request) error {
	req.Header.Set("User-Agent", "ClosedSSPM/"+version)
	req.Header.Set("Accept", "application/json")
	tok, err := c.getOAuthToken(ctx)
	if err != nil {
		return fmt.Errorf("obtaining OAuth token: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+tok.AccessToken)
	return nil
}

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

func sanitizeErrorBody(body []byte) string {
	const maxErrorBodyLen = 256
	s := string(body)
	if len(s) > maxErrorBodyLen {
		s = s[:maxErrorBodyLen] + "...(truncated)"
	}
	return s
}

func (c *Client) getOAuthToken(ctx context.Context) (*OAuthToken, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.token != nil && !c.token.IsExpired() {
		return c.token, nil
	}
	data := url.Values{
		"grant_type":    {"client_credentials"},
		"client_id":     {c.clientID},
		"client_secret": {c.clientSecret},
		"scope":         {"https://graph.microsoft.com/.default"},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.tokenURL, strings.NewReader(data.Encode()))
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

func (c *Client) resolveGraphURL(path string) string {
	if strings.HasPrefix(path, "https://") || strings.HasPrefix(path, "http://") {
		return path
	}
	if strings.HasPrefix(path, "/beta/") || strings.HasPrefix(path, "/v1.0/") {
		return graphRootURL + path
	}
	if strings.HasPrefix(path, "/") {
		return c.baseURL + path
	}
	return c.baseURL + "/" + path
}

func (c *Client) doGraphGET(ctx context.Context, requestURL string) ([]byte, error) {
	if err := c.rateLimiter.Wait(ctx); err != nil {
		return nil, fmt.Errorf("rate limiter: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, requestURL, nil)
	if err != nil {
		return nil, fmt.Errorf("creating request: %w", err)
	}
	if err := c.authenticate(ctx, req); err != nil {
		return nil, fmt.Errorf("authenticating request: %w", err)
	}
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("performing request: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := readLimitedBody(resp.Body)
		return nil, fmt.Errorf("graph request failed (status %d): %s", resp.StatusCode, sanitizeErrorBody(body))
	}
	body, err := readLimitedBody(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("reading response body: %w", err)
	}
	return body, nil
}

func (c *Client) graphGet(ctx context.Context, path string) ([]json.RawMessage, error) {
	type pageResponse struct {
		Value    []json.RawMessage `json:"value"`
		NextLink string            `json:"@odata.nextLink"`
	}
	next := path
	all := make([]json.RawMessage, 0)
	for next != "" {
		requestURL := c.resolveGraphURL(next)
		body, err := c.doGraphGET(ctx, requestURL)
		if err != nil {
			return nil, err
		}
		var page pageResponse
		if err := json.Unmarshal(body, &page); err != nil {
			return nil, fmt.Errorf("decoding graph response: %w", err)
		}
		all = append(all, page.Value...)
		next = page.NextLink
	}
	return all, nil
}

func rawMessagesToRecords(raws []json.RawMessage) ([]collector.Record, error) {
	records := make([]collector.Record, 0, len(raws))
	for _, raw := range raws {
		var rec collector.Record
		if err := json.Unmarshal(raw, &rec); err != nil {
			return nil, fmt.Errorf("decoding graph record: %w", err)
		}
		records = append(records, rec)
	}
	return records, nil
}

func (c *Client) ListApplications(ctx context.Context) ([]collector.Record, error) {
	raws, err := c.graphGet(ctx, "/applications?$select=id,appId,displayName,signInAudience,requiredResourceAccess,keyCredentials,passwordCredentials")
	if err != nil {
		return nil, err
	}
	return rawMessagesToRecords(raws)
}

func (c *Client) ListServicePrincipals(ctx context.Context) ([]collector.Record, error) {
	raws, err := c.graphGet(ctx, "/servicePrincipals?$select=id,appId,displayName,accountEnabled,appRoleAssignmentRequired,servicePrincipalType,signInActivity,appRoles,publishedPermissionScopes")
	if err != nil {
		return nil, err
	}
	return rawMessagesToRecords(raws)
}

func (c *Client) ListOAuth2PermissionGrants(ctx context.Context) ([]collector.Record, error) {
	raws, err := c.graphGet(ctx, "/oauth2PermissionGrants")
	if err != nil {
		return nil, err
	}
	return rawMessagesToRecords(raws)
}

func (c *Client) ListAppRoleAssignments(ctx context.Context, servicePrincipalID string) ([]collector.Record, error) {
	raws, err := c.graphGet(ctx, "/servicePrincipals/"+url.PathEscape(servicePrincipalID)+"/appRoleAssignments")
	if err != nil {
		return nil, err
	}
	return rawMessagesToRecords(raws)
}

func (c *Client) ListApplicationOwners(ctx context.Context, appObjectID string) ([]collector.Record, error) {
	raws, err := c.graphGet(ctx, "/applications/"+url.PathEscape(appObjectID)+"/owners?$select=id,displayName,userPrincipalName")
	if err != nil {
		return nil, err
	}
	return rawMessagesToRecords(raws)
}

func asSlice(v interface{}) []interface{} {
	if v == nil {
		return nil
	}
	items, _ := v.([]interface{})
	return items
}

func getString(v interface{}) string {
	if v == nil {
		return ""
	}
	s, _ := v.(string)
	return s
}

func credentialsFromApplicationRecord(app collector.Record) []collector.Record {
	appObjectID := getString(app["id"])
	appID := getString(app["appId"])
	appDisplayName := getString(app["displayName"])
	creds := make([]collector.Record, 0)
	for _, item := range asSlice(app["passwordCredentials"]) {
		pc, ok := item.(map[string]interface{})
		if !ok {
			continue
		}
		creds = append(creds, collector.Record{
			"application_object_id": appObjectID,
			"application_app_id":    appID,
			"application_name":      appDisplayName,
			"credential_id":         getString(pc["keyId"]),
			"credential_type":       "password",
			"display_name":          getString(pc["displayName"]),
			"start_date_time":       getString(pc["startDateTime"]),
			"end_date_time":         getString(pc["endDateTime"]),
		})
	}
	for _, item := range asSlice(app["keyCredentials"]) {
		kc, ok := item.(map[string]interface{})
		if !ok {
			continue
		}
		creds = append(creds, collector.Record{
			"application_object_id": appObjectID,
			"application_app_id":    appID,
			"application_name":      appDisplayName,
			"credential_id":         getString(kc["keyId"]),
			"credential_type":       "certificate",
			"display_name":          getString(kc["displayName"]),
			"start_date_time":       getString(kc["startDateTime"]),
			"end_date_time":         getString(kc["endDateTime"]),
		})
	}
	return creds
}

func (c *Client) GetApplicationCredentials(ctx context.Context, appObjectID string) ([]collector.Record, error) {
	body, err := c.doGraphGET(ctx, c.resolveGraphURL("/applications/"+url.PathEscape(appObjectID)+"?$select=id,appId,displayName,keyCredentials,passwordCredentials"))
	if err != nil {
		return nil, err
	}
	var app collector.Record
	if err := json.Unmarshal(body, &app); err != nil {
		return nil, fmt.Errorf("decoding application credentials response: %w", err)
	}
	return credentialsFromApplicationRecord(app), nil
}
