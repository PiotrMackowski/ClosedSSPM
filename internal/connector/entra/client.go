package entra

import (
	"context"
	"crypto"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/url"
	"os"
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
	version          = "0.1.0"
	defaultRateLimit = 10.0
	graphV1BaseURL   = "https://graph.microsoft.com/v1.0"
	graphRootURL     = "https://graph.microsoft.com"
)

type Client struct {
	baseURL     string
	tokenURL    string
	httpClient  *http.Client
	rateLimiter *rate.Limiter

	tenantID            string
	clientID            string
	clientSecret        string
	certificatePath     string
	certificatePassword string

	mu    sync.Mutex
	token *httputil.OAuthToken
}

func NewClient(config *EntraConfig) (*Client, error) {
	tenantID := strings.TrimSpace(config.TenantID)
	if tenantID == "" {
		return nil, fmt.Errorf("tenant ID is required")
	}
	clientID := strings.TrimSpace(config.ClientID)
	clientSecret := strings.TrimSpace(config.ClientSecret)
	certificatePath := strings.TrimSpace(config.CertificatePath)
	if clientID == "" || (clientSecret == "" && certificatePath == "") {
		return nil, fmt.Errorf("client_id and either client_secret or certificate_path are required for OAuth")
	}

	rl := config.GetRateLimit()
	if rl <= 0 {
		rl = defaultRateLimit
	}

	transport := &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12}}
	checkRedirect := func(req *http.Request, via []*http.Request) error {
		if len(via) >= httputil.MaxRedirects {
			return fmt.Errorf("exceeded maximum redirects (%d)", httputil.MaxRedirects)
		}
		if len(via) > 0 && req.URL.Host != via[0].URL.Host {
			return fmt.Errorf("redirect to different host %q blocked", req.URL.Host)
		}
		return nil
	}

	return &Client{
		baseURL:             graphV1BaseURL,
		tokenURL:            fmt.Sprintf("https://login.microsoftonline.com/%s/oauth2/v2.0/token", url.PathEscape(tenantID)),
		httpClient:          &http.Client{Timeout: 30 * time.Second, Transport: transport, CheckRedirect: checkRedirect},
		rateLimiter:         rate.NewLimiter(rate.Limit(rl), 1),
		tenantID:            tenantID,
		clientID:            clientID,
		clientSecret:        clientSecret,
		certificatePath:     certificatePath,
		certificatePassword: strings.TrimSpace(config.CertificatePassword),
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

func (c *Client) getOAuthToken(ctx context.Context) (*httputil.OAuthToken, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.token != nil && !c.token.IsExpired() {
		return c.token, nil
	}
	data := url.Values{
		"grant_type": {"client_credentials"},
		"client_id":  {c.clientID},
		"scope":      {"https://graph.microsoft.com/.default"},
	}
	if c.certificatePath != "" {
		assertion, err := buildClientAssertion(c.certificatePath, c.clientID, c.tokenURL)
		if err != nil {
			return nil, fmt.Errorf("building client assertion: %w", err)
		}
		data.Set("client_assertion", assertion)
		data.Set("client_assertion_type", "urn:ietf:params:oauth:client-assertion-type:jwt-bearer")
	} else {
		data.Set("client_secret", c.clientSecret)
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

func buildClientAssertion(certPath, clientID, tokenURL string) (string, error) {
	content, err := os.ReadFile(certPath)
	if err != nil {
		return "", fmt.Errorf("reading certificate file: %w", err)
	}

	var (
		certificate *x509.Certificate
		privateKey  *rsa.PrivateKey
	)

	remaining := content
	for {
		var block *pem.Block
		block, remaining = pem.Decode(remaining)
		if block == nil {
			break
		}

		switch block.Type {
		case "CERTIFICATE":
			if certificate != nil {
				continue
			}
			parsedCert, parseErr := x509.ParseCertificate(block.Bytes)
			if parseErr != nil {
				return "", fmt.Errorf("parsing certificate: %w", parseErr)
			}
			certificate = parsedCert
		case "PRIVATE KEY", "RSA PRIVATE KEY":
			if privateKey != nil {
				continue
			}
			if block.Type == "PRIVATE KEY" {
				parsedKey, parseErr := x509.ParsePKCS8PrivateKey(block.Bytes)
				if parseErr != nil {
					return "", fmt.Errorf("parsing PKCS8 private key: %w", parseErr)
				}
				rsaKey, ok := parsedKey.(*rsa.PrivateKey)
				if !ok {
					return "", fmt.Errorf("private key is not RSA")
				}
				privateKey = rsaKey
			} else {
				parsedKey, parseErr := x509.ParsePKCS1PrivateKey(block.Bytes)
				if parseErr != nil {
					return "", fmt.Errorf("parsing PKCS1 private key: %w", parseErr)
				}
				privateKey = parsedKey
			}
		}
	}

	if certificate == nil || privateKey == nil {
		return "", fmt.Errorf("certificate file must contain PEM certificate and RSA private key (PFX/PKCS12 not supported)")
	}

	now := time.Now().UTC()
	claims := jwt.MapClaims{
		"aud": tokenURL,
		"iss": clientID,
		"sub": clientID,
		"jti": uuid.NewString(),
		"nbf": now.Unix(),
		"exp": now.Add(10 * time.Minute).Unix(),
	}

	thumbprint := sha1.Sum(certificate.Raw)
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["x5t"] = base64.RawURLEncoding.EncodeToString(thumbprint[:])

	var signer crypto.Signer = privateKey
	if _, ok := signer.Public().(*rsa.PublicKey); !ok {
		return "", fmt.Errorf("private key public component is not RSA")
	}

	if privateKey.N == nil || privateKey.N.Sign() <= 0 || privateKey.D == nil || privateKey.D.Cmp(big.NewInt(0)) <= 0 {
		return "", fmt.Errorf("invalid RSA private key")
	}

	signedToken, err := token.SignedString(privateKey)
	if err != nil {
		return "", fmt.Errorf("signing client assertion: %w", err)
	}

	return signedToken, nil
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
		body, _ := httputil.ReadLimitedBody(resp.Body)
		return nil, fmt.Errorf("graph request failed (status %d): %s", resp.StatusCode, httputil.SanitizeErrorBody(body))
	}
	body, err := httputil.ReadLimitedBody(resp.Body)
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
