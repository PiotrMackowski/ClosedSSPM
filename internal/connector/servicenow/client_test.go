package servicenow

import (
	"bytes"
	"context"
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/PiotrMackowski/ClosedSSPM/internal/collector"
)

func TestNewClient_BasicAuth(t *testing.T) {
	config := collector.ConnectorConfig{
		InstanceURL: "https://example.service-now.com",
		AuthMethod:  "basic",
		Username:    "admin",
		Password:    "password123",
	}

	client, err := NewClient(config)
	if err != nil {
		t.Fatalf("NewClient() error: %v", err)
	}

	if client.baseURL != "https://example.service-now.com" {
		t.Errorf("baseURL = %q, want %q", client.baseURL, "https://example.service-now.com")
	}
	if client.authMethod != "basic" {
		t.Errorf("authMethod = %q, want %q", client.authMethod, "basic")
	}
}

func TestNewClient_AutoPrefixHTTPS(t *testing.T) {
	config := collector.ConnectorConfig{
		InstanceURL: "example.service-now.com",
		AuthMethod:  "basic",
		Username:    "admin",
		Password:    "password123",
	}

	client, err := NewClient(config)
	if err != nil {
		t.Fatalf("NewClient() error: %v", err)
	}

	if client.baseURL != "https://example.service-now.com" {
		t.Errorf("baseURL = %q, want %q", client.baseURL, "https://example.service-now.com")
	}
}

func TestNewClient_TrailingSlashRemoved(t *testing.T) {
	config := collector.ConnectorConfig{
		InstanceURL: "https://example.service-now.com/",
		AuthMethod:  "basic",
		Username:    "admin",
		Password:    "password123",
	}

	client, err := NewClient(config)
	if err != nil {
		t.Fatalf("NewClient() error: %v", err)
	}

	if client.baseURL != "https://example.service-now.com" {
		t.Errorf("baseURL = %q, want %q", client.baseURL, "https://example.service-now.com")
	}
}

func TestNewClient_RejectHTTP(t *testing.T) {
	config := collector.ConnectorConfig{
		InstanceURL: "http://example.service-now.com",
		AuthMethod:  "basic",
		Username:    "admin",
		Password:    "password123",
	}

	_, err := NewClient(config)
	if err == nil {
		t.Error("NewClient() should reject HTTP URLs")
	}
}

func TestNewClient_EmptyURL(t *testing.T) {
	config := collector.ConnectorConfig{
		AuthMethod: "basic",
		Username:   "admin",
		Password:   "password123",
	}

	_, err := NewClient(config)
	if err == nil {
		t.Error("NewClient() should reject empty URL")
	}
}

func TestNewClient_BasicAuthMissingCredentials(t *testing.T) {
	tests := []struct {
		name     string
		username string
		password string
	}{
		{"missing both", "", ""},
		{"missing username", "", "password"},
		{"missing password", "admin", ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := collector.ConnectorConfig{
				InstanceURL: "https://example.service-now.com",
				AuthMethod:  "basic",
				Username:    tt.username,
				Password:    tt.password,
			}

			_, err := NewClient(config)
			if err == nil {
				t.Error("NewClient() should reject missing credentials")
			}
		})
	}
}

func TestNewClient_OAuthConfig(t *testing.T) {
	config := collector.ConnectorConfig{
		InstanceURL:  "https://example.service-now.com",
		AuthMethod:   "oauth",
		ClientID:     "client123",
		ClientSecret: "secret456",
	}

	client, err := NewClient(config)
	if err != nil {
		t.Fatalf("NewClient() error: %v", err)
	}

	if client.authMethod != "oauth" {
		t.Errorf("authMethod = %q, want %q", client.authMethod, "oauth")
	}
}

func TestNewClient_OAuthMissingCredentials(t *testing.T) {
	tests := []struct {
		name         string
		clientID     string
		clientSecret string
	}{
		{"missing both", "", ""},
		{"missing client_id", "", "secret"},
		{"missing client_secret", "client", ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := collector.ConnectorConfig{
				InstanceURL:  "https://example.service-now.com",
				AuthMethod:   "oauth",
				ClientID:     tt.clientID,
				ClientSecret: tt.clientSecret,
			}

			_, err := NewClient(config)
			if err == nil {
				t.Error("NewClient() should reject missing OAuth credentials")
			}
		})
	}
}

func TestNewClient_UnsupportedAuthMethod(t *testing.T) {
	config := collector.ConnectorConfig{
		InstanceURL: "https://example.service-now.com",
		AuthMethod:  "saml",
		Username:    "admin",
		Password:    "password",
	}

	_, err := NewClient(config)
	if err == nil {
		t.Error("NewClient() should reject unsupported auth methods")
	}
}

func TestNewClient_DefaultAuthMethod(t *testing.T) {
	config := collector.ConnectorConfig{
		InstanceURL: "https://example.service-now.com",
		Username:    "admin",
		Password:    "password123",
	}

	client, err := NewClient(config)
	if err != nil {
		t.Fatalf("NewClient() error: %v", err)
	}

	if client.authMethod != "basic" {
		t.Errorf("authMethod = %q, want %q (default)", client.authMethod, "basic")
	}
}

func TestNewClient_DefaultRateLimit(t *testing.T) {
	config := collector.ConnectorConfig{
		InstanceURL: "https://example.service-now.com",
		AuthMethod:  "basic",
		Username:    "admin",
		Password:    "password123",
	}

	client, err := NewClient(config)
	if err != nil {
		t.Fatalf("NewClient() error: %v", err)
	}

	if client.rateLimiter == nil {
		t.Error("rateLimiter should be initialized")
	}
	if client.pageSize != defaultPageSize {
		t.Errorf("pageSize = %d, want %d", client.pageSize, defaultPageSize)
	}
}

func TestOAuthTokenIsExpired(t *testing.T) {
	// Not expired.
	token := &OAuthToken{
		AccessToken: "test_token",
		ExpiresIn:   3600,
	}
	// Set expiry far in the future.
	token.expiresAt = token.expiresAt.Add(3600 * 1e9)
	// With zero expiresAt, it's in the past.
	zeroToken := &OAuthToken{}
	if !zeroToken.IsExpired() {
		t.Error("Zero-time token should be expired")
	}
}

func TestServiceNowCollectorName(t *testing.T) {
	c := &ServiceNowCollector{}
	if c.Name() != "servicenow" {
		t.Errorf("Name() = %q, want %q", c.Name(), "servicenow")
	}
}

func TestServiceNowCollectorTables(t *testing.T) {
	c := &ServiceNowCollector{}
	tables := c.Tables()

	if len(tables) != len(securityTables) {
		t.Errorf("Tables() returned %d tables, want %d", len(tables), len(securityTables))
	}

	// Verify first and last table names.
	if tables[0] != "sys_security_acl" {
		t.Errorf("First table = %q, want %q", tables[0], "sys_security_acl")
	}
}

func TestNewClient_TLSMinVersion(t *testing.T) {
	config := collector.ConnectorConfig{
		InstanceURL: "https://example.service-now.com",
		AuthMethod:  "basic",
		Username:    "admin",
		Password:    "password123",
	}

	client, err := NewClient(config)
	if err != nil {
		t.Fatalf("NewClient() error: %v", err)
	}

	transport, ok := client.httpClient.Transport.(*http.Transport)
	if !ok {
		t.Fatal("httpClient.Transport is not *http.Transport")
	}
	if transport.TLSClientConfig == nil {
		t.Fatal("TLSClientConfig is nil")
	}
	if transport.TLSClientConfig.MinVersion != tls.VersionTLS12 {
		t.Errorf("TLS MinVersion = %d, want %d (TLS 1.2)", transport.TLSClientConfig.MinVersion, tls.VersionTLS12)
	}
}

func TestNewClient_RedirectPolicy(t *testing.T) {
	config := collector.ConnectorConfig{
		InstanceURL: "https://example.service-now.com",
		AuthMethod:  "basic",
		Username:    "admin",
		Password:    "password123",
	}

	client, err := NewClient(config)
	if err != nil {
		t.Fatalf("NewClient() error: %v", err)
	}

	if client.httpClient.CheckRedirect == nil {
		t.Error("CheckRedirect should be set")
	}
}

func TestReadLimitedBody(t *testing.T) {
	// Within limit.
	small := bytes.NewReader(make([]byte, 100))
	data, err := readLimitedBody(small)
	if err != nil {
		t.Fatalf("readLimitedBody() error: %v", err)
	}
	if len(data) != 100 {
		t.Errorf("got %d bytes, want 100", len(data))
	}

	// Exceeds limit.
	huge := bytes.NewReader(make([]byte, maxResponseBodySize+1))
	_, err = readLimitedBody(huge)
	if err == nil {
		t.Error("readLimitedBody() should reject bodies exceeding max size")
	}
}

func TestSanitizeErrorBody(t *testing.T) {
	short := "short error message"
	if got := sanitizeErrorBody([]byte(short)); got != short {
		t.Errorf("sanitizeErrorBody(%q) = %q, want %q", short, got, short)
	}

	// Long message should be truncated.
	long := make([]byte, 500)
	for i := range long {
		long[i] = 'x'
	}
	got := sanitizeErrorBody(long)
	if len(got) > 300 {
		t.Errorf("sanitizeErrorBody should truncate long messages, got length %d", len(got))
	}
	if got[len(got)-14:] != "...(truncated)" {
		t.Errorf("sanitizeErrorBody should end with ...(truncated), got %q", got[len(got)-20:])
	}
}

func TestQueryTable_UserAgent(t *testing.T) {
	var gotUserAgent string

	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotUserAgent = r.Header.Get("User-Agent")
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"result":[]}`))
	}))
	defer ts.Close()

	config := collector.ConnectorConfig{
		InstanceURL: ts.URL,
		AuthMethod:  "basic",
		Username:    "admin",
		Password:    "password",
	}

	client, err := NewClient(config)
	if err != nil {
		t.Fatalf("NewClient() error: %v", err)
	}
	// Use the test server's TLS client to trust its self-signed cert.
	client.httpClient = ts.Client()

	_, err = client.QueryTable(context.Background(), "sys_user", nil)
	if err != nil {
		t.Fatalf("QueryTable() error: %v", err)
	}

	if gotUserAgent != "ClosedSSPM/"+version {
		t.Errorf("User-Agent = %q, want %q", gotUserAgent, "ClosedSSPM/"+version)
	}
}

func TestQueryTable_Pagination(t *testing.T) {
	callCount := 0

	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		w.Header().Set("Content-Type", "application/json")
		// First call returns pageSize records (triggers next page), second returns fewer.
		if callCount == 1 {
			w.Write([]byte(`{"result":[{"sys_id":"1"}]}`))
		} else {
			w.Write([]byte(`{"result":[]}`))
		}
	}))
	defer ts.Close()

	config := collector.ConnectorConfig{
		InstanceURL: ts.URL,
		AuthMethod:  "basic",
		Username:    "admin",
		Password:    "password",
	}

	client, err := NewClient(config)
	if err != nil {
		t.Fatalf("NewClient() error: %v", err)
	}
	client.httpClient = ts.Client()
	client.pageSize = 1 // Force pagination after 1 record.

	records, err := client.QueryTable(context.Background(), "sys_user", nil)
	if err != nil {
		t.Fatalf("QueryTable() error: %v", err)
	}

	if len(records) != 1 {
		t.Errorf("got %d records, want 1", len(records))
	}
	if callCount != 2 {
		t.Errorf("expected 2 API calls (pagination), got %d", callCount)
	}
}
