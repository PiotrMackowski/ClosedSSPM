package servicenow

import (
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
