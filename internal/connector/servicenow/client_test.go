package servicenow

import (
	"context"
	crypto_rand "crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/PiotrMackowski/ClosedSSPM/internal/collector"
	"github.com/PiotrMackowski/ClosedSSPM/internal/httputil"
	"github.com/golang-jwt/jwt/v5"
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
	token := &httputil.OAuthToken{
		AccessToken: "test_token",
		ExpiresIn:   3600,
	}
	// Set expiry far in the future.
	token.ExpiresAt = time.Now().Add(1 * time.Hour)
	if token.IsExpired() {
		t.Error("token should not be expired")
	}
	// With zero expiresAt, it's in the past.
	zeroToken := &httputil.OAuthToken{}
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

// --- Key Pair Auth Tests ---

// generateTestKeyPEM creates a temporary PKCS#1 RSA private key PEM file and returns
// the file path and the key. The file is cleaned up automatically by t.TempDir().
func generateTestKeyPEM(t *testing.T) (string, *rsa.PrivateKey) {
	t.Helper()
	key, err := rsa.GenerateKey(crypto_rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generating RSA key: %v", err)
	}
	f, err := os.CreateTemp(t.TempDir(), "test-key-*.pem")
	if err != nil {
		t.Fatalf("creating temp file: %v", err)
	}
	defer f.Close()
	pkcs1Bytes := x509.MarshalPKCS1PrivateKey(key)
	if err := pem.Encode(f, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: pkcs1Bytes}); err != nil {
		t.Fatalf("encoding PEM: %v", err)
	}
	return f.Name(), key
}

// generateTestKeyPEMPKCS8 creates a temporary PKCS#8 RSA private key PEM file.
func generateTestKeyPEMPKCS8(t *testing.T) (string, *rsa.PrivateKey) {
	t.Helper()
	key, err := rsa.GenerateKey(crypto_rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generating RSA key: %v", err)
	}
	f, err := os.CreateTemp(t.TempDir(), "test-key-pkcs8-*.pem")
	if err != nil {
		t.Fatalf("creating temp file: %v", err)
	}
	defer f.Close()
	pkcs8Bytes, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatalf("marshaling PKCS8 key: %v", err)
	}
	if err := pem.Encode(f, &pem.Block{Type: "PRIVATE KEY", Bytes: pkcs8Bytes}); err != nil {
		t.Fatalf("encoding PEM: %v", err)
	}
	return f.Name(), key
}

func TestNewClient_KeyPairConfig(t *testing.T) {
	keyPath, _ := generateTestKeyPEM(t)

	config := collector.ConnectorConfig{
		InstanceURL:    "https://example.service-now.com",
		AuthMethod:     "keypair",
		ClientID:       "client123",
		ClientSecret:   "secret456",
		PrivateKeyPath: keyPath,
		KeyID:          "kid-abc",
		JWTUser:        "svc_user",
	}

	client, err := NewClient(config)
	if err != nil {
		t.Fatalf("NewClient() error: %v", err)
	}

	if client.authMethod != "keypair" {
		t.Errorf("authMethod = %q, want %q", client.authMethod, "keypair")
	}
	if client.privateKey == nil {
		t.Error("privateKey should not be nil")
	}
	if client.keyID != "kid-abc" {
		t.Errorf("keyID = %q, want %q", client.keyID, "kid-abc")
	}
	if client.jwtUser != "svc_user" {
		t.Errorf("jwtUser = %q, want %q", client.jwtUser, "svc_user")
	}
}

func TestNewClient_KeyPairMissingCredentials(t *testing.T) {
	keyPath, _ := generateTestKeyPEM(t)

	tests := []struct {
		name         string
		clientID     string
		clientSecret string
		keyPath      string
		keyID        string
		jwtUser      string
	}{
		{"missing clientID", "", "secret", keyPath, "kid", "user"},
		{"missing clientSecret", "client", "", keyPath, "kid", "user"},
		{"missing privateKeyPath", "client", "secret", "", "kid", "user"},
		{"missing keyID", "client", "secret", keyPath, "", "user"},
		{"missing jwtUser", "client", "secret", keyPath, "kid", ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := collector.ConnectorConfig{
				InstanceURL:    "https://example.service-now.com",
				AuthMethod:     "keypair",
				ClientID:       tt.clientID,
				ClientSecret:   tt.clientSecret,
				PrivateKeyPath: tt.keyPath,
				KeyID:          tt.keyID,
				JWTUser:        tt.jwtUser,
			}

			_, err := NewClient(config)
			if err == nil {
				t.Error("NewClient() should reject missing keypair credentials")
			}
		})
	}
}

func TestNewClient_KeyPairInvalidKeyFile(t *testing.T) {
	// Nonexistent file.
	config := collector.ConnectorConfig{
		InstanceURL:    "https://example.service-now.com",
		AuthMethod:     "keypair",
		ClientID:       "client",
		ClientSecret:   "secret",
		PrivateKeyPath: "/nonexistent/path/key.pem",
		KeyID:          "kid",
		JWTUser:        "user",
	}
	_, err := NewClient(config)
	if err == nil {
		t.Error("NewClient() should reject nonexistent key file")
	}

	// Invalid PEM content.
	badFile, err := os.CreateTemp(t.TempDir(), "bad-key-*.pem")
	if err != nil {
		t.Fatalf("creating temp file: %v", err)
	}
	badFile.WriteString("not a pem")
	badFile.Close()

	config.PrivateKeyPath = badFile.Name()
	_, err = NewClient(config)
	if err == nil {
		t.Error("NewClient() should reject invalid PEM content")
	}
}

func TestLoadPrivateKey_PKCS1(t *testing.T) {
	keyPath, want := generateTestKeyPEM(t)

	got, err := loadPrivateKey(keyPath)
	if err != nil {
		t.Fatalf("loadPrivateKey() error: %v", err)
	}
	if got.N.Cmp(want.N) != 0 {
		t.Error("loaded key does not match generated key")
	}
}

func TestLoadPrivateKey_PKCS8(t *testing.T) {
	keyPath, want := generateTestKeyPEMPKCS8(t)

	got, err := loadPrivateKey(keyPath)
	if err != nil {
		t.Fatalf("loadPrivateKey() error: %v", err)
	}
	if got.N.Cmp(want.N) != 0 {
		t.Error("loaded key does not match generated key")
	}
}

func TestLoadPrivateKey_InvalidPEM(t *testing.T) {
	badFile, err := os.CreateTemp(t.TempDir(), "bad-*.pem")
	if err != nil {
		t.Fatalf("creating temp file: %v", err)
	}
	badFile.WriteString("this is not PEM data")
	badFile.Close()

	_, err = loadPrivateKey(badFile.Name())
	if err == nil {
		t.Error("loadPrivateKey() should reject invalid PEM")
	}
}

func TestLoadPrivateKey_NonexistentFile(t *testing.T) {
	_, err := loadPrivateKey("/nonexistent/path/key.pem")
	if err == nil {
		t.Error("loadPrivateKey() should reject nonexistent file")
	}
}

func TestSignJWT(t *testing.T) {
	_, key := generateTestKeyPEM(t)

	c := &Client{
		clientID:   "test-client-id",
		keyID:      "test-kid",
		jwtUser:    "test-user",
		privateKey: key,
	}

	tokenStr, err := c.signJWT()
	if err != nil {
		t.Fatalf("signJWT() error: %v", err)
	}

	// Parse and validate the JWT.
	parsed, err := jwt.Parse(tokenStr, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			t.Fatalf("unexpected signing method: %v", token.Header["alg"])
		}
		return &key.PublicKey, nil
	})
	if err != nil {
		t.Fatalf("jwt.Parse() error: %v", err)
	}

	// Check header.
	if parsed.Header["alg"] != "RS256" {
		t.Errorf("alg = %v, want RS256", parsed.Header["alg"])
	}
	if parsed.Header["kid"] != "test-kid" {
		t.Errorf("kid = %v, want test-kid", parsed.Header["kid"])
	}

	// Check claims.
	claims, ok := parsed.Claims.(jwt.MapClaims)
	if !ok {
		t.Fatal("could not parse claims")
	}
	if claims["iss"] != "test-client-id" {
		t.Errorf("iss = %v, want test-client-id", claims["iss"])
	}
	if claims["sub"] != "test-user" {
		t.Errorf("sub = %v, want test-user", claims["sub"])
	}

	// aud can be a string or []interface{}
	switch aud := claims["aud"].(type) {
	case string:
		if aud != "test-client-id" {
			t.Errorf("aud = %v, want test-client-id", aud)
		}
	case []interface{}:
		if len(aud) == 0 || aud[0] != "test-client-id" {
			t.Errorf("aud = %v, want [test-client-id]", aud)
		}
	default:
		t.Errorf("aud unexpected type %T", claims["aud"])
	}

	// exp should be ~5 minutes from now.
	if exp, ok := claims["exp"].(float64); ok {
		expTime := time.Unix(int64(exp), 0)
		delta := time.Until(expTime)
		if delta < 4*time.Minute || delta > 6*time.Minute {
			t.Errorf("exp delta = %v, want ~5 minutes", delta)
		}
	} else {
		t.Error("exp claim missing or not a number")
	}

	// jti should be a non-empty UUID.
	if jti, ok := claims["jti"].(string); !ok || jti == "" {
		t.Error("jti claim should be a non-empty string")
	}
}

// newKeyPairTestServer creates a mock OAuth token server that validates the
// JWT bearer grant request and returns a test token.
func newKeyPairTestServer(t *testing.T, wantClientID, wantClientSecret string, callCount *int) *httptest.Server {
	t.Helper()
	return httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		*callCount++
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Errorf("reading request body: %v", err)
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		params := string(body)

		if !strings.Contains(params, "grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Ajwt-bearer") {
			t.Errorf("wrong grant_type in body: %s", params)
		}
		if !strings.Contains(params, "assertion=") {
			t.Error("missing assertion in body")
		}
		if !strings.Contains(params, "client_id="+wantClientID) {
			t.Errorf("wrong client_id in body: %s", params)
		}
		if !strings.Contains(params, "client_secret="+wantClientSecret) {
			t.Errorf("wrong client_secret in body: %s", params)
		}

		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"access_token":"test-kp-token","token_type":"Bearer","expires_in":3600}`))
	}))
}

func TestGetKeyPairToken(t *testing.T) {
	callCount := 0
	ts := newKeyPairTestServer(t, "client123", "secret456", &callCount)
	defer ts.Close()

	_, key := generateTestKeyPEM(t)

	c := &Client{
		baseURL:      ts.URL,
		httpClient:   ts.Client(),
		authMethod:   "keypair",
		clientID:     "client123",
		clientSecret: "secret456",
		privateKey:   key,
		keyID:        "kid-test",
		jwtUser:      "svc_user",
	}

	// First call — should hit the server.
	token, err := c.getKeyPairToken(context.Background())
	if err != nil {
		t.Fatalf("getKeyPairToken() error: %v", err)
	}
	if token.AccessToken != "test-kp-token" {
		t.Errorf("AccessToken = %q, want %q", token.AccessToken, "test-kp-token")
	}
	if callCount != 1 {
		t.Errorf("server call count = %d, want 1", callCount)
	}

	// Second call — should use cached token.
	token2, err := c.getKeyPairToken(context.Background())
	if err != nil {
		t.Fatalf("getKeyPairToken() cached call error: %v", err)
	}
	if token2.AccessToken != "test-kp-token" {
		t.Errorf("cached AccessToken = %q, want %q", token2.AccessToken, "test-kp-token")
	}
	if callCount != 1 {
		t.Errorf("server call count after cache = %d, want 1 (should not call again)", callCount)
	}
}

func TestAuthenticate_KeyPair(t *testing.T) {
	callCount := 0
	ts := newKeyPairTestServer(t, "client123", "secret456", &callCount)
	defer ts.Close()

	_, key := generateTestKeyPEM(t)

	c := &Client{
		baseURL:      ts.URL,
		httpClient:   ts.Client(),
		authMethod:   "keypair",
		clientID:     "client123",
		clientSecret: "secret456",
		privateKey:   key,
		keyID:        "kid-test",
		jwtUser:      "svc_user",
	}

	req, _ := http.NewRequest(http.MethodGet, ts.URL+"/api/now/table/sys_user", nil)
	if err := c.authenticate(context.Background(), req); err != nil {
		t.Fatalf("authenticate() error: %v", err)
	}

	auth := req.Header.Get("Authorization")
	if !strings.HasPrefix(auth, "Bearer ") {
		t.Errorf("Authorization = %q, want prefix 'Bearer '", auth)
	}
	if auth == "Bearer " {
		t.Error("Authorization token should not be empty")
	}
}
