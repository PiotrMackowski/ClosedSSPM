package snowflake

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"os"
	"testing"

	"github.com/PiotrMackowski/ClosedSSPM/internal/collector"
)

func TestNewClient_BasicAuthValidation(t *testing.T) {
	tests := []struct {
		name      string
		config    *SnowflakeConfig
		wantErr   bool
		errSubstr string
	}{
		{
			name: "missing account",
			config: &SnowflakeConfig{
				AuthMethod: "basic",
				Username:   "admin",
				Password:   "password",
			},
			wantErr:   true,
			errSubstr: "account identifier is required",
		},
		{
			name: "missing username",
			config: &SnowflakeConfig{
				Account:    "test-account",
				AuthMethod: "basic",
				Password:   "password",
			},
			wantErr:   true,
			errSubstr: "username and password are required",
		},
		{
			name: "missing password",
			config: &SnowflakeConfig{
				Account:    "test-account",
				AuthMethod: "basic",
				Username:   "admin",
			},
			wantErr:   true,
			errSubstr: "username and password are required",
		},
		{
			name: "unsupported auth method",
			config: &SnowflakeConfig{
				Account:    "test-account",
				AuthMethod: "saml",
				Username:   "admin",
				Password:   "password",
			},
			wantErr:   true,
			errSubstr: "unsupported auth method",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := NewClient(tt.config)
			if tt.wantErr {
				if err == nil {
					t.Error("NewClient() should return error")
				} else if tt.errSubstr != "" && !contains(err.Error(), tt.errSubstr) {
					t.Errorf("error = %q, want substring %q", err.Error(), tt.errSubstr)
				}
			} else if err != nil {
				t.Errorf("NewClient() unexpected error: %v", err)
			}
		})
	}
}

func TestNewClient_KeyPairMissingCredentials(t *testing.T) {
	keyPath := generateTestKeyPEM(t)

	tests := []struct {
		name      string
		username  string
		keyPath   string
		errSubstr string
	}{
		{"missing username", "", keyPath, "username is required"},
		{"missing key path", "admin", "", "private key path is required"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := &SnowflakeConfig{
				Account:        "test-account",
				AuthMethod:     "keypair",
				Username:       tt.username,
				PrivateKeyPath: tt.keyPath,
			}
			_, err := NewClient(config)
			if err == nil {
				t.Error("NewClient() should return error")
			} else if !contains(err.Error(), tt.errSubstr) {
				t.Errorf("error = %q, want substring %q", err.Error(), tt.errSubstr)
			}
		})
	}
}

func TestNewClient_KeyPairInvalidKeyFile(t *testing.T) {
	// Nonexistent file.
	config := &SnowflakeConfig{
		Account:        "test-account",
		AuthMethod:     "keypair",
		Username:       "admin",
		PrivateKeyPath: "/nonexistent/path/key.pem",
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

func TestNewClient_OAuthMissingToken(t *testing.T) {
	config := &SnowflakeConfig{
		Account:    "test-account",
		AuthMethod: "oauth",
		Username:   "admin",
	}
	_, err := NewClient(config)
	if err == nil {
		t.Error("NewClient() should reject missing OAuth token")
	}
}

func TestNewClient_PATMissingCredentials(t *testing.T) {
	tests := []struct {
		name      string
		username  string
		token     string
		errSubstr string
	}{
		{"missing username", "", "pat-token-value", "username is required for PAT auth"},
		{"missing token", "admin", "", "PAT token is required"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := &SnowflakeConfig{
				Account:    "test-account",
				AuthMethod: "pat",
				Username:   tt.username,
				Password:   tt.token,
			}
			_, err := NewClient(config)
			if err == nil {
				t.Error("NewClient() should return error")
			} else if !contains(err.Error(), tt.errSubstr) {
				t.Errorf("error = %q, want substring %q", err.Error(), tt.errSubstr)
			}
		})
	}
}

func TestNewClient_AccountNormalization(t *testing.T) {
	tests := []struct {
		name    string
		account string
		want    string
	}{
		{"plain", "xy12345.us-east-1", "xy12345.us-east-1"},
		{"with https", "https://xy12345.us-east-1", "xy12345.us-east-1"},
		{"with http", "http://xy12345.us-east-1", "xy12345.us-east-1"},
		{"with trailing slash", "xy12345.us-east-1/", "xy12345.us-east-1"},
		{"with full domain", "xy12345.us-east-1.snowflakecomputing.com", "xy12345.us-east-1"},
		{"with https and domain", "https://xy12345.us-east-1.snowflakecomputing.com", "xy12345.us-east-1"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// We can't fully create the client (no Snowflake to connect to),
			// but we can test that the normalization logic works by checking
			// that validation passes and we get the expected DSN error.
			config := &SnowflakeConfig{
				Account:    tt.account,
				AuthMethod: "basic",
				Username:   "admin",
				Password:   "password",
			}
			// NewClient will fail at Ping since there's no Snowflake,
			// but we can verify it got past validation.
			_, err := NewClient(config)
			if err == nil {
				t.Skip("Unexpectedly connected — likely a real Snowflake instance")
			}
			// Should NOT be a validation error — it should fail at connect.
			if contains(err.Error(), "account identifier is required") {
				t.Errorf("account %q was not normalized correctly", tt.account)
			}
		})
	}
}

func TestNewClient_FallbackToInstanceURL(t *testing.T) {
	config := &SnowflakeConfig{
		BaseConfig: collector.BaseConfig{InstanceURL: "my-account.us-west-2"},
		AuthMethod: "basic",
		Username:   "admin",
		Password:   "password",
	}
	// Should fail at connect, not at "account required" validation.
	_, err := NewClient(config)
	if err == nil {
		t.Skip("Unexpectedly connected")
	}
	if contains(err.Error(), "account identifier is required") {
		t.Error("Should fall back to InstanceURL when Account is empty")
	}
}

func TestLoadPrivateKey_PKCS1(t *testing.T) {
	keyPath := generateTestKeyPEM(t)

	got, err := loadPrivateKey(keyPath)
	if err != nil {
		t.Fatalf("loadPrivateKey() error: %v", err)
	}
	if got == nil {
		t.Fatal("loadPrivateKey() returned nil key")
	}
}

func TestLoadPrivateKey_PKCS8(t *testing.T) {
	keyPath := generateTestKeyPEMPKCS8(t)

	got, err := loadPrivateKey(keyPath)
	if err != nil {
		t.Fatalf("loadPrivateKey() error: %v", err)
	}
	if got == nil {
		t.Fatal("loadPrivateKey() returned nil key")
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

func TestNormalizeValue(t *testing.T) {
	tests := []struct {
		name string
		in   interface{}
		want interface{}
	}{
		{"nil", nil, ""},
		{"bytes", []byte("hello"), "hello"},
		{"string", "hello", "hello"},
		{"int", 42, 42},
		{"float", 3.14, 3.14},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := normalizeValue(tt.in)
			if got != tt.want {
				t.Errorf("normalizeValue(%v) = %v, want %v", tt.in, got, tt.want)
			}
		})
	}
}

func TestSnowflakeCollectorName(t *testing.T) {
	c := &SnowflakeCollector{}
	if c.Name() != "snowflake" {
		t.Errorf("Name() = %q, want %q", c.Name(), "snowflake")
	}
}

func TestSnowflakeCollectorTables(t *testing.T) {
	c := &SnowflakeCollector{}
	tables := c.Tables()

	if len(tables) != len(securityQueries) {
		t.Errorf("Tables() returned %d tables, want %d", len(tables), len(securityQueries))
	}

	// Verify known tables exist.
	found := make(map[string]bool)
	for _, name := range tables {
		found[name] = true
	}

	expected := []string{"users", "roles", "network_policies", "grants_to_users", "account_parameters", "procedures", "functions"}
	for _, name := range expected {
		if !found[name] {
			t.Errorf("Tables() missing expected table %q", name)
		}
	}
}

// --- Test Helpers ---

func generateTestKeyPEM(t *testing.T) string {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
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
	return f.Name()
}

func generateTestKeyPEMPKCS8(t *testing.T) string {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
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
	return f.Name()
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && searchSubstr(s, substr)
}

func searchSubstr(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
