package entra

import (
	"context"
	"crypto/tls"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/PiotrMackowski/ClosedSSPM/internal/collector"
	"github.com/PiotrMackowski/ClosedSSPM/internal/httputil"
)

type rewriteTransport struct {
	base   http.RoundTripper
	target *url.URL
}

func (t *rewriteTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	clone := req.Clone(req.Context())
	clone.URL.Scheme = t.target.Scheme
	clone.URL.Host = t.target.Host
	clone.Host = t.target.Host
	return t.base.RoundTrip(clone)
}

func testHTTPClientForServer(ts *httptest.Server) *http.Client {
	parsed, _ := url.Parse(ts.URL)
	base := ts.Client().Transport
	return &http.Client{
		Timeout: 30 * time.Second,
		Transport: &rewriteTransport{
			base:   base,
			target: parsed,
		},
	}
}

func TestNewClient_ValidConfig(t *testing.T) {
	config := collector.ConnectorConfig{
		Account:      "tenant-id",
		ClientID:     "client-id",
		ClientSecret: "client-secret",
	}

	client, err := NewClient(config)
	if err != nil {
		t.Fatalf("NewClient() error: %v", err)
	}

	if client.tenantID != "tenant-id" {
		t.Errorf("tenantID = %q, want %q", client.tenantID, "tenant-id")
	}
	if client.clientID != "client-id" {
		t.Errorf("clientID = %q, want %q", client.clientID, "client-id")
	}
	if client.clientSecret != "client-secret" {
		t.Errorf("clientSecret = %q, want %q", client.clientSecret, "client-secret")
	}
}

func TestNewClient_MissingTenantID(t *testing.T) {
	_, err := NewClient(collector.ConnectorConfig{ClientID: "client-id", ClientSecret: "client-secret"})
	if err == nil {
		t.Fatal("expected error for missing tenant ID")
	}
}

func TestNewClient_MissingClientID(t *testing.T) {
	_, err := NewClient(collector.ConnectorConfig{Account: "tenant-id", ClientSecret: "client-secret"})
	if err == nil {
		t.Fatal("expected error for missing client ID")
	}
}

func TestNewClient_MissingClientSecret(t *testing.T) {
	_, err := NewClient(collector.ConnectorConfig{Account: "tenant-id", ClientID: "client-id"})
	if err == nil {
		t.Fatal("expected error for missing client secret")
	}
}

func TestOAuthTokenIsExpired(t *testing.T) {
	if !(&httputil.OAuthToken{}).IsExpired() {
		t.Fatal("zero-value token should be expired")
	}

	notExpired := &httputil.OAuthToken{ExpiresAt: time.Now().Add(5 * time.Minute)}
	if notExpired.IsExpired() {
		t.Fatal("token should not be expired")
	}

	withinBuffer := &httputil.OAuthToken{ExpiresAt: time.Now().Add(30 * time.Second)}
	if !withinBuffer.IsExpired() {
		t.Fatal("token inside 60-second buffer should be treated as expired")
	}
}

func TestNewClient_TLSMinVersion(t *testing.T) {
	client, err := NewClient(collector.ConnectorConfig{Account: "tenant-id", ClientID: "client-id", ClientSecret: "client-secret"})
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
		t.Errorf("TLS MinVersion = %d, want %d", transport.TLSClientConfig.MinVersion, tls.VersionTLS12)
	}
}

func TestNewClient_RedirectPolicy(t *testing.T) {
	client, err := NewClient(collector.ConnectorConfig{Account: "tenant-id", ClientID: "client-id", ClientSecret: "client-secret"})
	if err != nil {
		t.Fatalf("NewClient() error: %v", err)
	}

	if client.httpClient.CheckRedirect == nil {
		t.Fatal("CheckRedirect should be set")
	}
}

func TestGetOAuthToken_WithTLSServer(t *testing.T) {
	var calls int32

	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		if !strings.HasSuffix(r.URL.Path, "/oauth2/v2.0/token") {
			w.WriteHeader(http.StatusNotFound)
			return
		}

		atomic.AddInt32(&calls, 1)
		body, _ := io.ReadAll(r.Body)
		encoded := string(body)
		if !strings.Contains(encoded, "grant_type=client_credentials") {
			t.Fatalf("missing grant_type in token request body: %s", encoded)
		}
		if !strings.Contains(encoded, "scope=https%3A%2F%2Fgraph.microsoft.com%2F.default") {
			t.Fatalf("missing scope in token request body: %s", encoded)
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"access_token":"token-1","token_type":"Bearer","expires_in":3600}`))
	}))
	defer ts.Close()

	client, err := NewClient(collector.ConnectorConfig{Account: "tenant-id", ClientID: "client-id", ClientSecret: "client-secret"})
	if err != nil {
		t.Fatalf("NewClient() error: %v", err)
	}
	client.httpClient = testHTTPClientForServer(ts)

	token, err := client.getOAuthToken(context.Background())
	if err != nil {
		t.Fatalf("getOAuthToken() error: %v", err)
	}
	if token.AccessToken != "token-1" {
		t.Fatalf("AccessToken = %q, want %q", token.AccessToken, "token-1")
	}
	if atomic.LoadInt32(&calls) != 1 {
		t.Fatalf("token endpoint called %d times, want 1", atomic.LoadInt32(&calls))
	}
}

func TestGraphGet_Pagination(t *testing.T) {
	var graphCalls int32

	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/oauth2/v2.0/token") {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"access_token":"token","token_type":"Bearer","expires_in":3600}`))
			return
		}

		if r.URL.Path == "/v1.0/applications" && strings.Contains(r.URL.RawQuery, "$select=") {
			atomic.AddInt32(&graphCalls, 1)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"value":[{"id":"1"}],"@odata.nextLink":"https://graph.microsoft.com/v1.0/applications?$skiptoken=next"}`))
			return
		}

		if r.URL.Path == "/v1.0/applications" && r.URL.RawQuery == "$skiptoken=next" {
			atomic.AddInt32(&graphCalls, 1)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"value":[{"id":"2"}]}`))
			return
		}

		w.WriteHeader(http.StatusNotFound)
	}))
	defer ts.Close()

	client, err := NewClient(collector.ConnectorConfig{Account: "tenant-id", ClientID: "client-id", ClientSecret: "client-secret"})
	if err != nil {
		t.Fatalf("NewClient() error: %v", err)
	}
	client.httpClient = testHTTPClientForServer(ts)

	records, err := client.ListApplications(context.Background())
	if err != nil {
		t.Fatalf("ListApplications() error: %v", err)
	}
	if len(records) != 2 {
		t.Fatalf("ListApplications() returned %d records, want 2", len(records))
	}
	if atomic.LoadInt32(&graphCalls) != 2 {
		t.Fatalf("graph endpoint called %d times, want 2", atomic.LoadInt32(&graphCalls))
	}
}

func TestAuthenticate_SetsBearerHeader(t *testing.T) {
	client, err := NewClient(collector.ConnectorConfig{Account: "tenant-id", ClientID: "client-id", ClientSecret: "client-secret"})
	if err != nil {
		t.Fatalf("NewClient() error: %v", err)
	}
	client.token = &httputil.OAuthToken{AccessToken: "seed-token", ExpiresAt: time.Now().Add(10 * time.Minute)}

	req, err := http.NewRequest(http.MethodGet, "https://graph.microsoft.com/v1.0/applications", nil)
	if err != nil {
		t.Fatalf("http.NewRequest() error: %v", err)
	}

	if err := client.authenticate(context.Background(), req); err != nil {
		t.Fatalf("authenticate() error: %v", err)
	}

	if got := req.Header.Get("Authorization"); got != "Bearer seed-token" {
		t.Fatalf("Authorization = %q, want %q", got, "Bearer seed-token")
	}
}

func TestGetOAuthToken_Caching(t *testing.T) {
	var calls int32

	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasSuffix(r.URL.Path, "/oauth2/v2.0/token") {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		atomic.AddInt32(&calls, 1)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"access_token":"cached","token_type":"Bearer","expires_in":3600}`))
	}))
	defer ts.Close()

	client, err := NewClient(collector.ConnectorConfig{Account: "tenant-id", ClientID: "client-id", ClientSecret: "client-secret"})
	if err != nil {
		t.Fatalf("NewClient() error: %v", err)
	}
	client.httpClient = testHTTPClientForServer(ts)

	_, err = client.getOAuthToken(context.Background())
	if err != nil {
		t.Fatalf("first getOAuthToken() error: %v", err)
	}
	_, err = client.getOAuthToken(context.Background())
	if err != nil {
		t.Fatalf("second getOAuthToken() error: %v", err)
	}

	if atomic.LoadInt32(&calls) != 1 {
		t.Fatalf("token endpoint called %d times, want 1", atomic.LoadInt32(&calls))
	}
}

func TestListServicePrincipals(t *testing.T) {
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/oauth2/v2.0/token") {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"access_token":"token","token_type":"Bearer","expires_in":3600}`))
			return
		}
		if r.URL.Path == "/v1.0/servicePrincipals" {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"value":[{"id":"sp1","displayName":"SP One"}]}`))
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer ts.Close()

	client, err := NewClient(collector.ConnectorConfig{Account: "tenant-id", ClientID: "client-id", ClientSecret: "client-secret"})
	if err != nil {
		t.Fatalf("NewClient() error: %v", err)
	}
	client.httpClient = testHTTPClientForServer(ts)

	records, err := client.ListServicePrincipals(context.Background())
	if err != nil {
		t.Fatalf("ListServicePrincipals() error: %v", err)
	}
	if len(records) != 1 {
		t.Fatalf("ListServicePrincipals() returned %d records, want 1", len(records))
	}
	if records[0]["id"] != "sp1" {
		t.Fatalf("id = %v, want sp1", records[0]["id"])
	}
}

func TestListOAuth2PermissionGrants(t *testing.T) {
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/oauth2/v2.0/token") {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"access_token":"token","token_type":"Bearer","expires_in":3600}`))
			return
		}
		if r.URL.Path == "/v1.0/oauth2PermissionGrants" {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"value":[{"id":"grant1","consentType":"AllPrincipals"}]}`))
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer ts.Close()

	client, err := NewClient(collector.ConnectorConfig{Account: "tenant-id", ClientID: "client-id", ClientSecret: "client-secret"})
	if err != nil {
		t.Fatalf("NewClient() error: %v", err)
	}
	client.httpClient = testHTTPClientForServer(ts)

	records, err := client.ListOAuth2PermissionGrants(context.Background())
	if err != nil {
		t.Fatalf("ListOAuth2PermissionGrants() error: %v", err)
	}
	if len(records) != 1 {
		t.Fatalf("ListOAuth2PermissionGrants() returned %d records, want 1", len(records))
	}
	if records[0]["id"] != "grant1" {
		t.Fatalf("id = %v, want grant1", records[0]["id"])
	}
}

func TestListApplications_Non200(t *testing.T) {
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/oauth2/v2.0/token") {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"access_token":"token","token_type":"Bearer","expires_in":3600}`))
			return
		}
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`{"error":"forbidden"}`))
	}))
	defer ts.Close()

	client, err := NewClient(collector.ConnectorConfig{Account: "tenant-id", ClientID: "client-id", ClientSecret: "client-secret"})
	if err != nil {
		t.Fatalf("NewClient() error: %v", err)
	}
	client.httpClient = testHTTPClientForServer(ts)

	_, err = client.ListApplications(context.Background())
	if err == nil {
		t.Fatal("expected error for non-200 graph response")
	}
	if !strings.Contains(err.Error(), "status 403") {
		t.Fatalf("unexpected error: %v", err)
	}
}
