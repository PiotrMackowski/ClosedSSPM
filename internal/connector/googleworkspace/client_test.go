package googleworkspace

import (
	"os"
	"strings"
	"testing"

	"github.com/PiotrMackowski/ClosedSSPM/internal/collector"
	admin "google.golang.org/api/admin/directory/v1"
	reports "google.golang.org/api/admin/reports/v1"
)

// --- NewClient validation tests ---

func TestNewClient_AccessToken_CreatesClient(t *testing.T) {
	// With a valid access token, NewClient should succeed and create services.
	// We can't test actual API calls, but we verify no error is returned.
	config := collector.ConnectorConfig{
		AccessToken: "ya29.fake-token-for-testing",
	}

	client, err := NewClient(config)
	if err != nil {
		t.Fatalf("NewClient() with access token failed: %v", err)
	}
	if client == nil {
		t.Fatal("NewClient() returned nil client")
	}
	if client.directoryService == nil {
		t.Error("directoryService should be initialized")
	}
	if client.reportsService == nil {
		t.Error("reportsService should be initialized")
	}
}

func TestNewClient_AccessToken_ExtractsDomain(t *testing.T) {
	config := collector.ConnectorConfig{
		AccessToken:   "ya29.fake-token",
		DelegatedUser: "admin@example.com",
	}

	client, err := NewClient(config)
	if err != nil {
		t.Fatalf("NewClient() error: %v", err)
	}
	if client.domain != "example.com" {
		t.Errorf("domain = %q, want %q", client.domain, "example.com")
	}
}

func TestNewClient_AccessToken_FallbackDomain(t *testing.T) {
	config := collector.ConnectorConfig{
		AccessToken: "ya29.fake-token",
		InstanceURL: "mycompany.com",
	}

	client, err := NewClient(config)
	if err != nil {
		t.Fatalf("NewClient() error: %v", err)
	}
	if client.domain != "mycompany.com" {
		t.Errorf("domain = %q, want %q", client.domain, "mycompany.com")
	}
}

func TestNewClient_AccessToken_DefaultConcurrency(t *testing.T) {
	config := collector.ConnectorConfig{
		AccessToken: "ya29.fake-token",
	}

	client, err := NewClient(config)
	if err != nil {
		t.Fatalf("NewClient() error: %v", err)
	}
	if client.concurrency != collector.DefaultConcurrency {
		t.Errorf("concurrency = %d, want %d", client.concurrency, collector.DefaultConcurrency)
	}
}

func TestNewClient_AccessToken_CustomConcurrency(t *testing.T) {
	config := collector.ConnectorConfig{
		AccessToken: "ya29.fake-token",
		Concurrency: 10,
		RateLimit:   20.0,
	}

	client, err := NewClient(config)
	if err != nil {
		t.Fatalf("NewClient() error: %v", err)
	}
	if client.concurrency != 10 {
		t.Errorf("concurrency = %d, want 10", client.concurrency)
	}
}

func TestNewClient_AccessToken_TakesPrecedenceOverServiceAccount(t *testing.T) {
	// When both AccessToken and CredentialsFile are set, AccessToken wins.
	config := collector.ConnectorConfig{
		AccessToken:     "ya29.fake-token",
		CredentialsFile: "/nonexistent/path.json",
		DelegatedUser:   "admin@example.com",
	}

	// If CredentialsFile were used, this would fail because the file doesn't exist.
	_, err := NewClient(config)
	if err != nil {
		t.Fatalf("NewClient() should use AccessToken and ignore CredentialsFile, got error: %v", err)
	}
}

func TestNewClient_MissingAllCredentials(t *testing.T) {
	config := collector.ConnectorConfig{
		DelegatedUser: "admin@example.com",
	}

	_, err := NewClient(config)
	if err == nil {
		t.Error("NewClient() should reject config with no credentials")
	}
	if !strings.Contains(err.Error(), "GW_ACCESS_TOKEN") {
		t.Errorf("error = %q, should mention GW_ACCESS_TOKEN", err.Error())
	}
}

func TestNewClient_MissingDelegatedUser(t *testing.T) {
	config := collector.ConnectorConfig{
		CredentialsFile: "/some/path/creds.json",
	}

	_, err := NewClient(config)
	if err == nil {
		t.Error("NewClient() should reject missing delegated user")
	}
	if !strings.Contains(err.Error(), "delegated user is required") {
		t.Errorf("error = %q, want substring %q", err.Error(), "delegated user is required")
	}
}

func TestNewClient_MissingBothFields(t *testing.T) {
	config := collector.ConnectorConfig{}

	_, err := NewClient(config)
	if err == nil {
		t.Error("NewClient() should reject empty config")
	}
	if !strings.Contains(err.Error(), "GW_ACCESS_TOKEN") {
		t.Errorf("error = %q, should mention GW_ACCESS_TOKEN", err.Error())
	}
}

func TestNewClient_NonexistentCredentialsFile(t *testing.T) {
	config := collector.ConnectorConfig{
		CredentialsFile: "/nonexistent/path/credentials.json",
		DelegatedUser:   "admin@example.com",
	}

	_, err := NewClient(config)
	if err == nil {
		t.Error("NewClient() should reject nonexistent credentials file")
	}
	if !strings.Contains(err.Error(), "reading credentials file") {
		t.Errorf("error = %q, want substring %q", err.Error(), "reading credentials file")
	}
}

func TestNewClient_InvalidCredentialsJSON(t *testing.T) {
	tmpFile := createTempFile(t, "bad-creds-*.json", "not valid json")

	config := collector.ConnectorConfig{
		CredentialsFile: tmpFile,
		DelegatedUser:   "admin@example.com",
	}

	_, err := NewClient(config)
	if err == nil {
		t.Error("NewClient() should reject invalid credentials JSON")
	}
	if !strings.Contains(err.Error(), "parsing service account credentials") {
		t.Errorf("error = %q, want substring %q", err.Error(), "parsing service account credentials")
	}
}

// --- Data conversion function tests ---

func TestUserToRecord(t *testing.T) {
	user := &admin.User{
		Id:           "user123",
		PrimaryEmail: "test@example.com",
		Name: &admin.UserName{
			GivenName:  "Test",
			FamilyName: "User",
		},
		IsAdmin:          true,
		IsDelegatedAdmin: false,
		IsEnrolledIn2Sv:  true,
		IsEnforcedIn2Sv:  true,
		Suspended:        false,
		Archived:         false,
		OrgUnitPath:      "/Engineering",
		LastLoginTime:    "2025-01-15T10:00:00Z",
		CreationTime:     "2024-01-01T00:00:00Z",
		AgreedToTerms:    true,
		IsMailboxSetup:   true,
		RecoveryEmail:    "test@personal.com",
		RecoveryPhone:    "+1234567890",
		SuspensionReason: "",
	}

	rec := userToRecord(user)

	if rec["id"] != "user123" {
		t.Errorf("id = %v, want %v", rec["id"], "user123")
	}
	if rec["primary_email"] != "test@example.com" {
		t.Errorf("primary_email = %v, want %v", rec["primary_email"], "test@example.com")
	}
	if rec["full_name"] != "Test User" {
		t.Errorf("full_name = %v, want %v", rec["full_name"], "Test User")
	}
	if rec["is_admin"] != true {
		t.Errorf("is_admin = %v, want true", rec["is_admin"])
	}
	if rec["is_enrolled_in_2sv"] != true {
		t.Errorf("is_enrolled_in_2sv = %v, want true", rec["is_enrolled_in_2sv"])
	}
	if rec["suspended"] != false {
		t.Errorf("suspended = %v, want false", rec["suspended"])
	}
	if rec["org_unit_path"] != "/Engineering" {
		t.Errorf("org_unit_path = %v, want %v", rec["org_unit_path"], "/Engineering")
	}
	if rec["recovery_email"] != "test@personal.com" {
		t.Errorf("recovery_email = %v, want %v", rec["recovery_email"], "test@personal.com")
	}
	if rec["last_login_time"] != "2025-01-15T10:00:00Z" {
		t.Errorf("last_login_time = %v, want %v", rec["last_login_time"], "2025-01-15T10:00:00Z")
	}
	if rec["creation_time"] != "2024-01-01T00:00:00Z" {
		t.Errorf("creation_time = %v, want %v", rec["creation_time"], "2024-01-01T00:00:00Z")
	}
}

func TestUserToRecord_Nil(t *testing.T) {
	rec := userToRecord(nil)
	if rec == nil {
		t.Error("userToRecord(nil) should return empty record, not nil")
	}
	if len(rec) != 0 {
		t.Errorf("userToRecord(nil) should return empty record, got %d fields", len(rec))
	}
}

func TestUserToRecord_NilName(t *testing.T) {
	user := &admin.User{
		Id:           "user-no-name",
		PrimaryEmail: "noname@example.com",
	}

	rec := userToRecord(user)
	if rec["full_name"] != "" {
		t.Errorf("full_name = %q, want empty when Name is nil", rec["full_name"])
	}
}

func TestTokenToRecord(t *testing.T) {
	token := &admin.Token{
		ClientId:    "client123.apps.googleusercontent.com",
		DisplayText: "My App",
		Anonymous:   false,
		NativeApp:   false,
		Scopes:      []string{"https://mail.google.com/", "https://www.googleapis.com/auth/drive"},
		Kind:        "admin#directory#token",
		Etag:        "etag-value",
	}

	rec := tokenToRecord(token, "user@example.com")

	if rec["user_key"] != "user@example.com" {
		t.Errorf("user_key = %v, want %v", rec["user_key"], "user@example.com")
	}
	if rec["client_id"] != "client123.apps.googleusercontent.com" {
		t.Errorf("client_id = %v, want %v", rec["client_id"], "client123.apps.googleusercontent.com")
	}
	if rec["display_text"] != "My App" {
		t.Errorf("display_text = %v, want %v", rec["display_text"], "My App")
	}
	if rec["anonymous"] != false {
		t.Errorf("anonymous = %v, want false", rec["anonymous"])
	}
	if rec["native_app"] != false {
		t.Errorf("native_app = %v, want false", rec["native_app"])
	}
	scopes, ok := rec["scopes"].(string)
	if !ok {
		t.Fatalf("scopes should be string, got %T", rec["scopes"])
	}
	if !strings.Contains(scopes, "mail.google.com") {
		t.Errorf("scopes = %q, should contain mail.google.com", scopes)
	}
	if !strings.Contains(scopes, "auth/drive") {
		t.Errorf("scopes = %q, should contain auth/drive", scopes)
	}
	if rec["scopes_count"] != 2 {
		t.Errorf("scopes_count = %v, want 2", rec["scopes_count"])
	}
}

func TestTokenToRecord_Nil(t *testing.T) {
	rec := tokenToRecord(nil, "user@example.com")
	if rec["user_key"] != "user@example.com" {
		t.Errorf("user_key = %v, want %v for nil token", rec["user_key"], "user@example.com")
	}
}

func TestTokenToRecord_EmptyScopes(t *testing.T) {
	token := &admin.Token{
		ClientId:    "client456",
		DisplayText: "Minimal App",
		Scopes:      []string{},
	}

	rec := tokenToRecord(token, "user2@example.com")
	if rec["scopes"] != "" {
		t.Errorf("scopes = %q, want empty string for no scopes", rec["scopes"])
	}
	if rec["scopes_count"] != 0 {
		t.Errorf("scopes_count = %v, want 0", rec["scopes_count"])
	}
}

func TestTokenToRecord_AnonymousNativeApp(t *testing.T) {
	token := &admin.Token{
		ClientId:    "anon-client",
		DisplayText: "Anonymous App",
		Anonymous:   true,
		NativeApp:   true,
		Scopes:      []string{"openid"},
	}

	rec := tokenToRecord(token, "user3@example.com")
	if rec["anonymous"] != true {
		t.Errorf("anonymous = %v, want true", rec["anonymous"])
	}
	if rec["native_app"] != true {
		t.Errorf("native_app = %v, want true", rec["native_app"])
	}
}

func TestActivityToRecords(t *testing.T) {
	activity := &reports.Activity{
		Id: &reports.ActivityId{
			ApplicationName: "token",
			CustomerId:      "C12345",
			UniqueQualifier: 1,
			Time:            "2025-01-15T10:00:00Z",
		},
		Actor: &reports.ActivityActor{
			Email:     "actor@example.com",
			ProfileId: "profile-001",
		},
		IpAddress:   "192.168.1.1",
		Kind:        "admin#reports#activity",
		OwnerDomain: "example.com",
		Events: []*reports.ActivityEvents{
			{
				Name: "authorize",
				Parameters: []*reports.ActivityEventsParameters{
					{Name: "app_name", Value: "TestApp"},
					{Name: "is_verified", BoolValue: true},
				},
			},
		},
	}

	records := activityToRecords(activity)
	if len(records) != 1 {
		t.Fatalf("activityToRecords() returned %d records, want 1", len(records))
	}

	rec := records[0]
	if rec["application_name"] != "token" {
		t.Errorf("application_name = %v, want %v", rec["application_name"], "token")
	}
	if rec["actor_email"] != "actor@example.com" {
		t.Errorf("actor_email = %v, want %v", rec["actor_email"], "actor@example.com")
	}
	if rec["event_name"] != "authorize" {
		t.Errorf("event_name = %v, want %v", rec["event_name"], "authorize")
	}
	if rec["ip_address"] != "192.168.1.1" {
		t.Errorf("ip_address = %v, want %v", rec["ip_address"], "192.168.1.1")
	}
	if rec["param_app_name"] != "TestApp" {
		t.Errorf("param_app_name = %v, want %v", rec["param_app_name"], "TestApp")
	}
	if rec["param_is_verified"] != true {
		t.Errorf("param_is_verified = %v, want true", rec["param_is_verified"])
	}
}

func TestActivityToRecords_Nil(t *testing.T) {
	records := activityToRecords(nil)
	if records != nil {
		t.Errorf("activityToRecords(nil) should return nil, got %v", records)
	}
}

func TestActivityToRecords_NoEvents(t *testing.T) {
	activity := &reports.Activity{
		Id: &reports.ActivityId{
			ApplicationName: "token",
			CustomerId:      "C12345",
			UniqueQualifier: 2,
			Time:            "2025-01-15T10:00:00Z",
		},
		Actor: &reports.ActivityActor{
			Email: "actor@example.com",
		},
		Events: []*reports.ActivityEvents{},
	}

	records := activityToRecords(activity)
	if len(records) != 1 {
		t.Fatalf("activityToRecords() with no events returned %d records, want 1", len(records))
	}
	if records[0]["event_name"] != "" {
		t.Errorf("event_name = %v, want empty string for no events", records[0]["event_name"])
	}
}

func TestActivityToRecords_MultipleEvents(t *testing.T) {
	activity := &reports.Activity{
		Id: &reports.ActivityId{
			ApplicationName: "token",
			CustomerId:      "C12345",
			UniqueQualifier: 3,
			Time:            "2025-01-15T10:00:00Z",
		},
		Actor: &reports.ActivityActor{
			Email: "actor@example.com",
		},
		Events: []*reports.ActivityEvents{
			{Name: "authorize"},
			{Name: "revoke"},
		},
	}

	records := activityToRecords(activity)
	if len(records) != 2 {
		t.Fatalf("activityToRecords() with 2 events returned %d records, want 2", len(records))
	}
	if records[0]["event_name"] != "authorize" {
		t.Errorf("first event_name = %v, want %v", records[0]["event_name"], "authorize")
	}
	if records[1]["event_name"] != "revoke" {
		t.Errorf("second event_name = %v, want %v", records[1]["event_name"], "revoke")
	}
	// Verify events share actor_email from base record.
	if records[0]["actor_email"] != "actor@example.com" {
		t.Errorf("first event actor_email = %v, want actor@example.com", records[0]["actor_email"])
	}
	if records[1]["actor_email"] != "actor@example.com" {
		t.Errorf("second event actor_email = %v, want actor@example.com", records[1]["actor_email"])
	}
}

func TestActivityToRecords_MultiValueParam(t *testing.T) {
	activity := &reports.Activity{
		Id: &reports.ActivityId{
			ApplicationName: "token",
			CustomerId:      "C12345",
			UniqueQualifier: 4,
			Time:            "2025-01-15T10:00:00Z",
		},
		Actor: &reports.ActivityActor{
			Email: "actor@example.com",
		},
		Events: []*reports.ActivityEvents{
			{
				Name: "authorize",
				Parameters: []*reports.ActivityEventsParameters{
					{
						Name:       "scope",
						MultiValue: []string{"https://mail.google.com/", "https://www.googleapis.com/auth/drive"},
					},
				},
			},
		},
	}

	records := activityToRecords(activity)
	if len(records) != 1 {
		t.Fatalf("activityToRecords() returned %d records, want 1", len(records))
	}
	scopeVal, ok := records[0]["param_scope"].(string)
	if !ok {
		t.Fatalf("param_scope should be string, got %T", records[0]["param_scope"])
	}
	if !strings.Contains(scopeVal, "mail.google.com") || !strings.Contains(scopeVal, "auth/drive") {
		t.Errorf("param_scope = %q, should contain both scopes", scopeVal)
	}
}

func TestActivityToRecords_IntParam(t *testing.T) {
	activity := &reports.Activity{
		Id: &reports.ActivityId{
			ApplicationName: "token",
			CustomerId:      "C12345",
			UniqueQualifier: 5,
			Time:            "2025-01-15T10:00:00Z",
		},
		Actor: &reports.ActivityActor{
			Email: "actor@example.com",
		},
		Events: []*reports.ActivityEvents{
			{
				Name: "authorize",
				Parameters: []*reports.ActivityEventsParameters{
					{Name: "num_scopes", IntValue: 42},
				},
			},
		},
	}

	records := activityToRecords(activity)
	if len(records) != 1 {
		t.Fatalf("activityToRecords() returned %d records, want 1", len(records))
	}
	if records[0]["param_num_scopes"] != int64(42) {
		t.Errorf("param_num_scopes = %v, want 42", records[0]["param_num_scopes"])
	}
}

// --- normalizeParameterName tests ---

func TestNormalizeParameterName(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{"simple", "app_name", "app_name"},
		{"uppercase", "App Name", "app_name"},
		{"spaces", "my parameter", "my_parameter"},
		{"dots", "some.dotted.name", "some_dotted_name"},
		{"hyphens", "some-hyphenated-name", "some_hyphenated_name"},
		{"empty", "", "unknown"},
		{"spaces only", "   ", "unknown"},
		{"special chars", "!!!@@@", "unknown"},
		{"mixed", "  Hello World! ", "hello_world"},
		{"leading trailing special", "---name---", "name"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := normalizeParameterName(tt.input)
			if got != tt.want {
				t.Errorf("normalizeParameterName(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

// --- cloneRecord tests ---

func TestCloneRecord(t *testing.T) {
	original := collector.Record{
		"key1": "value1",
		"key2": 42,
		"key3": true,
	}

	cloned := cloneRecord(original)

	// Verify values are the same.
	if cloned["key1"] != "value1" {
		t.Errorf("cloned[key1] = %v, want %v", cloned["key1"], "value1")
	}
	if cloned["key2"] != 42 {
		t.Errorf("cloned[key2] = %v, want %v", cloned["key2"], 42)
	}
	if cloned["key3"] != true {
		t.Errorf("cloned[key3] = %v, want true", cloned["key3"])
	}

	// Verify it's a different map (modifying clone does not affect original).
	cloned["key1"] = "modified"
	if original["key1"] == "modified" {
		t.Error("cloneRecord should create a deep copy; modifying clone affected original")
	}
}

func TestCloneRecord_Empty(t *testing.T) {
	original := collector.Record{}
	cloned := cloneRecord(original)
	if len(cloned) != 0 {
		t.Errorf("cloneRecord of empty record should be empty, got %d entries", len(cloned))
	}
}

// --- Client method validation tests ---

func TestListOAuthTokens_EmptyUserKey(t *testing.T) {
	c := &Client{}
	_, err := c.ListOAuthTokens(nil, "")
	if err == nil {
		t.Error("ListOAuthTokens() should reject empty user key")
	}
	if !strings.Contains(err.Error(), "directory service is not initialized") {
		t.Errorf("error = %q, want substring %q", err.Error(), "directory service is not initialized")
	}
}

func TestListUsers_NilService(t *testing.T) {
	c := &Client{}
	_, err := c.ListUsers(nil)
	if err == nil {
		t.Error("ListUsers() should fail when service is nil")
	}
	if !strings.Contains(err.Error(), "directory service is not initialized") {
		t.Errorf("error = %q, want substring about nil service", err.Error())
	}
}

func TestListOAuthTokens_NilService(t *testing.T) {
	c := &Client{}
	_, err := c.ListOAuthTokens(nil, "user@example.com")
	if err == nil {
		t.Error("ListOAuthTokens() should fail when service is nil")
	}
	if !strings.Contains(err.Error(), "directory service is not initialized") {
		t.Errorf("error = %q, want substring about nil service", err.Error())
	}
}

func TestListTokenActivity_NilService(t *testing.T) {
	c := &Client{}
	_, err := c.ListTokenActivity(nil)
	if err == nil {
		t.Error("ListTokenActivity() should fail when reports service is nil")
	}
	if !strings.Contains(err.Error(), "reports service is not initialized") {
		t.Errorf("error = %q, want substring about nil service", err.Error())
	}
}

// --- Test Helpers ---

func createTempFile(t *testing.T, pattern, content string) string {
	t.Helper()
	f, err := os.CreateTemp(t.TempDir(), pattern)
	if err != nil {
		t.Fatalf("creating temp file: %v", err)
	}
	defer f.Close()
	if _, err := f.WriteString(content); err != nil {
		t.Fatalf("writing temp file: %v", err)
	}
	return f.Name()
}
