package httputil

import (
	"bytes"
	"strings"
	"testing"
	"time"
)

func TestReadLimitedBody(t *testing.T) {
	data, err := ReadLimitedBody(bytes.NewReader(make([]byte, 100)))
	if err != nil {
		t.Fatalf("ReadLimitedBody() error: %v", err)
	}
	if len(data) != 100 {
		t.Fatalf("ReadLimitedBody() length = %d, want 100", len(data))
	}

	_, err = ReadLimitedBody(bytes.NewReader(make([]byte, MaxResponseBodySize+1)))
	if err == nil {
		t.Fatal("expected error when body exceeds limit")
	}
}

func TestSanitizeErrorBody(t *testing.T) {
	short := "short"
	if got := SanitizeErrorBody([]byte(short)); got != short {
		t.Fatalf("SanitizeErrorBody(short) = %q, want %q", got, short)
	}

	long := strings.Repeat("x", 400)
	got := SanitizeErrorBody([]byte(long))
	if !strings.HasSuffix(got, "...(truncated)") {
		t.Fatalf("SanitizeErrorBody(long) should end with truncation suffix, got %q", got)
	}
}

func TestSanitizeErrorBodyRedaction(t *testing.T) {
	tests := []struct {
		name        string
		input       string
		contains    string
		notContains string
	}{
		{
			name:        "bearer token redacted",
			input:       "error: Bearer sk_live_abc123def456xyz",
			contains:    "Bearer [REDACTED]",
			notContains: "sk_live_abc123def456xyz",
		},
		{
			name:        "access_token redacted",
			input:       `{"error":"unauthorized","access_token":"secret_token_12345"}`,
			contains:    "access_token=[REDACTED]",
			notContains: "secret_token_12345",
		},
		{
			name:        "password redacted",
			input:       `error authenticating: password=supersecret123`,
			contains:    "password=[REDACTED]",
			notContains: "supersecret123",
		},
		{
			name:        "authorization header redacted",
			input:       `Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9`,
			contains:    "Authorization=[REDACTED]",
			notContains: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9",
		},
		{
			name:        "generic token redacted",
			input:       `token=abc123xyz789`,
			contains:    "token=[REDACTED]",
			notContains: "abc123xyz789",
		},
		{
			name:        "normal error without secrets passes through",
			input:       "error: request failed with status 401",
			contains:    "error: request failed with status 401",
			notContains: "[REDACTED]",
		},
		{
			name:        "multiple secrets in one message",
			input:       `Bearer xyz123 and password=secret and access_token=token123`,
			contains:    "Bearer [REDACTED]",
			notContains: "xyz123",
		},
		{
			name:        "redaction works on short bodies",
			input:       "Bearer mytoken123",
			contains:    "Bearer [REDACTED]",
			notContains: "mytoken123",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result := SanitizeErrorBody([]byte(tc.input))

			if !strings.Contains(result, tc.contains) {
				t.Errorf("result should contain %q, got: %q", tc.contains, result)
			}

			if tc.notContains != "" && strings.Contains(result, tc.notContains) {
				t.Errorf("result should not contain %q, got: %q", tc.notContains, result)
			}
		})
	}
}

func TestOAuthTokenIsExpired(t *testing.T) {
	if !(&OAuthToken{}).IsExpired() {
		t.Fatal("zero-value token should be expired")
	}

	notExpired := &OAuthToken{ExpiresAt: time.Now().Add(5 * time.Minute)}
	if notExpired.IsExpired() {
		t.Fatal("token should not be expired")
	}

	withinBuffer := &OAuthToken{ExpiresAt: time.Now().Add(30 * time.Second)}
	if !withinBuffer.IsExpired() {
		t.Fatal("token inside 60-second buffer should be treated as expired")
	}
}
