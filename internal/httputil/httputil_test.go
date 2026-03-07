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
