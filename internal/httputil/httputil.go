// Package httputil provides shared HTTP utility functions for API connectors.
package httputil

import (
	"errors"
	"io"
	"regexp"
	"time"
)

const (
	MaxResponseBodySize = 50 * 1024 * 1024
	MaxRedirects        = 5
)

type OAuthToken struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	ExpiresIn   int    `json:"expires_in"`
	Scope       string `json:"scope"`
	ExpiresAt   time.Time
}

func (t *OAuthToken) IsExpired() bool {
	return time.Now().After(t.ExpiresAt.Add(-60 * time.Second))
}

// secretPatterns defines regex patterns for credentials that must be redacted
// from error bodies before they are logged or returned to callers.
var secretPatterns = []struct {
	re          *regexp.Regexp
	replacement string
}{
	{regexp.MustCompile(`Bearer\s+[^\s"]+`), "Bearer [REDACTED]"},
	{regexp.MustCompile(`access_token[\s:="]+[^\s"&]+`), "access_token=[REDACTED]"},
	{regexp.MustCompile(`password[\s:="]+[^\s"&]+`), "password=[REDACTED]"},
	{regexp.MustCompile(`Authorization[\s:="]+[^\s"]+`), "Authorization=[REDACTED]"},
	{regexp.MustCompile(`\btoken[\s:="]+[^\s"&]+`), "token=[REDACTED]"},
}

func redactSecrets(s string) string {
	for _, p := range secretPatterns {
		s = p.re.ReplaceAllString(s, p.replacement)
	}
	return s
}

func ReadLimitedBody(body io.Reader) ([]byte, error) {
	limited := io.LimitReader(body, MaxResponseBodySize+1)
	data, err := io.ReadAll(limited)
	if err != nil {
		return nil, err
	}
	if len(data) > MaxResponseBodySize {
		return nil, errors.New("response body exceeds maximum allowed size")
	}
	return data, nil
}

func SanitizeErrorBody(body []byte) string {
	const maxErrorBodyLen = 256
	s := string(body)
	s = redactSecrets(s)
	if len(s) > maxErrorBodyLen {
		s = s[:maxErrorBodyLen] + "...(truncated)"
	}
	return s
}
