// Package httputil provides shared HTTP utility functions for API connectors.
package httputil

import (
	"errors"
	"io"
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
	if len(s) > maxErrorBodyLen {
		s = s[:maxErrorBodyLen] + "...(truncated)"
	}
	return s
}
