// Package finding defines the core finding model used throughout ClosedSSPM.
package finding

import "time"

// Severity represents the severity level of a security finding.
type Severity string

const (
	Critical Severity = "CRITICAL"
	High     Severity = "HIGH"
	Medium   Severity = "MEDIUM"
	Low      Severity = "LOW"
	Info     Severity = "INFO"
)

// SeverityOrder returns a numeric priority for sorting (lower = more severe).
func SeverityOrder(s Severity) int {
	switch s {
	case Critical:
		return 0
	case High:
		return 1
	case Medium:
		return 2
	case Low:
		return 3
	case Info:
		return 4
	default:
		return 5
	}
}

// Evidence represents a specific piece of evidence supporting a finding.
type Evidence struct {
	// ResourceType identifies the kind of resource (e.g. ServiceNow table name).
	ResourceType string `json:"resource_type"`
	// ResourceID is the unique identifier of the resource.
	ResourceID string `json:"resource_id"`
	// DisplayName is a human-readable label for the resource.
	DisplayName string `json:"display_name"`
	// Description provides additional context about the evidence.
	Description string `json:"description,omitempty"`
	// Fields contains the relevant field values from the record.
	Fields map[string]string `json:"fields,omitempty"`
}

// Finding represents a single security finding from an audit.
type Finding struct {
	// ID is a unique identifier for this finding instance (e.g. "SNOW-ACL-001-abc123").
	ID string `json:"id"`
	// PolicyID is the ID of the policy that generated this finding (e.g. "SNOW-ACL-001").
	PolicyID string `json:"policy_id"`
	// Title is a short description of the finding.
	Title string `json:"title"`
	// Description is a detailed explanation of the security issue.
	Description string `json:"description"`
	// Severity is the severity level of the finding.
	Severity Severity `json:"severity"`
	// Category groups findings (e.g. "ACL", "Roles", "Scripts").
	Category string `json:"category"`
	// Resource identifies the affected resource (e.g. "sys_security_acl:abc123").
	Resource string `json:"resource"`
	// Evidence contains the supporting evidence for the finding.
	Evidence []Evidence `json:"evidence"`
	// Remediation describes how to fix the issue.
	Remediation string `json:"remediation"`
	// References contains links to documentation or advisories.
	References []string `json:"references,omitempty"`
	// Timestamp is when the finding was generated.
	Timestamp time.Time `json:"timestamp"`
}

// Summary provides aggregate statistics for a set of findings.
type Summary struct {
	Total         int            `json:"total"`
	BySeverity    map[Severity]int `json:"by_severity"`
	ByCategory    map[string]int   `json:"by_category"`
	PostureScore  string           `json:"posture_score"`
	GeneratedAt   time.Time        `json:"generated_at"`
}

// CalculatePostureScore computes an A-F grade based on findings.
func CalculatePostureScore(findings []Finding) string {
	if len(findings) == 0 {
		return "A"
	}

	criticals := 0
	highs := 0
	mediums := 0
	for _, f := range findings {
		switch f.Severity {
		case Critical:
			criticals++
		case High:
			highs++
		case Medium:
			mediums++
		}
	}

	switch {
	case criticals > 0:
		return "F"
	case highs > 3:
		return "D"
	case highs > 0:
		return "C"
	case mediums > 5:
		return "C"
	case mediums > 0:
		return "B"
	default:
		return "A"
	}
}

// NewSummary creates a Summary from a slice of findings.
func NewSummary(findings []Finding) Summary {
	s := Summary{
		Total:       len(findings),
		BySeverity:  make(map[Severity]int),
		ByCategory:  make(map[string]int),
		GeneratedAt: time.Now().UTC(),
	}

	for _, f := range findings {
		s.BySeverity[f.Severity]++
		s.ByCategory[f.Category]++
	}

	s.PostureScore = CalculatePostureScore(findings)
	return s
}
