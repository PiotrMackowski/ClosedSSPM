package html

import (
	"bytes"
	"strings"
	"testing"

	"github.com/PiotrMackowski/ClosedSSPM/internal/collector"
	"github.com/PiotrMackowski/ClosedSSPM/internal/finding"
)

func TestReporterGenerate(t *testing.T) {
	findings := []finding.Finding{
		{
			ID:          "TEST-001-abc",
			PolicyID:    "TEST-001",
			Title:       "Test Finding",
			Description: "A test finding",
			Severity:    finding.Critical,
			Category:    "Test",
			Resource:    "test_table:abc",
			Evidence: []finding.Evidence{
				{
					Table:        "test_table",
					SysID:        "abc",
					DisplayValue: "test_record",
					Fields:       map[string]string{"field1": "val1"},
				},
			},
			Remediation: "Fix the thing",
		},
		{
			ID:          "TEST-002-def",
			PolicyID:    "TEST-002",
			Title:       "Another Finding",
			Description: "Another test finding",
			Severity:    finding.Low,
			Category:    "Other",
			Resource:    "other_table:def",
			Remediation: "Fix this too",
		},
	}

	snapshot := collector.NewSnapshot("test", "https://test.example.com")
	snapshot.AddTableData(&collector.TableData{
		Table: "test_table",
		Count: 10,
	})

	var buf bytes.Buffer
	reporter := &Reporter{}
	err := reporter.Generate(&buf, findings, snapshot)
	if err != nil {
		t.Fatalf("Generate() error: %v", err)
	}

	output := buf.String()

	// Check it's valid HTML.
	if !strings.Contains(output, "<!DOCTYPE html>") && !strings.Contains(output, "<html") {
		t.Error("Output does not appear to be HTML")
	}

	// Check it contains key content.
	if !strings.Contains(output, "ClosedSSPM") {
		t.Error("Output should contain ClosedSSPM title")
	}
	if !strings.Contains(output, "Test Finding") {
		t.Error("Output should contain finding title")
	}
	if !strings.Contains(output, "CRITICAL") {
		t.Error("Output should contain severity")
	}

	// Check search input is present.
	if !strings.Contains(output, `id="search-input"`) {
		t.Error("Output should contain search input")
	}

	// Check expand/collapse buttons are present.
	if !strings.Contains(output, `id="expand-all-btn"`) {
		t.Error("Output should contain expand-all button")
	}
	if !strings.Contains(output, `id="collapse-all-btn"`) {
		t.Error("Output should contain collapse-all button")
	}

	// Check group-by dropdown is present.
	if !strings.Contains(output, `id="group-by-select"`) {
		t.Error("Output should contain group-by select")
	}

	// Check collapsible group CSS class is present.
	if !strings.Contains(output, "group-findings") {
		t.Error("Output should contain collapsible group-findings class in JS")
	}

	// Check sticky toolbar CSS.
	if !strings.Contains(output, "position: sticky") {
		t.Error("Output should contain sticky toolbar CSS")
	}
}

func TestReporterGenerateNilSnapshot(t *testing.T) {
	findings := []finding.Finding{
		{
			ID:       "TEST-001",
			Title:    "Test",
			Severity: finding.Medium,
			Category: "Test",
		},
	}

	var buf bytes.Buffer
	reporter := &Reporter{}
	err := reporter.Generate(&buf, findings, nil)
	if err != nil {
		t.Fatalf("Generate() error: %v", err)
	}

	if buf.Len() == 0 {
		t.Error("Output should not be empty")
	}
}

func TestReporterGenerateEmpty(t *testing.T) {
	var buf bytes.Buffer
	reporter := &Reporter{}
	err := reporter.Generate(&buf, nil, nil)
	if err != nil {
		t.Fatalf("Generate() error: %v", err)
	}

	if buf.Len() == 0 {
		t.Error("Output should not be empty even with no findings")
	}
}

func TestSeverityClass(t *testing.T) {
	tests := []struct {
		severity finding.Severity
		want     string
	}{
		{finding.Critical, "critical"},
		{finding.High, "high"},
		{finding.Medium, "medium"},
		{finding.Low, "low"},
		{finding.Info, "info"},
		{finding.Severity("UNKNOWN"), "unknown"},
	}

	for _, tt := range tests {
		t.Run(string(tt.severity), func(t *testing.T) {
			got := severityClass(tt.severity)
			if got != tt.want {
				t.Errorf("severityClass(%q) = %q, want %q", tt.severity, got, tt.want)
			}
		})
	}
}

func TestScoreClass(t *testing.T) {
	tests := []struct {
		score string
		want  string
	}{
		{"A", "score-a"},
		{"B", "score-b"},
		{"C", "score-c"},
		{"D", "score-d"},
		{"F", "score-f"},
		{"Z", ""},
	}

	for _, tt := range tests {
		t.Run(tt.score, func(t *testing.T) {
			got := scoreClass(tt.score)
			if got != tt.want {
				t.Errorf("scoreClass(%q) = %q, want %q", tt.score, got, tt.want)
			}
		})
	}
}
