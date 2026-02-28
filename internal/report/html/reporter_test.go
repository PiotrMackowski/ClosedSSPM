package html

import (
	"bytes"
	"encoding/json"
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

	// Check embedded JSON data script tag is present.
	if !strings.Contains(output, `<script id="report-data" type="application/json">`) {
		t.Error("Output should contain embedded JSON data script tag")
	}

	// Check findings are embedded as JSON (not as HTML DOM elements).
	if !strings.Contains(output, `"policy_id":"TEST-001"`) {
		t.Error("Output should contain finding policy_id in embedded JSON")
	}
	if !strings.Contains(output, `"title":"Test Finding"`) {
		t.Error("Output should contain finding title in embedded JSON")
	}
	if !strings.Contains(output, `"severity":"CRITICAL"`) {
		t.Error("Output should contain finding severity in embedded JSON")
	}

	// Check the embedded JSON is valid by extracting and parsing it.
	const startTag = `<script id="report-data" type="application/json">`
	const endTag = `</script>`
	startIdx := strings.Index(output, startTag)
	if startIdx == -1 {
		t.Fatal("Cannot find start of embedded JSON")
	}
	jsonStart := startIdx + len(startTag)
	jsonEnd := strings.Index(output[jsonStart:], endTag)
	if jsonEnd == -1 {
		t.Fatal("Cannot find end of embedded JSON")
	}
	jsonStr := output[jsonStart : jsonStart+jsonEnd]

	var parsed []finding.Finding
	if err := json.Unmarshal([]byte(jsonStr), &parsed); err != nil {
		t.Fatalf("Embedded JSON is not valid: %v", err)
	}
	if len(parsed) != 2 {
		t.Errorf("Embedded JSON should have 2 findings, got %d", len(parsed))
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

	// Check sticky toolbar CSS.
	if !strings.Contains(output, "position: sticky") {
		t.Error("Output should contain sticky toolbar CSS")
	}

	// Check JS renders findings container (not server-rendered DOM).
	if !strings.Contains(output, `id="findings-container"`) {
		t.Error("Output should contain findings-container div")
	}

	// Ensure findings are NOT rendered as server-side DOM elements.
	if strings.Contains(output, `data-severity="CRITICAL"`) {
		t.Error("Output should NOT contain server-rendered finding DOM elements")
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

	// Should still have embedded JSON.
	output := buf.String()
	if !strings.Contains(output, `<script id="report-data" type="application/json">`) {
		t.Error("Output should contain embedded JSON data even with nil snapshot")
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

	// Should have empty JSON array.
	output := buf.String()
	if !strings.Contains(output, `<script id="report-data" type="application/json">`) {
		t.Error("Output should contain embedded JSON data script tag even with empty findings")
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
