package json

import (
	"bytes"
	"encoding/json"
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
			Severity:    finding.High,
			Category:    "Test",
			Resource:    "test_table:abc",
			Evidence: []finding.Evidence{
				{
				ResourceType: "test_table",
				ResourceID:   "abc",
				DisplayName:  "test_record",
					Fields:       map[string]string{"field1": "val1"},
				},
			},
			Remediation: "Fix the thing",
		},
	}

	snapshot := collector.NewSnapshot("test", "https://test.example.com")

	var buf bytes.Buffer
	reporter := &Reporter{}
	err := reporter.Generate(&buf, findings, snapshot)
	if err != nil {
		t.Fatalf("Generate() error: %v", err)
	}

	// Verify it's valid JSON.
	var report Report
	if err := json.Unmarshal(buf.Bytes(), &report); err != nil {
		t.Fatalf("Output is not valid JSON: %v", err)
	}

	if report.Title != "ClosedSSPM Security Audit Report" {
		t.Errorf("Title = %q, want %q", report.Title, "ClosedSSPM Security Audit Report")
	}
	if report.Platform != "test" {
		t.Errorf("Platform = %q, want %q", report.Platform, "test")
	}
	if report.InstanceURL != "https://test.example.com" {
		t.Errorf("InstanceURL = %q, want %q", report.InstanceURL, "https://test.example.com")
	}
	if len(report.Findings) != 1 {
		t.Errorf("Findings count = %d, want 1", len(report.Findings))
	}
	if report.Summary.Total != 1 {
		t.Errorf("Summary.Total = %d, want 1", report.Summary.Total)
	}
}

func TestReporterGenerateNilSnapshot(t *testing.T) {
	findings := []finding.Finding{
		{
			ID:       "TEST-001",
			Severity: finding.Low,
			Category: "Test",
		},
	}

	var buf bytes.Buffer
	reporter := &Reporter{}
	err := reporter.Generate(&buf, findings, nil)
	if err != nil {
		t.Fatalf("Generate() error: %v", err)
	}

	var report Report
	if err := json.Unmarshal(buf.Bytes(), &report); err != nil {
		t.Fatalf("Output is not valid JSON: %v", err)
	}

	if report.InstanceURL != "" {
		t.Errorf("InstanceURL should be empty when snapshot is nil, got %q", report.InstanceURL)
	}
	if report.Platform != "" {
		t.Errorf("Platform should be empty when snapshot is nil, got %q", report.Platform)
	}
}

func TestReporterGenerateEmpty(t *testing.T) {
	var buf bytes.Buffer
	reporter := &Reporter{}
	err := reporter.Generate(&buf, nil, nil)
	if err != nil {
		t.Fatalf("Generate() error: %v", err)
	}

	var report Report
	if err := json.Unmarshal(buf.Bytes(), &report); err != nil {
		t.Fatalf("Output is not valid JSON: %v", err)
	}

	if report.Summary.Total != 0 {
		t.Errorf("Summary.Total = %d, want 0", report.Summary.Total)
	}
	if report.Summary.PostureScore != "A" {
		t.Errorf("PostureScore = %q, want %q", report.Summary.PostureScore, "A")
	}
}
