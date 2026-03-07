package json

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/PiotrMackowski/ClosedSSPM/internal/finding"
	"github.com/PiotrMackowski/ClosedSSPM/internal/testutil"
)

func TestReporterGenerate(t *testing.T) {
	findings := []finding.Finding{
		testutil.SampleFinding(),
	}

	snapshot := testutil.SampleSnapshot("test")

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
		testutil.SampleFinding(
			testutil.WithID("TEST-001"),
			testutil.WithSeverity(finding.Low),
		),
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
