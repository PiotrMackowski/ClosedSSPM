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

func TestReporterGenerateMultiPlatform(t *testing.T) {
	findings := []finding.Finding{
		testutil.SampleFinding(
			testutil.WithID("ENTRA-001-a"),
			testutil.WithPlatform("entra"),
		),
		testutil.SampleFinding(
			testutil.WithID("SNOW-001-b"),
			testutil.WithPlatform("servicenow"),
		),
	}

	snapshot := testutil.SampleSnapshot("entra+servicenow")

	var buf bytes.Buffer
	reporter := &Reporter{}
	if err := reporter.Generate(&buf, findings, snapshot); err != nil {
		t.Fatalf("Generate() error: %v", err)
	}

	var report Report
	if err := json.Unmarshal(buf.Bytes(), &report); err != nil {
		t.Fatalf("Output is not valid JSON: %v", err)
	}

	if report.Platform != "entra+servicenow" {
		t.Errorf("Platform = %q, want %q", report.Platform, "entra+servicenow")
	}
	if len(report.Findings) != 2 {
		t.Fatalf("Findings count = %d, want 2", len(report.Findings))
	}

	var raw map[string]interface{}
	if err := json.Unmarshal(buf.Bytes(), &raw); err != nil {
		t.Fatalf("Output is not valid raw JSON map: %v", err)
	}

	rawFindings, ok := raw["findings"].([]interface{})
	if !ok {
		t.Fatalf("report.findings has unexpected type %T", raw["findings"])
	}
	if len(rawFindings) != 2 {
		t.Fatalf("raw findings count = %d, want 2", len(rawFindings))
	}

	firstFinding, ok := rawFindings[0].(map[string]interface{})
	if !ok {
		t.Fatalf("first raw finding has unexpected type %T", rawFindings[0])
	}
	secondFinding, ok := rawFindings[1].(map[string]interface{})
	if !ok {
		t.Fatalf("second raw finding has unexpected type %T", rawFindings[1])
	}

	if firstPlatform, ok := firstFinding["platform"].(string); !ok || firstPlatform != "entra" {
		t.Errorf("first finding platform = %v, want %q", firstFinding["platform"], "entra")
	}
	if secondPlatform, ok := secondFinding["platform"].(string); !ok || secondPlatform != "servicenow" {
		t.Errorf("second finding platform = %v, want %q", secondFinding["platform"], "servicenow")
	}
}
