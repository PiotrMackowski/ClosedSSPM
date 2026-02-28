package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/PiotrMackowski/ClosedSSPM/internal/collector"
	"github.com/PiotrMackowski/ClosedSSPM/internal/finding"
)

// --- writeReport tests ---

func TestWriteReportHTML(t *testing.T) {
	dir := t.TempDir()
	out := filepath.Join(dir, "report.html")
	snapshot := collector.NewSnapshot("test", "https://test.example.com")

	err := writeReport(nil, snapshot, out, "html")
	if err != nil {
		t.Fatalf("writeReport(html) error: %v", err)
	}

	data, err := os.ReadFile(out)
	if err != nil {
		t.Fatalf("reading output: %v", err)
	}
	if !strings.Contains(string(data), "<!DOCTYPE html>") {
		t.Error("HTML report should contain DOCTYPE")
	}
}

func TestWriteReportJSON(t *testing.T) {
	dir := t.TempDir()
	out := filepath.Join(dir, "report.json")
	snapshot := collector.NewSnapshot("test", "https://test.example.com")

	findings := []finding.Finding{
		{
			ID:       "TEST-001",
			PolicyID: "TEST-001",
			Title:    "Test",
			Severity: finding.Info,
			Category: "Test",
		},
	}

	err := writeReport(findings, snapshot, out, "json")
	if err != nil {
		t.Fatalf("writeReport(json) error: %v", err)
	}

	data, err := os.ReadFile(out)
	if err != nil {
		t.Fatalf("reading output: %v", err)
	}
	if !strings.Contains(string(data), "TEST-001") {
		t.Error("JSON report should contain finding ID")
	}
}

func TestWriteReportCSV(t *testing.T) {
	dir := t.TempDir()
	out := filepath.Join(dir, "report.csv")
	snapshot := collector.NewSnapshot("test", "https://test.example.com")

	findings := []finding.Finding{
		{
			ID:       "TEST-001",
			PolicyID: "TEST-001",
			Title:    "Test Finding",
			Severity: finding.Critical,
			Category: "Test",
			Evidence: []finding.Evidence{
				{
					ResourceType: "test_table",
					ResourceID:   "abc",
					DisplayName:  "test_record",
				},
			},
		},
	}

	err := writeReport(findings, snapshot, out, "csv")
	if err != nil {
		t.Fatalf("writeReport(csv) error: %v", err)
	}

	data, err := os.ReadFile(out)
	if err != nil {
		t.Fatalf("reading output: %v", err)
	}

	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	if len(lines) != 2 {
		t.Fatalf("expected 2 lines (header + 1 row), got %d", len(lines))
	}
	if !strings.Contains(lines[0], "EvidenceResourceType") {
		t.Error("CSV header should contain EvidenceResourceType")
	}
	if !strings.Contains(lines[1], "test_record") {
		t.Error("CSV row should contain evidence display name")
	}
}

func TestWriteReportUnsupportedFormat(t *testing.T) {
	dir := t.TempDir()
	out := filepath.Join(dir, "report.txt")
	snapshot := collector.NewSnapshot("test", "https://test.example.com")

	err := writeReport(nil, snapshot, out, "xml")
	if err == nil {
		t.Fatal("expected error for unsupported format")
	}
	if !strings.Contains(err.Error(), "unsupported output format") {
		t.Errorf("error should mention unsupported format, got: %v", err)
	}
}

func TestWriteReportBadPath(t *testing.T) {
	err := writeReport(nil, nil, "/nonexistent/dir/report.html", "html")
	if err == nil {
		t.Fatal("expected error for bad output path")
	}
}

// --- loadSnapshot / saveSnapshot roundtrip ---

func TestSnapshotRoundtrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "snapshot.json")

	original := collector.NewSnapshot("servicenow", "https://dev123.service-now.com")
	original.AddTableData(&collector.TableData{
		Table:   "sys_user",
		Records: []collector.Record{{"sys_id": "u1", "name": "admin"}},
		Count:   1,
	})

	if err := saveSnapshot(original, path); err != nil {
		t.Fatalf("saveSnapshot error: %v", err)
	}

	// Verify file exists and has restricted permissions.
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat error: %v", err)
	}
	if info.Size() == 0 {
		t.Fatal("snapshot file is empty")
	}

	loaded, err := loadSnapshot(path)
	if err != nil {
		t.Fatalf("loadSnapshot error: %v", err)
	}

	if loaded.Platform != original.Platform {
		t.Errorf("Platform = %q, want %q", loaded.Platform, original.Platform)
	}
	if loaded.InstanceURL != original.InstanceURL {
		t.Errorf("InstanceURL = %q, want %q", loaded.InstanceURL, original.InstanceURL)
	}
	if len(loaded.Tables) != 1 {
		t.Fatalf("Tables count = %d, want 1", len(loaded.Tables))
	}
	td := loaded.Tables["sys_user"]
	if td == nil {
		t.Fatal("sys_user table missing from loaded snapshot")
	}
	if td.Count != 1 {
		t.Errorf("sys_user Count = %d, want 1", td.Count)
	}
}

func TestLoadSnapshotNotFound(t *testing.T) {
	_, err := loadSnapshot("/nonexistent/snapshot.json")
	if err == nil {
		t.Fatal("expected error for missing file")
	}
}

func TestLoadSnapshotInvalidJSON(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bad.json")
	if err := os.WriteFile(path, []byte("not json"), 0644); err != nil {
		t.Fatal(err)
	}

	_, err := loadSnapshot(path)
	if err == nil {
		t.Fatal("expected error for invalid JSON")
	}
}

// --- getPoliciesDir tests ---

func TestGetPoliciesDirFromFlag(t *testing.T) {
	cmd := newAuditCmd()
	cmd.Flags().Set("policies", "/custom/policies")

	result := getPoliciesDir(cmd)
	if result != "/custom/policies" {
		t.Errorf("getPoliciesDir = %q, want /custom/policies", result)
	}
}

func TestGetPoliciesDirFallbackCwd(t *testing.T) {
	// When no flag is set but a "policies" directory exists in cwd,
	// it should find it. We test from the repo root where policies/ exists.
	cmd := newAuditCmd()

	// Save and restore working directory.
	orig, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	defer os.Chdir(orig)

	// Create a temp dir with a "policies" subdirectory.
	dir := t.TempDir()
	os.MkdirAll(filepath.Join(dir, "policies"), 0755)
	os.Chdir(dir)

	result := getPoliciesDir(cmd)
	if result != "policies" {
		t.Errorf("getPoliciesDir = %q, want 'policies'", result)
	}
}

func TestGetPoliciesDirFallbackEmbedded(t *testing.T) {
	cmd := newAuditCmd()

	// Save and restore working directory.
	orig, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	defer os.Chdir(orig)

	// Change to a temp dir with no policies directory.
	dir := t.TempDir()
	os.Chdir(dir)

	result := getPoliciesDir(cmd)
	if result != "" {
		t.Errorf("getPoliciesDir = %q, want empty string (embedded fallback)", result)
	}
}

// --- loadPolicies tests ---

func TestLoadPoliciesEmbedded(t *testing.T) {
	pols, source, err := loadPolicies("")
	if err != nil {
		t.Fatalf("loadPolicies(embedded) error: %v", err)
	}
	if source != "(embedded)" {
		t.Errorf("source = %q, want (embedded)", source)
	}
	if len(pols) == 0 {
		t.Error("expected at least one embedded policy")
	}
}

func TestLoadPoliciesBadDir(t *testing.T) {
	_, _, err := loadPolicies("/nonexistent/policies")
	if err == nil {
		t.Fatal("expected error for nonexistent policies dir")
	}
}
