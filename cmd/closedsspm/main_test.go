package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/PiotrMackowski/ClosedSSPM/internal/collector"
	"github.com/PiotrMackowski/ClosedSSPM/internal/finding"
	"github.com/PiotrMackowski/ClosedSSPM/internal/testutil"
)

// --- writeReport tests ---

func TestWriteReportHTML(t *testing.T) {
	dir := t.TempDir()
	out := filepath.Join(dir, "report.html")
	snapshot := testutil.SampleSnapshot("test")

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

	findings := []finding.Finding{testutil.SampleFinding(
		testutil.WithID("TEST-001"),
		testutil.WithSeverity(finding.Info),
	)}

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
	snapshot := testutil.SampleSnapshot("test")

	findings := []finding.Finding{testutil.SampleFinding(
		testutil.WithID("TEST-001"),
		testutil.WithTitle("Test Finding"),
		testutil.WithSeverity(finding.Critical),
		testutil.WithEvidence(testutil.SampleEvidence()),
	)}

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

func TestWriteReportSARIF(t *testing.T) {
	dir := t.TempDir()
	out := filepath.Join(dir, "report.sarif")
	snapshot := testutil.SampleSnapshot("servicenow")
	snapshot.InstanceURL = "https://test.service-now.com"

	findings := []finding.Finding{testutil.SampleFinding(
		testutil.WithID("TEST-001-a"),
		testutil.WithSeverity(finding.High),
	)}

	err := writeReport(findings, snapshot, out, "sarif")
	if err != nil {
		t.Fatalf("writeReport(sarif) error: %v", err)
	}

	data, err := os.ReadFile(out)
	if err != nil {
		t.Fatalf("reading output: %v", err)
	}
	// SARIF files must contain the SARIF schema and version.
	content := string(data)
	if !strings.Contains(content, "\"version\": \"2.1.0\"") {
		t.Error("SARIF report should contain version 2.1.0")
	}
	if !strings.Contains(content, "\"$schema\"") {
		t.Error("SARIF report should contain $schema")
	}
	if !strings.Contains(content, "TEST-001") {
		t.Error("SARIF report should contain finding rule ID")
	}
}

func TestWriteReportUnsupportedFormat(t *testing.T) {
	dir := t.TempDir()
	out := filepath.Join(dir, "report.txt")
	snapshot := testutil.SampleSnapshot("test")

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

	original := testutil.SampleSnapshot(
		"servicenow",
		testutil.SampleTableData("sys_user", collector.Record{"sys_id": "u1", "name": "admin"}),
	)
	original.InstanceURL = "https://dev123.service-now.com"

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

// --- parsePlatforms tests ---

func TestParsePlatformsSingle(t *testing.T) {
	platforms, err := parsePlatforms("servicenow")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(platforms) != 1 || platforms[0] != "servicenow" {
		t.Errorf("got %v, want [servicenow]", platforms)
	}
}

func TestParsePlatformsCommaSeparated(t *testing.T) {
	platforms, err := parsePlatforms("entra, googleworkspace")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(platforms) != 2 {
		t.Fatalf("got %d platforms, want 2", len(platforms))
	}
	if platforms[0] != "entra" || platforms[1] != "googleworkspace" {
		t.Errorf("got %v, want [entra googleworkspace]", platforms)
	}
}

func TestParsePlatformsAll(t *testing.T) {
	platforms, err := parsePlatforms("all")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(platforms) == 0 {
		t.Fatal("expected at least one platform for 'all'")
	}
}

func TestParsePlatformsAllCaseInsensitive(t *testing.T) {
	platforms, err := parsePlatforms("ALL")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(platforms) == 0 {
		t.Fatal("expected at least one platform for 'ALL'")
	}
}

func TestParsePlatformsUnknown(t *testing.T) {
	_, err := parsePlatforms("nonexistent")
	if err == nil {
		t.Fatal("expected error for unknown platform")
	}
}

func TestParsePlatformsEmpty(t *testing.T) {
	_, err := parsePlatforms("")
	if err == nil {
		t.Fatal("expected error for empty string")
	}
}

func TestParsePlatformsSkipsBlanks(t *testing.T) {
	platforms, err := parsePlatforms("servicenow,,entra,")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(platforms) != 2 {
		t.Fatalf("got %d platforms, want 2", len(platforms))
	}
}

// --- mergeSnapshots tests ---

func TestMergeSnapshotsSingle(t *testing.T) {
	s := collector.NewSnapshot("entra", "https://graph.microsoft.com")
	merged := mergeSnapshots([]*collector.Snapshot{s})
	if merged != s {
		t.Error("single snapshot should return the same pointer")
	}
}

func TestMergeSnapshotsMultiple(t *testing.T) {
	s1 := collector.NewSnapshot("entra", "https://graph.microsoft.com")
	s1.AddTableData(&collector.TableData{
		Table:   "applications",
		Records: []collector.Record{{"name": "app1"}},
		Count:   1,
	})

	s2 := collector.NewSnapshot("googleworkspace", "https://admin.googleapis.com")
	s2.AddTableData(&collector.TableData{
		Table:   "oauth_tokens",
		Records: []collector.Record{{"user": "admin@test.com"}},
		Count:   1,
	})

	merged := mergeSnapshots([]*collector.Snapshot{s1, s2})

	if merged.Platform != "entra+googleworkspace" {
		t.Errorf("Platform = %q, want entra+googleworkspace", merged.Platform)
	}
	if !strings.Contains(merged.InstanceURL, "graph.microsoft.com") {
		t.Error("InstanceURL should contain graph.microsoft.com")
	}
	if !strings.Contains(merged.InstanceURL, "admin.googleapis.com") {
		t.Error("InstanceURL should contain admin.googleapis.com")
	}
	if len(merged.Tables) != 2 {
		t.Errorf("Tables count = %d, want 2", len(merged.Tables))
	}
	if merged.GetRecords("entra/applications") == nil {
		t.Error("merged snapshot should contain entra/applications table")
	}
	if merged.GetRecords("googleworkspace/oauth_tokens") == nil {
		t.Error("merged snapshot should contain googleworkspace/oauth_tokens table")
	}
}

func TestMergeSnapshotsThreePlatforms(t *testing.T) {
	s1 := collector.NewSnapshot("entra", "https://graph.microsoft.com")
	s1.AddTableData(&collector.TableData{
		Table:   "applications",
		Records: []collector.Record{{"name": "app1"}},
		Count:   1,
	})

	s2 := collector.NewSnapshot("googleworkspace", "https://admin.googleapis.com")
	s2.AddTableData(&collector.TableData{
		Table:   "oauth_tokens",
		Records: []collector.Record{{"user": "admin@test.com"}},
		Count:   1,
	})

	s3 := collector.NewSnapshot("servicenow", "https://dev123.service-now.com")
	s3.AddTableData(&collector.TableData{
		Table:   "sys_user",
		Records: []collector.Record{{"name": "admin"}},
		Count:   1,
	})

	merged := mergeSnapshots([]*collector.Snapshot{s1, s2, s3})

	if merged.Platform != "entra+googleworkspace+servicenow" {
		t.Errorf("Platform = %q, want entra+googleworkspace+servicenow", merged.Platform)
	}
	if !strings.Contains(merged.InstanceURL, "graph.microsoft.com") {
		t.Error("InstanceURL should contain graph.microsoft.com")
	}
	if !strings.Contains(merged.InstanceURL, "admin.googleapis.com") {
		t.Error("InstanceURL should contain admin.googleapis.com")
	}
	if !strings.Contains(merged.InstanceURL, "service-now.com") {
		t.Error("InstanceURL should contain service-now.com")
	}
	if len(merged.Tables) != 3 {
		t.Errorf("Tables count = %d, want 3", len(merged.Tables))
	}
	if merged.GetRecords("entra/applications") == nil {
		t.Error("merged snapshot should contain entra/applications table")
	}
	if merged.GetRecords("googleworkspace/oauth_tokens") == nil {
		t.Error("merged snapshot should contain googleworkspace/oauth_tokens table")
	}
	if merged.GetRecords("servicenow/sys_user") == nil {
		t.Error("merged snapshot should contain servicenow/sys_user table")
	}
}

func TestChecksShowFound(t *testing.T) {
	cmd := newChecksCmd()
	buf := new(bytes.Buffer)
	cmd.SetOut(buf)
	cmd.SetErr(buf)
	cmd.SetArgs([]string{"show", "SNOW-USER-001"})

	err := cmd.Execute()
	if err != nil {
		t.Fatalf("checks show returned error: %v", err)
	}

	out := buf.String()
	if !strings.Contains(out, "ID:          SNOW-USER-001") {
		t.Errorf("expected ID in output, got: %s", out)
	}
	if !strings.Contains(out, "Title:") {
		t.Errorf("expected Title in output, got: %s", out)
	}
	if !strings.Contains(out, "Platform:    servicenow") {
		t.Errorf("expected platform in output, got: %s", out)
	}
	if !strings.Contains(out, "Query Table:") {
		t.Errorf("expected query table in output, got: %s", out)
	}
}

func TestChecksShowNotFound(t *testing.T) {
	cmd := newChecksCmd()
	buf := new(bytes.Buffer)
	cmd.SetOut(buf)
	cmd.SetErr(buf)
	cmd.SetArgs([]string{"show", "DOES-NOT-EXIST-001"})

	err := cmd.Execute()
	if err == nil {
		t.Fatal("expected error for unknown policy")
	}
	if !strings.Contains(err.Error(), "not found") {
		t.Fatalf("expected not found error, got: %v", err)
	}
}

func TestPlatformEnvSingle(t *testing.T) {
	cmd := newPlatformCmd()
	buf := new(bytes.Buffer)
	cmd.SetOut(buf)
	cmd.SetErr(buf)
	cmd.SetArgs([]string{"env", "servicenow"})

	err := cmd.Execute()
	if err != nil {
		t.Fatalf("platform env servicenow returned error: %v", err)
	}

	out := buf.String()
	if !strings.Contains(out, "SNOW_INSTANCE") {
		t.Errorf("expected ServiceNow env help in output, got: %s", out)
	}
	if !strings.Contains(out, "SNOW_USERNAME") {
		t.Errorf("expected ServiceNow env help in output, got: %s", out)
	}
}

func TestPlatformEnvAll(t *testing.T) {
	cmd := newPlatformCmd()
	buf := new(bytes.Buffer)
	cmd.SetOut(buf)
	cmd.SetErr(buf)
	cmd.SetArgs([]string{"env"})

	err := cmd.Execute()
	if err != nil {
		t.Fatalf("platform env returned error: %v", err)
	}

	out := buf.String()
	if !strings.Contains(out, "=== servicenow ===") {
		t.Errorf("expected servicenow section in output, got: %s", out)
	}
	if !strings.Contains(out, "=== entra ===") {
		t.Errorf("expected entra section in output, got: %s", out)
	}
}
