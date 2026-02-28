package csv

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
				ResourceType: "test_table",
				ResourceID:   "abc",
				DisplayName:  "test_record",
				Fields:       map[string]string{"field1": "val1", "active": "true"},
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

	var buf bytes.Buffer
	reporter := &Reporter{}
	err := reporter.Generate(&buf, findings, snapshot)
	if err != nil {
		t.Fatalf("Generate() error: %v", err)
	}

	output := buf.String()
	lines := strings.Split(strings.TrimSpace(output), "\n")

	// Header + 2 data rows.
	if len(lines) != 3 {
		t.Fatalf("Expected 3 lines (header + 2 rows), got %d", len(lines))
	}

	// Check header.
	expectedHeader := "ID,PolicyID,Title,Description,Severity,Category,Resource,Remediation,EvidenceResourceType,EvidenceResourceID,EvidenceDisplayName,EvidenceDescription"
	if lines[0] != expectedHeader {
		t.Errorf("Header mismatch:\ngot:  %s\nwant: %s", lines[0], expectedHeader)
	}

	// Critical finding should come first (sorted by severity).
	if !strings.Contains(lines[1], "TEST-001") {
		t.Error("First data row should be critical finding TEST-001")
	}
	if !strings.Contains(lines[1], "CRITICAL") {
		t.Error("First data row should contain CRITICAL severity")
	}

	// Check evidence fields are present.
	if !strings.Contains(lines[1], "test_table") {
		t.Error("First row should contain evidence table")
	}
	if !strings.Contains(lines[1], "test_record") {
		t.Error("First row should contain evidence display_value")
	}

	// Second row should have empty evidence columns.
	if !strings.Contains(lines[2], "TEST-002") {
		t.Error("Second data row should be low finding TEST-002")
	}
}

func TestReporterGenerateEmpty(t *testing.T) {
	var buf bytes.Buffer
	reporter := &Reporter{}
	err := reporter.Generate(&buf, nil, nil)
	if err != nil {
		t.Fatalf("Generate() error: %v", err)
	}

	output := buf.String()
	lines := strings.Split(strings.TrimSpace(output), "\n")

	// Should have header only.
	if len(lines) != 1 {
		t.Errorf("Expected 1 line (header only), got %d", len(lines))
	}
}

func TestEvidenceColumns(t *testing.T) {
	t.Run("empty", func(t *testing.T) {
		resType, resID, name, desc := evidenceColumns(nil)
		if resType != "" || resID != "" || name != "" || desc != "" {
			t.Error("Empty evidence should return empty strings")
		}
	})

	t.Run("with data", func(t *testing.T) {
		ev := []finding.Evidence{
			{
				ResourceType: "sys_user",
				ResourceID:   "abc123",
				DisplayName:  "admin",
				Description:  "Admin user account",
				Fields:       map[string]string{"active": "true"},
			},
		}
		resType, resID, name, desc := evidenceColumns(ev)
		if resType != "sys_user" {
			t.Errorf("resType = %q, want sys_user", resType)
		}
		if resID != "abc123" {
			t.Errorf("resID = %q, want abc123", resID)
		}
		if name != "admin" {
			t.Errorf("name = %q, want admin", name)
		}
		if desc != "Admin user account" {
			t.Errorf("desc = %q, want \"Admin user account\"", desc)
		}
	})
}
