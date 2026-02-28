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
					Table:        "test_table",
					SysID:        "abc",
					DisplayValue: "test_record",
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
	expectedHeader := "ID,PolicyID,Title,Description,Severity,Category,Resource,Remediation,EvidenceTable,EvidenceSysID,EvidenceDisplayValue"
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
		table, sysID, display := evidenceColumns(nil)
		if table != "" || sysID != "" || display != "" {
			t.Error("Empty evidence should return empty strings")
		}
	})

	t.Run("with data", func(t *testing.T) {
		ev := []finding.Evidence{
			{
				Table:        "sys_user",
				SysID:        "abc123",
				DisplayValue: "admin",
				Fields:       map[string]string{"active": "true"},
			},
		}
		table, sysID, display := evidenceColumns(ev)
		if table != "sys_user" {
			t.Errorf("table = %q, want sys_user", table)
		}
		if sysID != "abc123" {
			t.Errorf("sysID = %q, want abc123", sysID)
		}
		if display != "admin" {
			t.Errorf("display = %q, want admin", display)
		}
	})
}
