package csv

import (
	"bytes"
	"strings"
	"testing"

	"github.com/PiotrMackowski/ClosedSSPM/internal/finding"
	"github.com/PiotrMackowski/ClosedSSPM/internal/testutil"
)

func TestReporterGenerate(t *testing.T) {
	findings := []finding.Finding{
		testutil.SampleFinding(
			testutil.WithSeverity(finding.Critical),
			testutil.WithEvidence(testutil.SampleEvidence(testutil.WithFields(map[string]string{"field1": "val1", "active": "true"}))),
		),
		testutil.SampleFinding(
			testutil.WithID("TEST-002-def"),
			testutil.WithPolicyID("TEST-002"),
			testutil.WithTitle("Another Finding"),
			testutil.WithDescription("Another test finding"),
			testutil.WithSeverity(finding.Low),
			testutil.WithCategory("Other"),
			testutil.WithResource("other_table:def"),
			testutil.WithRemediation("Fix this too"),
			testutil.WithEvidence(),
		),
	}

	snapshot := testutil.SampleSnapshot("test")

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
	expectedHeader := "ID,PolicyID,Title,Description,Severity,Category,Platform,Resource,Remediation,EvidenceResourceType,EvidenceResourceID,EvidenceDisplayName,EvidenceDescription"
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

func TestReporterGenerateMultiPlatformRows(t *testing.T) {
	findings := []finding.Finding{
		testutil.SampleFinding(
			testutil.WithID("TEST-001-a"),
			testutil.WithSeverity(finding.Critical),
			testutil.WithPlatform("entra"),
		),
		testutil.SampleFinding(
			testutil.WithID("TEST-002-b"),
			testutil.WithSeverity(finding.Low),
			testutil.WithPlatform("servicenow"),
		),
	}

	var buf bytes.Buffer
	reporter := &Reporter{}
	if err := reporter.Generate(&buf, findings, testutil.SampleSnapshot("entra+servicenow")); err != nil {
		t.Fatalf("Generate() error: %v", err)
	}

	lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
	if len(lines) != 3 {
		t.Fatalf("Expected 3 lines (header + 2 rows), got %d", len(lines))
	}

	if !strings.Contains(lines[0], "Platform") {
		t.Errorf("Header should contain Platform column, got: %s", lines[0])
	}
	if !strings.Contains(lines[1], "entra") {
		t.Errorf("First data row should contain platform entra, got: %s", lines[1])
	}
	if !strings.Contains(lines[2], "servicenow") {
		t.Errorf("Second data row should contain platform servicenow, got: %s", lines[2])
	}
}

func TestReporterCSVInjectionSanitization(t *testing.T) {
	findings := []finding.Finding{
		testutil.SampleFinding(
			testutil.WithTitle(`=cmd|'/C calc'!A0`),
			testutil.WithDescription("+dangerous"),
			testutil.WithRemediation("-remove this"),
			testutil.WithSeverity(finding.High),
		),
		testutil.SampleFinding(
			testutil.WithID("TEST-002-safe"),
			testutil.WithPolicyID("TEST-002"),
			testutil.WithTitle("Safe title"),
			testutil.WithDescription("@mention injection"),
			testutil.WithSeverity(finding.Low),
			testutil.WithRemediation("\ttab injection"),
			testutil.WithEvidence(),
		),
	}

	var buf bytes.Buffer
	reporter := &Reporter{}
	if err := reporter.Generate(&buf, findings, nil); err != nil {
		t.Fatalf("Generate() error: %v", err)
	}

	output := buf.String()
	lines := strings.Split(strings.TrimSpace(output), "\n")

	// Header + 2 data rows.
	if len(lines) != 3 {
		t.Fatalf("Expected 3 lines, got %d", len(lines))
	}

	// Verify dangerous prefixes are sanitised with leading single-quote.
	if !strings.Contains(lines[1], "'=cmd|") {
		t.Errorf("Expected '=cmd| prefix in row 1, got: %s", lines[1])
	}
	if !strings.Contains(lines[1], "'+dangerous") {
		t.Errorf("Expected '+dangerous in row 1, got: %s", lines[1])
	}
	if !strings.Contains(lines[1], "'-remove this") {
		t.Errorf("Expected '-remove this in row 1, got: %s", lines[1])
	}
	if !strings.Contains(lines[2], "'@mention injection") {
		t.Errorf("Expected '@mention injection in row 2, got: %s", lines[2])
	}
}

func TestSanitizeCell(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"normal text", "normal text"},
		{"", ""},
		{"=1+1", "'=1+1"},
		{"+cmd", "'+cmd"},
		{"-cmd", "'-cmd"},
		{"@sum", "'@sum"},
		{"\tcmd", "'\tcmd"},
		{"\rcmd", "'\rcmd"},
	}
	for _, tt := range tests {
		got := sanitizeCell(tt.input)
		if got != tt.want {
			t.Errorf("sanitizeCell(%q) = %q, want %q", tt.input, got, tt.want)
		}
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
