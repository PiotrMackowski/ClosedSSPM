package sarif

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
			Description: "A test finding description",
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
			References:  []string{"https://example.com/docs"},
		},
	}

	snapshot := collector.NewSnapshot("servicenow", "https://test.service-now.com")

	var buf bytes.Buffer
	reporter := &Reporter{}
	err := reporter.Generate(&buf, findings, snapshot)
	if err != nil {
		t.Fatalf("Generate() error: %v", err)
	}

	// Verify valid JSON and correct SARIF structure.
	var log sarifLog
	if err := json.Unmarshal(buf.Bytes(), &log); err != nil {
		t.Fatalf("Output is not valid JSON: %v", err)
	}

	if log.Version != "2.1.0" {
		t.Errorf("Version = %q, want %q", log.Version, "2.1.0")
	}
	if log.Schema == "" {
		t.Error("Schema should not be empty")
	}
	if len(log.Runs) != 1 {
		t.Fatalf("Runs count = %d, want 1", len(log.Runs))
	}

	run := log.Runs[0]
	if run.Tool.Driver.Name != "ClosedSSPM" {
		t.Errorf("Driver.Name = %q, want %q", run.Tool.Driver.Name, "ClosedSSPM")
	}
	if run.Tool.Driver.Version != "servicenow" {
		t.Errorf("Driver.Version = %q, want %q", run.Tool.Driver.Version, "servicenow")
	}

	// Rules.
	if len(run.Tool.Driver.Rules) != 1 {
		t.Fatalf("Rules count = %d, want 1", len(run.Tool.Driver.Rules))
	}
	rule := run.Tool.Driver.Rules[0]
	if rule.ID != "TEST-001" {
		t.Errorf("Rule.ID = %q, want %q", rule.ID, "TEST-001")
	}
	if rule.ShortDescription.Text != "Test Finding" {
		t.Errorf("Rule.ShortDescription = %q, want %q", rule.ShortDescription.Text, "Test Finding")
	}
	if rule.FullDescription.Text != "A test finding description" {
		t.Errorf("Rule.FullDescription = %q, want %q", rule.FullDescription.Text, "A test finding description")
	}
	if rule.HelpURI != "https://example.com/docs" {
		t.Errorf("Rule.HelpURI = %q, want %q", rule.HelpURI, "https://example.com/docs")
	}
	if rule.Help == nil || rule.Help.Text != "Fix the thing" {
		t.Errorf("Rule.Help = %v, want text %q", rule.Help, "Fix the thing")
	}
	if rule.DefaultConfig == nil || rule.DefaultConfig.Level != "error" {
		t.Errorf("Rule.DefaultConfig.Level = %v, want %q", rule.DefaultConfig, "error")
	}

	// Results.
	if len(run.Results) != 1 {
		t.Fatalf("Results count = %d, want 1", len(run.Results))
	}
	result := run.Results[0]
	if result.RuleID != "TEST-001" {
		t.Errorf("Result.RuleID = %q, want %q", result.RuleID, "TEST-001")
	}
	if result.RuleIndex != 0 {
		t.Errorf("Result.RuleIndex = %d, want 0", result.RuleIndex)
	}
	if result.Level != "error" {
		t.Errorf("Result.Level = %q, want %q", result.Level, "error")
	}
	if len(result.Locations) != 1 {
		t.Fatalf("Result.Locations count = %d, want 1", len(result.Locations))
	}
	loc := result.Locations[0]
	if len(loc.LogicalLocations) != 1 {
		t.Fatalf("LogicalLocations count = %d, want 1", len(loc.LogicalLocations))
	}
	if loc.LogicalLocations[0].Name != "test_table:abc" {
		t.Errorf("LogicalLocation.Name = %q, want %q", loc.LogicalLocations[0].Name, "test_table:abc")
	}
	if loc.LogicalLocations[0].Kind != "resource" {
		t.Errorf("LogicalLocation.Kind = %q, want %q", loc.LogicalLocations[0].Kind, "resource")
	}
}

func TestReporterGenerateMultipleFindings(t *testing.T) {
	findings := []finding.Finding{
		{
			ID:       "SNOW-ACL-001-a",
			PolicyID: "SNOW-ACL-001",
			Title:    "ACL Missing",
			Severity: finding.Critical,
			Category: "ACL",
			Resource: "sys_security_acl:a",
		},
		{
			ID:       "SNOW-ACL-001-b",
			PolicyID: "SNOW-ACL-001",
			Title:    "ACL Missing",
			Severity: finding.Critical,
			Category: "ACL",
			Resource: "sys_security_acl:b",
		},
		{
			ID:       "SNOW-ROLE-001-c",
			PolicyID: "SNOW-ROLE-001",
			Title:    "Excessive Role",
			Severity: finding.Medium,
			Category: "Roles",
			Resource: "sys_user_role:c",
		},
	}

	var buf bytes.Buffer
	reporter := &Reporter{}
	err := reporter.Generate(&buf, findings, nil)
	if err != nil {
		t.Fatalf("Generate() error: %v", err)
	}

	var log sarifLog
	if err := json.Unmarshal(buf.Bytes(), &log); err != nil {
		t.Fatalf("Output is not valid JSON: %v", err)
	}

	run := log.Runs[0]

	// Two unique policies → two rules.
	if len(run.Tool.Driver.Rules) != 2 {
		t.Errorf("Rules count = %d, want 2 (deduplicated by PolicyID)", len(run.Tool.Driver.Rules))
	}

	// Three findings → three results.
	if len(run.Results) != 3 {
		t.Errorf("Results count = %d, want 3", len(run.Results))
	}

	// Verify rule index references are correct.
	for _, r := range run.Results {
		if r.RuleIndex < 0 || r.RuleIndex >= len(run.Tool.Driver.Rules) {
			t.Errorf("Result %q has out-of-range RuleIndex %d", r.RuleID, r.RuleIndex)
		}
		if run.Tool.Driver.Rules[r.RuleIndex].ID != r.RuleID {
			t.Errorf("Result.RuleID %q does not match Rules[%d].ID %q", r.RuleID, r.RuleIndex, run.Tool.Driver.Rules[r.RuleIndex].ID)
		}
	}

	// Driver version should be empty with nil snapshot.
	if run.Tool.Driver.Version != "" {
		t.Errorf("Driver.Version = %q, want empty for nil snapshot", run.Tool.Driver.Version)
	}
}

func TestReporterGenerateNilSnapshot(t *testing.T) {
	findings := []finding.Finding{
		{
			ID:       "TEST-001",
			PolicyID: "TEST-001",
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

	var log sarifLog
	if err := json.Unmarshal(buf.Bytes(), &log); err != nil {
		t.Fatalf("Output is not valid JSON: %v", err)
	}

	run := log.Runs[0]
	if run.Tool.Driver.Version != "" {
		t.Errorf("Driver.Version should be empty when snapshot is nil, got %q", run.Tool.Driver.Version)
	}

	// Low severity → "note" level.
	if len(run.Results) != 1 {
		t.Fatalf("Results count = %d, want 1", len(run.Results))
	}
	if run.Results[0].Level != "note" {
		t.Errorf("Level = %q, want %q for Low severity", run.Results[0].Level, "note")
	}
}

func TestReporterGenerateEmpty(t *testing.T) {
	var buf bytes.Buffer
	reporter := &Reporter{}
	err := reporter.Generate(&buf, nil, nil)
	if err != nil {
		t.Fatalf("Generate() error: %v", err)
	}

	var log sarifLog
	if err := json.Unmarshal(buf.Bytes(), &log); err != nil {
		t.Fatalf("Output is not valid JSON: %v", err)
	}

	run := log.Runs[0]
	if len(run.Tool.Driver.Rules) != 0 {
		t.Errorf("Rules count = %d, want 0 for empty findings", len(run.Tool.Driver.Rules))
	}
	if len(run.Results) != 0 {
		t.Errorf("Results count = %d, want 0 for empty findings", len(run.Results))
	}
}

func TestSeverityToLevel(t *testing.T) {
	tests := []struct {
		severity finding.Severity
		want     string
	}{
		{finding.Critical, "error"},
		{finding.High, "error"},
		{finding.Medium, "warning"},
		{finding.Low, "note"},
		{finding.Info, "note"},
		{finding.Severity("UNKNOWN"), "warning"},
	}

	for _, tc := range tests {
		t.Run(string(tc.severity), func(t *testing.T) {
			got := severityToLevel(tc.severity)
			if got != tc.want {
				t.Errorf("severityToLevel(%q) = %q, want %q", tc.severity, got, tc.want)
			}
		})
	}
}

func TestSlugify(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"Test Finding", "TestFinding"},
		{"ACL Missing Script", "AclMissingScript"},
		{"a b c d e f g h", "ABCDE"},                 // capped at 5 words
		{"special-chars! @here", "SpecialcharsHere"}, // strips non-alphanum
		{"", "UnknownRule"},
		{"!!! @@@", "UnknownRule"},
	}

	for _, tc := range tests {
		t.Run(tc.input, func(t *testing.T) {
			got := slugify(tc.input)
			if got != tc.want {
				t.Errorf("slugify(%q) = %q, want %q", tc.input, got, tc.want)
			}
		})
	}
}

func TestBuildMessage(t *testing.T) {
	f := finding.Finding{
		Title:    "Test Title",
		Resource: "sys_table:abc",
	}
	got := buildMessage(f)
	want := "Test Title — resource: sys_table:abc"
	if got != want {
		t.Errorf("buildMessage() = %q, want %q", got, want)
	}

	// Without resource.
	f2 := finding.Finding{Title: "No Resource"}
	got2 := buildMessage(f2)
	if got2 != "No Resource" {
		t.Errorf("buildMessage() = %q, want %q", got2, "No Resource")
	}
}

func TestResultNoLocationWhenResourceEmpty(t *testing.T) {
	findings := []finding.Finding{
		{
			ID:       "TEST-001",
			PolicyID: "TEST-001",
			Title:    "No Resource Finding",
			Severity: finding.Info,
			Category: "Test",
			Resource: "", // empty resource
		},
	}

	var buf bytes.Buffer
	reporter := &Reporter{}
	if err := reporter.Generate(&buf, findings, nil); err != nil {
		t.Fatalf("Generate() error: %v", err)
	}

	var log sarifLog
	if err := json.Unmarshal(buf.Bytes(), &log); err != nil {
		t.Fatalf("Output is not valid JSON: %v", err)
	}

	result := log.Runs[0].Results[0]
	if len(result.Locations) != 0 {
		t.Errorf("Locations count = %d, want 0 when resource is empty", len(result.Locations))
	}
}
