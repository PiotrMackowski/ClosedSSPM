package policy

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/PiotrMackowski/ClosedSSPM/internal/collector"
	"github.com/PiotrMackowski/ClosedSSPM/internal/finding"
	"github.com/PiotrMackowski/ClosedSSPM/policies"
)

func TestLoadPolicies(t *testing.T) {
	// Use the actual policy directory.
	dir := filepath.Join("..", "..", "policies", "servicenow")
	policies, err := LoadPolicies(dir)
	if err != nil {
		t.Fatalf("LoadPolicies() error: %v", err)
	}

	if len(policies) != 86 {
		t.Errorf("LoadPolicies() returned %d policies, want 86", len(policies))
	}

	// Check that all policies have required fields.
	for _, p := range policies {
		if p.ID == "" {
			t.Error("Policy has empty ID")
		}
		if p.Title == "" {
			t.Errorf("Policy %s has empty Title", p.ID)
		}
		if p.Description == "" {
			t.Errorf("Policy %s has empty Description", p.ID)
		}
		if p.Severity == "" {
			t.Errorf("Policy %s has empty Severity", p.ID)
		}
		if p.Category == "" {
			t.Errorf("Policy %s has empty Category", p.ID)
		}
		if p.Platform == "" {
			t.Errorf("Policy %s has empty Platform", p.ID)
		}
		if p.Query.Table == "" {
			t.Errorf("Policy %s has empty Query.Table", p.ID)
		}
		if p.Remediation == "" {
			t.Errorf("Policy %s has empty Remediation", p.ID)
		}
	}
}

func TestLoadPoliciesFromTempDir(t *testing.T) {
	dir := t.TempDir()

	// Write a test policy.
	yamlContent := `
id: TEST-001
title: "Test policy"
description: "A test policy for unit testing"
severity: HIGH
category: Test
platform: test
query:
  table: test_table
  field_conditions:
    - field: "status"
      operator: "equals"
      value: "active"
remediation: "Fix the thing"
references:
  - "https://example.com"
`
	err := os.WriteFile(filepath.Join(dir, "test_001.yaml"), []byte(yamlContent), 0644)
	if err != nil {
		t.Fatalf("WriteFile error: %v", err)
	}

	policies, err := LoadPolicies(dir)
	if err != nil {
		t.Fatalf("LoadPolicies() error: %v", err)
	}

	if len(policies) != 1 {
		t.Fatalf("LoadPolicies() returned %d policies, want 1", len(policies))
	}

	p := policies[0]
	if p.ID != "TEST-001" {
		t.Errorf("ID = %q, want %q", p.ID, "TEST-001")
	}
	if p.Title != "Test policy" {
		t.Errorf("Title = %q, want %q", p.Title, "Test policy")
	}
	if p.Severity != finding.High {
		t.Errorf("Severity = %q, want %q", p.Severity, finding.High)
	}
	if p.Query.Table != "test_table" {
		t.Errorf("Query.Table = %q, want %q", p.Query.Table, "test_table")
	}
	if len(p.Query.FieldConditions) != 1 {
		t.Fatalf("FieldConditions count = %d, want 1", len(p.Query.FieldConditions))
	}
	if p.Query.FieldConditions[0].Operator != "equals" {
		t.Errorf("FieldConditions[0].Operator = %q, want %q", p.Query.FieldConditions[0].Operator, "equals")
	}
}

func TestLoadPoliciesEmptyDir(t *testing.T) {
	dir := t.TempDir()
	policies, err := LoadPolicies(dir)
	if err != nil {
		t.Fatalf("LoadPolicies() error: %v", err)
	}
	if len(policies) != 0 {
		t.Errorf("LoadPolicies() returned %d policies for empty dir, want 0", len(policies))
	}
}

func TestLoadPoliciesNoIDError(t *testing.T) {
	dir := t.TempDir()

	yamlContent := `
title: "No ID policy"
severity: HIGH
category: Test
platform: test
query:
  table: test_table
remediation: "Fix it"
`
	err := os.WriteFile(filepath.Join(dir, "bad.yaml"), []byte(yamlContent), 0644)
	if err != nil {
		t.Fatalf("WriteFile error: %v", err)
	}

	_, err = LoadPolicies(dir)
	if err == nil {
		t.Error("LoadPolicies() should error for policy with no ID")
	}
}

func TestPolicyIsEnabled(t *testing.T) {
	// Default (nil) => enabled.
	p := Policy{}
	if !p.IsEnabled() {
		t.Error("Default policy should be enabled")
	}

	// Explicitly true.
	trueVal := true
	p.Enabled = &trueVal
	if !p.IsEnabled() {
		t.Error("Explicitly enabled policy should be enabled")
	}

	// Explicitly false.
	falseVal := false
	p.Enabled = &falseVal
	if p.IsEnabled() {
		t.Error("Explicitly disabled policy should not be enabled")
	}
}

func TestEvaluatePolicy(t *testing.T) {
	policies := []Policy{
		{
			ID:          "TEST-001",
			Title:       "Test empty field",
			Description: "Tests that empty fields are flagged",
			Severity:    finding.High,
			Category:    "Test",
			Platform:    "test",
			Query: QuerySpec{
				Table: "test_table",
				FieldConditions: []FieldCondition{
					{Field: "condition", Operator: "empty"},
					{Field: "active", Operator: "equals", Value: "true"},
				},
			},
			Remediation: "Fix it",
		},
	}

	snapshot := collector.NewSnapshot("test", "https://test.example.com")
	snapshot.AddTableData(&collector.TableData{
		Table: "test_table",
		Records: []collector.Record{
			{"sys_id": "rec1", "name": "good_record", "condition": "has_value", "active": "true"},
			{"sys_id": "rec2", "name": "bad_record", "condition": "", "active": "true"},
			{"sys_id": "rec3", "name": "inactive_bad", "condition": "", "active": "false"},
		},
		Count: 3,
	})

	evaluator := NewEvaluator(policies)
	findings, err := evaluator.Evaluate(snapshot)
	if err != nil {
		t.Fatalf("Evaluate() error: %v", err)
	}

	// Only rec2 should match (empty condition + active=true).
	if len(findings) != 1 {
		t.Fatalf("Evaluate() returned %d findings, want 1", len(findings))
	}

	f := findings[0]
	if f.PolicyID != "TEST-001" {
		t.Errorf("PolicyID = %q, want %q", f.PolicyID, "TEST-001")
	}
	if f.Severity != finding.High {
		t.Errorf("Severity = %q, want %q", f.Severity, finding.High)
	}
	if len(f.Evidence) != 1 {
		t.Fatalf("Evidence count = %d, want 1", len(f.Evidence))
	}
	if f.Evidence[0].ResourceID != "rec2" {
		t.Errorf("Evidence ResourceID = %q, want %q", f.Evidence[0].ResourceID, "rec2")
	}
}

func TestEvaluateMultipleOperators(t *testing.T) {
	policies := []Policy{
		{
			ID:       "TEST-NOT-EMPTY",
			Title:    "Not empty test",
			Severity: finding.Medium,
			Category: "Test",
			Platform: "test",
			Query: QuerySpec{
				Table: "test_table",
				FieldConditions: []FieldCondition{
					{Field: "name", Operator: "not_empty"},
				},
			},
			Remediation: "Fix",
		},
		{
			ID:       "TEST-NOT-EQUALS",
			Title:    "Not equals test",
			Severity: finding.Low,
			Category: "Test",
			Platform: "test",
			Query: QuerySpec{
				Table: "test_table",
				FieldConditions: []FieldCondition{
					{Field: "status", Operator: "not_equals", Value: "active"},
				},
			},
			Remediation: "Fix",
		},
		{
			ID:       "TEST-CONTAINS",
			Title:    "Contains test",
			Severity: finding.Info,
			Category: "Test",
			Platform: "test",
			Query: QuerySpec{
				Table: "test_table",
				FieldConditions: []FieldCondition{
					{Field: "role", Operator: "contains", Value: "admin"},
				},
			},
			Remediation: "Fix",
		},
	}

	snapshot := collector.NewSnapshot("test", "https://test.example.com")
	snapshot.AddTableData(&collector.TableData{
		Table: "test_table",
		Records: []collector.Record{
			{"sys_id": "r1", "name": "record1", "status": "active", "role": "user"},
			{"sys_id": "r2", "name": "", "status": "inactive", "role": "admin"},
			{"sys_id": "r3", "name": "record3", "status": "disabled", "role": "super_admin_role"},
		},
		Count: 3,
	})

	evaluator := NewEvaluator(policies)
	findings, err := evaluator.Evaluate(snapshot)
	if err != nil {
		t.Fatalf("Evaluate() error: %v", err)
	}

	// Count findings per policy.
	counts := make(map[string]int)
	for _, f := range findings {
		counts[f.PolicyID]++
	}

	// NOT_EMPTY: r1 and r3 have non-empty names.
	if counts["TEST-NOT-EMPTY"] != 2 {
		t.Errorf("TEST-NOT-EMPTY findings = %d, want 2", counts["TEST-NOT-EMPTY"])
	}

	// NOT_EQUALS active: r2 (inactive) and r3 (disabled).
	if counts["TEST-NOT-EQUALS"] != 2 {
		t.Errorf("TEST-NOT-EQUALS findings = %d, want 2", counts["TEST-NOT-EQUALS"])
	}

	// CONTAINS admin: r2 (admin) and r3 (super_admin_role).
	if counts["TEST-CONTAINS"] != 2 {
		t.Errorf("TEST-CONTAINS findings = %d, want 2", counts["TEST-CONTAINS"])
	}
}

func TestEvaluateDisabledPolicy(t *testing.T) {
	falseVal := false
	policies := []Policy{
		{
			ID:       "TEST-DISABLED",
			Title:    "Disabled policy",
			Severity: finding.Critical,
			Category: "Test",
			Platform: "test",
			Enabled:  &falseVal,
			Query: QuerySpec{
				Table: "test_table",
				FieldConditions: []FieldCondition{
					{Field: "active", Operator: "equals", Value: "true"},
				},
			},
			Remediation: "Fix",
		},
	}

	snapshot := collector.NewSnapshot("test", "https://test.example.com")
	snapshot.AddTableData(&collector.TableData{
		Table:   "test_table",
		Records: []collector.Record{{"sys_id": "r1", "active": "true"}},
		Count:   1,
	})

	evaluator := NewEvaluator(policies)
	findings, err := evaluator.Evaluate(snapshot)
	if err != nil {
		t.Fatalf("Evaluate() error: %v", err)
	}

	if len(findings) != 0 {
		t.Errorf("Disabled policy should produce 0 findings, got %d", len(findings))
	}
}

func TestEvaluateMissingTable(t *testing.T) {
	policies := []Policy{
		{
			ID:       "TEST-MISSING",
			Title:    "Missing table test",
			Severity: finding.High,
			Category: "Test",
			Platform: "test",
			Query: QuerySpec{
				Table: "nonexistent_table",
			},
			Remediation: "Fix",
		},
	}

	snapshot := collector.NewSnapshot("test", "https://test.example.com")

	evaluator := NewEvaluator(policies)
	findings, err := evaluator.Evaluate(snapshot)
	if err != nil {
		t.Fatalf("Evaluate() error: %v", err)
	}

	if len(findings) != 0 {
		t.Errorf("Missing table should produce 0 findings, got %d", len(findings))
	}
}

func TestEvaluateDisplayValueObject(t *testing.T) {
	policies := []Policy{
		{
			ID:       "TEST-DV",
			Title:    "Display value test",
			Severity: finding.Low,
			Category: "Test",
			Platform: "test",
			Query: QuerySpec{
				Table: "test_table",
				FieldConditions: []FieldCondition{
					{Field: "role", Operator: "contains", Value: "admin"},
				},
			},
			Remediation: "Fix",
		},
	}

	snapshot := collector.NewSnapshot("test", "https://test.example.com")
	snapshot.AddTableData(&collector.TableData{
		Table: "test_table",
		Records: []collector.Record{
			{
				"sys_id": "r1",
				"name":   "test",
				"role": map[string]interface{}{
					"display_value": "admin",
					"value":         "abc123",
				},
			},
		},
		Count: 1,
	})

	evaluator := NewEvaluator(policies)
	findings, err := evaluator.Evaluate(snapshot)
	if err != nil {
		t.Fatalf("Evaluate() error: %v", err)
	}

	// The display_value "admin" should match the contains condition.
	if len(findings) != 1 {
		t.Errorf("Display value object should match, got %d findings, want 1", len(findings))
	}
}

func TestEvaluateMatchesRegex(t *testing.T) {
	policies := []Policy{
		{
			ID:       "TEST-REGEX",
			Title:    "Regex match test",
			Severity: finding.High,
			Category: "Test",
			Platform: "test",
			Query: QuerySpec{
				Table: "test_table",
				FieldConditions: []FieldCondition{
					{Field: "script", Operator: "matches_regex", Value: `(?i)password\s*=\s*["'][^"']{8,}["']`},
				},
			},
			Remediation: "Fix",
		},
		{
			ID:       "TEST-NOT-REGEX",
			Title:    "Not regex match test",
			Severity: finding.Medium,
			Category: "Test",
			Platform: "test",
			Query: QuerySpec{
				Table: "test_table",
				FieldConditions: []FieldCondition{
					{Field: "url", Operator: "not_matches_regex", Value: `^https://`},
				},
			},
			Remediation: "Fix",
		},
	}

	snapshot := collector.NewSnapshot("test", "https://test.example.com")
	snapshot.AddTableData(&collector.TableData{
		Table: "test_table",
		Records: []collector.Record{
			{"sys_id": "r1", "name": "hardcoded_pass", "script": `var password = "SuperSecret123"`, "url": "https://secure.example.com"},
			{"sys_id": "r2", "name": "safe_script", "script": "var x = gs.getProperty('key')", "url": "http://insecure.example.com"},
			{"sys_id": "r3", "name": "also_hardcoded", "script": `Password = "MyP@ssw0rd!"`, "url": ""},
		},
		Count: 3,
	})

	evaluator := NewEvaluator(policies)
	findings, err := evaluator.Evaluate(snapshot)
	if err != nil {
		t.Fatalf("Evaluate() error: %v", err)
	}

	counts := make(map[string]int)
	for _, f := range findings {
		counts[f.PolicyID]++
	}

	// MATCHES_REGEX: r1 (password = "SuperSecret123") and r3 (Password = "MyP@ssw0rd!") should match.
	if counts["TEST-REGEX"] != 2 {
		t.Errorf("TEST-REGEX findings = %d, want 2", counts["TEST-REGEX"])
	}

	// NOT_MATCHES_REGEX (url not starting with https://): r2 (http://) and r3 (empty).
	if counts["TEST-NOT-REGEX"] != 2 {
		t.Errorf("TEST-NOT-REGEX findings = %d, want 2", counts["TEST-NOT-REGEX"])
	}
}

func TestEvaluateInvalidRegex(t *testing.T) {
	policies := []Policy{
		{
			ID:       "TEST-BAD-REGEX",
			Title:    "Invalid regex test",
			Severity: finding.Low,
			Category: "Test",
			Platform: "test",
			Query: QuerySpec{
				Table: "test_table",
				FieldConditions: []FieldCondition{
					{Field: "script", Operator: "matches_regex", Value: `[invalid(`},
				},
			},
			Remediation: "Fix",
		},
	}

	snapshot := collector.NewSnapshot("test", "https://test.example.com")
	snapshot.AddTableData(&collector.TableData{
		Table:   "test_table",
		Records: []collector.Record{{"sys_id": "r1", "script": "anything"}},
		Count:   1,
	})

	evaluator := NewEvaluator(policies)
	findings, err := evaluator.Evaluate(snapshot)
	if err != nil {
		t.Fatalf("Evaluate() error: %v", err)
	}

	// Invalid regex should produce 0 findings (treated as non-match).
	if len(findings) != 0 {
		t.Errorf("Invalid regex should produce 0 findings, got %d", len(findings))
	}
}

func TestEvaluatePlatformFiltering(t *testing.T) {
	policies := []Policy{
		{
			ID:       "SF-001",
			Title:    "Snowflake policy",
			Severity: finding.High,
			Category: "IAM",
			Platform: "snowflake",
			Query: QuerySpec{
				Table: "users",
				FieldConditions: []FieldCondition{
					{Field: "email", Operator: "empty"},
				},
			},
			Remediation: "Fix",
		},
		{
			ID:       "GW-001",
			Title:    "Google Workspace policy",
			Severity: finding.Critical,
			Category: "OAuth",
			Platform: "googleworkspace",
			Query: QuerySpec{
				Table: "users",
				FieldConditions: []FieldCondition{
					{Field: "email", Operator: "empty"},
				},
			},
			Remediation: "Fix",
		},
		{
			ID:       "GENERIC-001",
			Title:    "Platform-agnostic policy",
			Severity: finding.Low,
			Category: "General",
			Platform: "",
			Query: QuerySpec{
				Table: "users",
				FieldConditions: []FieldCondition{
					{Field: "email", Operator: "empty"},
				},
			},
			Remediation: "Fix",
		},
	}

	snapshot := collector.NewSnapshot("googleworkspace", "https://googleapis.com")
	snapshot.AddTableData(&collector.TableData{
		Table:   "users",
		Records: []collector.Record{{"sys_id": "u1", "name": "test_user", "email": ""}},
		Count:   1,
	})

	evaluator := NewEvaluator(policies)
	findings, err := evaluator.Evaluate(snapshot)
	if err != nil {
		t.Fatalf("Evaluate() error: %v", err)
	}

	// Should get GW-001 (matching platform) and GENERIC-001 (no platform = matches all).
	// Should NOT get SF-001 (wrong platform).
	ids := make(map[string]bool)
	for _, f := range findings {
		ids[f.PolicyID] = true
	}

	if ids["SF-001"] {
		t.Error("Snowflake policy SF-001 should NOT fire on googleworkspace snapshot")
	}
	if !ids["GW-001"] {
		t.Error("Google Workspace policy GW-001 should fire on googleworkspace snapshot")
	}
	if !ids["GENERIC-001"] {
		t.Error("Platform-agnostic policy GENERIC-001 should fire on any snapshot")
	}
	if len(findings) != 2 {
		t.Errorf("Expected 2 findings, got %d", len(findings))
	}
}

func TestLoadPoliciesFS(t *testing.T) {
	// Load from embedded filesystem.
	pols, err := LoadPoliciesFS(policies.Embedded, ".")
	if err != nil {
		t.Fatalf("LoadPoliciesFS() error: %v", err)
	}

	if len(pols) != 166 {
		t.Errorf("LoadPoliciesFS() returned %d policies, want 166", len(pols))
	}

	// Verify all policies have required fields.
	for _, p := range pols {
		if p.ID == "" {
			t.Error("Embedded policy has empty ID")
		}
		if p.Title == "" {
			t.Errorf("Embedded policy %s has empty Title", p.ID)
		}
		if p.Severity == "" {
			t.Errorf("Embedded policy %s has empty Severity", p.ID)
		}
	}
}

func TestEvaluateNotContains(t *testing.T) {
	pol := []Policy{
		{
			ID:       "TEST-NOT-CONTAINS",
			Title:    "Not contains test",
			Severity: finding.Medium,
			Category: "Test",
			Platform: "test",
			Query: QuerySpec{
				Table: "test_table",
				FieldConditions: []FieldCondition{
					{Field: "role", Operator: "not_contains", Value: "admin"},
				},
			},
			Remediation: "Fix",
		},
	}

	snapshot := collector.NewSnapshot("test", "https://test.example.com")
	snapshot.AddTableData(&collector.TableData{
		Table: "test_table",
		Records: []collector.Record{
			{"sys_id": "r1", "role": "user"},
			{"sys_id": "r2", "role": "admin"},
			{"sys_id": "r3", "role": "super_admin_role"},
			{"sys_id": "r4", "role": "readonly"},
		},
		Count: 4,
	})

	evaluator := NewEvaluator(pol)
	findings, err := evaluator.Evaluate(snapshot)
	if err != nil {
		t.Fatalf("Evaluate() error: %v", err)
	}

	ids := make(map[string]bool)
	for _, f := range findings {
		for _, e := range f.Evidence {
			ids[e.ResourceID] = true
		}
	}

	if ids["r2"] || ids["r3"] {
		t.Error("Records containing 'admin' should NOT match not_contains")
	}
	if !ids["r1"] || !ids["r4"] {
		t.Error("Records without 'admin' should match not_contains")
	}
	if len(findings) != 2 {
		t.Errorf("Expected 2 findings (r1, r4), got %d", len(findings))
	}
}

func TestEvaluateGreaterThanLessThan(t *testing.T) {
	pols := []Policy{
		{
			ID:       "TEST-GT",
			Title:    "Greater than test",
			Severity: finding.High,
			Category: "Test",
			Platform: "test",
			Query: QuerySpec{
				Table: "test_table",
				FieldConditions: []FieldCondition{
					{Field: "score", Operator: "greater_than", Value: "80"},
				},
			},
			Remediation: "Fix",
		},
		{
			ID:       "TEST-LT",
			Title:    "Less than test",
			Severity: finding.Low,
			Category: "Test",
			Platform: "test",
			Query: QuerySpec{
				Table: "test_table",
				FieldConditions: []FieldCondition{
					{Field: "score", Operator: "less_than", Value: "50"},
				},
			},
			Remediation: "Fix",
		},
	}

	snapshot := collector.NewSnapshot("test", "https://test.example.com")
	snapshot.AddTableData(&collector.TableData{
		Table: "test_table",
		Records: []collector.Record{
			{"sys_id": "r1", "score": "90"},
			{"sys_id": "r2", "score": "50"},
			{"sys_id": "r3", "score": "30"},
			{"sys_id": "r4", "score": "80"},
			{"sys_id": "r5", "score": "not_a_number"},
			{"sys_id": "r6", "score": ""},
		},
		Count: 6,
	})

	evaluator := NewEvaluator(pols)
	findings, err := evaluator.Evaluate(snapshot)
	if err != nil {
		t.Fatalf("Evaluate() error: %v", err)
	}

	counts := make(map[string][]string)
	for _, f := range findings {
		for _, e := range f.Evidence {
			counts[f.PolicyID] = append(counts[f.PolicyID], e.ResourceID)
		}
	}

	// greater_than 80: only r1 (90). r4 is 80, not strictly greater.
	if len(counts["TEST-GT"]) != 1 || counts["TEST-GT"][0] != "r1" {
		t.Errorf("TEST-GT: expected [r1], got %v", counts["TEST-GT"])
	}

	// less_than 50: only r3 (30). r2 is 50, not strictly less. Non-numeric/empty → no match.
	if len(counts["TEST-LT"]) != 1 || counts["TEST-LT"][0] != "r3" {
		t.Errorf("TEST-LT: expected [r3], got %v", counts["TEST-LT"])
	}
}

func TestEvaluateGreaterThanFloats(t *testing.T) {
	pol := []Policy{
		{
			ID:       "TEST-GT-FLOAT",
			Title:    "Float greater than",
			Severity: finding.Medium,
			Category: "Test",
			Platform: "test",
			Query: QuerySpec{
				Table: "test_table",
				FieldConditions: []FieldCondition{
					{Field: "rate", Operator: "greater_than", Value: "0.5"},
				},
			},
			Remediation: "Fix",
		},
	}

	snapshot := collector.NewSnapshot("test", "https://test.example.com")
	snapshot.AddTableData(&collector.TableData{
		Table: "test_table",
		Records: []collector.Record{
			{"sys_id": "r1", "rate": "0.75"},
			{"sys_id": "r2", "rate": "0.5"},
			{"sys_id": "r3", "rate": "0.25"},
		},
		Count: 3,
	})

	evaluator := NewEvaluator(pol)
	findings, err := evaluator.Evaluate(snapshot)
	if err != nil {
		t.Fatalf("Evaluate() error: %v", err)
	}

	if len(findings) != 1 || len(findings[0].Evidence) != 1 || findings[0].Evidence[0].ResourceID != "r1" {
		t.Errorf("Expected only r1 (0.75 > 0.5), got %d findings", len(findings))
	}
}
