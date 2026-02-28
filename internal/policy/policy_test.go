package policy

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/PiotrMackowski/ClosedSSPM/internal/collector"
	"github.com/PiotrMackowski/ClosedSSPM/internal/finding"
)

func TestLoadPolicies(t *testing.T) {
	// Use the actual policy directory.
	dir := filepath.Join("..", "..", "policies", "servicenow")
	policies, err := LoadPolicies(dir)
	if err != nil {
		t.Fatalf("LoadPolicies() error: %v", err)
	}

	if len(policies) != 40 {
		t.Errorf("LoadPolicies() returned %d policies, want 40", len(policies))
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
	if f.Evidence[0].SysID != "rec2" {
		t.Errorf("Evidence SysID = %q, want %q", f.Evidence[0].SysID, "rec2")
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
