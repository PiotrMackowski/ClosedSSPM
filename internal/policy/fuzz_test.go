package policy

import (
	"testing"
	"testing/fstest"

	"github.com/PiotrMackowski/ClosedSSPM/internal/collector"
)

// FuzzLoadPoliciesYAML feeds random bytes as YAML policy files to LoadPoliciesFS.
// It exercises the YAML parser, policy validation, and fs.WalkDir traversal.
// A crash or panic is a bug; parse errors are expected and fine.
func FuzzLoadPoliciesYAML(f *testing.F) {
	// Seed corpus: valid policy YAML
	f.Add([]byte(`id: FUZZ-001
title: "Fuzz seed policy"
description: "A valid policy for seeding the fuzzer"
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
`))
	// Seed: minimal valid policy
	f.Add([]byte(`id: FUZZ-002
title: "Minimal"
description: "min"
severity: LOW
category: X
platform: y
query:
  table: t
remediation: "r"
`))
	// Seed: policy with regex condition
	f.Add([]byte(`id: FUZZ-003
title: "Regex policy"
description: "Policy with regex"
severity: MEDIUM
category: Security
platform: servicenow
query:
  table: sys_script
  field_conditions:
    - field: "script"
      operator: "matches_regex"
      value: "(?i)password"
remediation: "Remove hardcoded creds"
`))
	// Seed: empty bytes
	f.Add([]byte{})
	// Seed: invalid YAML
	f.Add([]byte(`{{{not yaml at all`))
	// Seed: valid YAML but missing required fields
	f.Add([]byte(`title: "no id"`))

	f.Fuzz(func(t *testing.T, data []byte) {
		fsys := fstest.MapFS{
			"fuzz_policy.yaml": &fstest.MapFile{Data: data},
		}
		// We don't care about errors — only panics/crashes are bugs.
		_, _ = LoadPoliciesFS(fsys, ".")
	})
}

// FuzzMatchesFieldConditions feeds random operator/value/field combinations
// to matchesFieldConditions, exercising all operator branches including
// regex compilation and matching.
func FuzzMatchesFieldConditions(f *testing.F) {
	// Seed: simple equals
	f.Add("status", "equals", "active", "active")
	// Seed: empty operator
	f.Add("field", "empty", "", "")
	// Seed: not_empty with value
	f.Add("name", "not_empty", "", "hello")
	// Seed: contains
	f.Add("role", "contains", "admin", "super_admin")
	// Seed: not_equals
	f.Add("status", "not_equals", "active", "inactive")
	// Seed: matches_regex with valid regex
	f.Add("script", "matches_regex", `(?i)password\s*=`, `password = "secret"`)
	// Seed: not_matches_regex
	f.Add("url", "not_matches_regex", `^https://`, "http://example.com")
	// Seed: invalid regex pattern
	f.Add("field", "matches_regex", `[invalid(`, "anything")
	// Seed: unknown operator
	f.Add("field", "bogus_op", "val", "data")

	f.Fuzz(func(t *testing.T, field, operator, condValue, fieldValue string) {
		record := collector.Record{
			field: fieldValue,
		}
		conditions := []FieldCondition{
			{Field: field, Operator: operator, Value: condValue},
		}
		// Only panics are bugs. Return value doesn't matter.
		_ = matchesFieldConditions(record, conditions)
	})
}
