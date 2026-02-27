// Package policy defines the policy engine for evaluating audit checks.
package policy

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/PiotrMackowski/ClosedSSPM/internal/collector"
	"github.com/PiotrMackowski/ClosedSSPM/internal/finding"
	"gopkg.in/yaml.v3"
)

// FieldCondition describes a condition to check on a record field.
type FieldCondition struct {
	Field    string `yaml:"field"`
	Operator string `yaml:"operator"` // "empty", "not_empty", "equals", "not_equals", "contains", "regex", "greater_than", "less_than"
	Value    string `yaml:"value,omitempty"`
}

// QuerySpec defines how to select records from the snapshot.
type QuerySpec struct {
	Table           string           `yaml:"table"`
	Filter          string           `yaml:"filter,omitempty"`
	FieldConditions []FieldCondition `yaml:"field_conditions,omitempty"`
}

// Policy represents a single security audit check loaded from YAML.
type Policy struct {
	ID          string         `yaml:"id"`
	Title       string         `yaml:"title"`
	Description string         `yaml:"description"`
	Severity    finding.Severity `yaml:"severity"`
	Category    string         `yaml:"category"`
	Platform    string         `yaml:"platform"`
	Query       QuerySpec      `yaml:"query"`
	Remediation string         `yaml:"remediation"`
	References  []string       `yaml:"references,omitempty"`
	Enabled     *bool          `yaml:"enabled,omitempty"`
}

// IsEnabled returns whether the policy is enabled (defaults to true).
func (p *Policy) IsEnabled() bool {
	if p.Enabled == nil {
		return true
	}
	return *p.Enabled
}

// LoadPolicies loads all policy YAML files from a directory.
func LoadPolicies(dir string) ([]Policy, error) {
	var policies []Policy

	err := filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			return nil
		}
		ext := strings.ToLower(filepath.Ext(path))
		if ext != ".yaml" && ext != ".yml" {
			return nil
		}

		data, err := os.ReadFile(path)
		if err != nil {
			return fmt.Errorf("reading policy file %s: %w", path, err)
		}

		var p Policy
		if err := yaml.Unmarshal(data, &p); err != nil {
			return fmt.Errorf("parsing policy file %s: %w", path, err)
		}

		if p.ID == "" {
			return fmt.Errorf("policy in %s has no ID", path)
		}

		policies = append(policies, p)
		return nil
	})

	if err != nil {
		return nil, fmt.Errorf("loading policies from %s: %w", dir, err)
	}

	return policies, nil
}

// Evaluator evaluates policies against a snapshot to produce findings.
type Evaluator struct {
	policies []Policy
}

// NewEvaluator creates a new policy evaluator with the given policies.
func NewEvaluator(policies []Policy) *Evaluator {
	return &Evaluator{policies: policies}
}

// Evaluate runs all enabled policies against the snapshot and returns findings.
func (e *Evaluator) Evaluate(snapshot *collector.Snapshot) ([]finding.Finding, error) {
	var findings []finding.Finding

	for _, p := range e.policies {
		if !p.IsEnabled() {
			continue
		}

		policyFindings, err := e.evaluatePolicy(p, snapshot)
		if err != nil {
			return nil, fmt.Errorf("evaluating policy %s: %w", p.ID, err)
		}
		findings = append(findings, policyFindings...)
	}

	return findings, nil
}

// evaluatePolicy evaluates a single policy against the snapshot.
func (e *Evaluator) evaluatePolicy(p Policy, snapshot *collector.Snapshot) ([]finding.Finding, error) {
	records := snapshot.GetRecords(p.Query.Table)
	if records == nil {
		return nil, nil // Table not collected, skip
	}

	var findings []finding.Finding

	for _, record := range records {
		if !matchesFieldConditions(record, p.Query.FieldConditions) {
			continue
		}

		sysID := getStringField(record, "sys_id")
		displayValue := getStringField(record, "name")
		if displayValue == "" {
			displayValue = sysID
		}

		findingID := fmt.Sprintf("%s-%s", p.ID, sysID)
		if sysID == "" {
			findingID = p.ID
		}

		f := finding.Finding{
			ID:          findingID,
			PolicyID:    p.ID,
			Title:       p.Title,
			Description: p.Description,
			Severity:    p.Severity,
			Category:    p.Category,
			Resource:    fmt.Sprintf("%s:%s", p.Query.Table, sysID),
			Evidence: []finding.Evidence{
				{
					Table:        p.Query.Table,
					SysID:        sysID,
					DisplayValue: displayValue,
					Fields:       recordToStringMap(record),
				},
			},
			Remediation: p.Remediation,
			References:  p.References,
		}
		findings = append(findings, f)
	}

	return findings, nil
}

// matchesFieldConditions checks if a record matches all field conditions.
func matchesFieldConditions(record collector.Record, conditions []FieldCondition) bool {
	for _, cond := range conditions {
		val := getStringField(record, cond.Field)
		switch cond.Operator {
		case "empty":
			if val != "" {
				return false
			}
		case "not_empty":
			if val == "" {
				return false
			}
		case "equals":
			if val != cond.Value {
				return false
			}
		case "not_equals":
			if val == cond.Value {
				return false
			}
		case "contains":
			if !strings.Contains(val, cond.Value) {
				return false
			}
		default:
			// Unknown operator, skip condition
		}
	}
	return true
}

// getStringField extracts a string value from a record field.
// Handles both direct string values and ServiceNow display_value objects.
func getStringField(record collector.Record, field string) string {
	v, ok := record[field]
	if !ok {
		return ""
	}
	switch val := v.(type) {
	case string:
		return val
	case map[string]interface{}:
		// ServiceNow sometimes returns {display_value: "...", value: "..."}
		if dv, ok := val["display_value"]; ok {
			if s, ok := dv.(string); ok {
				return s
			}
		}
		if dv, ok := val["value"]; ok {
			if s, ok := dv.(string); ok {
				return s
			}
		}
	}
	return fmt.Sprintf("%v", v)
}

// recordToStringMap converts a record to a map of string values.
func recordToStringMap(record collector.Record) map[string]string {
	result := make(map[string]string)
	for k, v := range record {
		result[k] = fmt.Sprintf("%v", v)
	}
	return result
}
