// Package sarif generates SARIF 2.1.0 reports for GitHub Code Scanning integration.
//
// SARIF (Static Analysis Results Interchange Format) is an OASIS standard for
// the output format of static analysis tools. This implementation uses
// logicalLocations (not physicalLocations) because ClosedSSPM findings refer
// to SaaS configuration resources rather than source-code files.
package sarif

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"github.com/PiotrMackowski/ClosedSSPM/internal/collector"
	"github.com/PiotrMackowski/ClosedSSPM/internal/finding"
)

// --- SARIF 2.1.0 JSON schema types (hand-rolled, zero dependencies) ---

type sarifLog struct {
	Schema  string     `json:"$schema"`
	Version string     `json:"version"`
	Runs    []sarifRun `json:"runs"`
}

type sarifRun struct {
	Tool    sarifTool     `json:"tool"`
	Results []sarifResult `json:"results"`
}

type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}

type sarifDriver struct {
	Name           string      `json:"name"`
	InformationURI string      `json:"informationUri"`
	Version        string      `json:"version,omitempty"`
	Rules          []sarifRule `json:"rules"`
}

type sarifRule struct {
	ID               string                 `json:"id"`
	Name             string                 `json:"name"`
	ShortDescription sarifMessage           `json:"shortDescription"`
	FullDescription  sarifMessage           `json:"fullDescription,omitempty"`
	HelpURI          string                 `json:"helpUri,omitempty"`
	Help             *sarifMessage          `json:"help,omitempty"`
	DefaultConfig    *sarifDefaultConfig    `json:"defaultConfiguration,omitempty"`
	Properties       map[string]interface{} `json:"properties,omitempty"`
}

type sarifDefaultConfig struct {
	Level string `json:"level"`
}

type sarifMessage struct {
	Text string `json:"text"`
}

type sarifResult struct {
	RuleID    string          `json:"ruleId"`
	RuleIndex int             `json:"ruleIndex"`
	Level     string          `json:"level"`
	Message   sarifMessage    `json:"message"`
	Locations []sarifLocation `json:"locations,omitempty"`
	Fixes     []interface{}   `json:"fixes,omitempty"`
}

type sarifLocation struct {
	LogicalLocations []sarifLogicalLocation `json:"logicalLocations,omitempty"`
}

type sarifLogicalLocation struct {
	Name               string `json:"name"`
	FullyQualifiedName string `json:"fullyQualifiedName"`
	Kind               string `json:"kind,omitempty"`
}

// --- Reporter ---

// Reporter generates SARIF 2.1.0 reports.
type Reporter struct{}

// Generate writes a SARIF report to the given writer.
func (r *Reporter) Generate(w io.Writer, findings []finding.Finding, snapshot *collector.Snapshot) error {
	// Build rule index: policyID → index.
	ruleIndex := map[string]int{}
	var rules []sarifRule

	for _, f := range findings {
		if _, ok := ruleIndex[f.PolicyID]; ok {
			continue
		}
		idx := len(rules)
		ruleIndex[f.PolicyID] = idx

		rule := sarifRule{
			ID:               f.PolicyID,
			Name:             slugify(f.Title),
			ShortDescription: sarifMessage{Text: f.Title},
			DefaultConfig:    &sarifDefaultConfig{Level: severityToLevel(f.Severity)},
			Properties: map[string]interface{}{
				"tags":     []string{"security", "saas", strings.ToLower(f.Category)},
				"severity": string(f.Severity),
			},
		}
		if f.Description != "" {
			rule.FullDescription = sarifMessage{Text: f.Description}
		}
		if len(f.References) > 0 {
			rule.HelpURI = f.References[0]
		}
		if f.Remediation != "" {
			rule.Help = &sarifMessage{Text: f.Remediation}
		}
		rules = append(rules, rule)
	}

	// Build results.
	results := make([]sarifResult, 0, len(findings))
	for _, f := range findings {
		result := sarifResult{
			RuleID:    f.PolicyID,
			RuleIndex: ruleIndex[f.PolicyID],
			Level:     severityToLevel(f.Severity),
			Message:   sarifMessage{Text: buildMessage(f)},
		}

		if f.Resource != "" {
			result.Locations = []sarifLocation{{
				LogicalLocations: []sarifLogicalLocation{{
					Name:               f.Resource,
					FullyQualifiedName: f.Resource,
					Kind:               "resource",
				}},
			}}
		}

		results = append(results, result)
	}

	driverVersion := ""
	if snapshot != nil && snapshot.Platform != "" {
		driverVersion = snapshot.Platform
	}

	log := sarifLog{
		Schema:  "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json",
		Version: "2.1.0",
		Runs: []sarifRun{{
			Tool: sarifTool{
				Driver: sarifDriver{
					Name:           "ClosedSSPM",
					InformationURI: "https://github.com/PiotrMackowski/ClosedSSPM",
					Version:        driverVersion,
					Rules:          rules,
				},
			},
			Results: results,
		}},
	}

	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	if err := enc.Encode(log); err != nil {
		return fmt.Errorf("encoding SARIF report: %w", err)
	}
	return nil
}

// severityToLevel maps ClosedSSPM severity to SARIF level.
// SARIF only defines: error, warning, note, none.
func severityToLevel(s finding.Severity) string {
	switch s {
	case finding.Critical, finding.High:
		return "error"
	case finding.Medium:
		return "warning"
	case finding.Low, finding.Info:
		return "note"
	default:
		return "warning"
	}
}

// buildMessage creates a human-readable result message from a finding.
func buildMessage(f finding.Finding) string {
	msg := f.Title
	if f.Resource != "" {
		msg += " — resource: " + f.Resource
	}
	return msg
}

// slugify converts a title to a PascalCase rule name.
func slugify(title string) string {
	words := strings.Fields(title)
	if len(words) == 0 {
		return "UnknownRule"
	}
	// Cap at 5 words to keep it short.
	if len(words) > 5 {
		words = words[:5]
	}
	var b strings.Builder
	for _, w := range words {
		// Strip non-alphanumeric.
		clean := strings.Map(func(r rune) rune {
			if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') {
				return r
			}
			return -1
		}, w)
		if clean == "" {
			continue
		}
		b.WriteString(strings.ToUpper(clean[:1]))
		if len(clean) > 1 {
			b.WriteString(strings.ToLower(clean[1:]))
		}
	}
	if b.Len() == 0 {
		return "UnknownRule"
	}
	return b.String()
}
