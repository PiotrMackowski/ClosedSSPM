// Package json generates JSON audit reports.
package json

import (
	"encoding/json"
	"fmt"
	"io"
	"time"

	"github.com/PiotrMackowski/ClosedSSPM/internal/collector"
	"github.com/PiotrMackowski/ClosedSSPM/internal/finding"
)

// Report is the top-level JSON report structure.
type Report struct {
	Title       string            `json:"title"`
	GeneratedAt string            `json:"generated_at"`
	InstanceURL string            `json:"instance_url,omitempty"`
	Platform    string            `json:"platform,omitempty"`
	Summary     finding.Summary   `json:"summary"`
	Findings    []finding.Finding `json:"findings"`
}

// Reporter generates JSON reports.
type Reporter struct{}

// Generate writes a JSON report to the given writer.
func (r *Reporter) Generate(w io.Writer, findings []finding.Finding, snapshot *collector.Snapshot) error {
	report := Report{
		Title:       "ClosedSSPM Security Audit Report",
		GeneratedAt: time.Now().UTC().Format(time.RFC3339),
		Summary:     finding.NewSummary(findings),
		Findings:    findings,
	}

	if snapshot != nil {
		report.InstanceURL = snapshot.InstanceURL
		report.Platform = snapshot.Platform
	}

	encoder := json.NewEncoder(w)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(report); err != nil {
		return fmt.Errorf("encoding JSON report: %w", err)
	}
	return nil
}
