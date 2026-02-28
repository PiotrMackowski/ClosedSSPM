// Package csv generates CSV audit reports.
package csv

import (
	"encoding/csv"
	"fmt"
	"io"
	"sort"

	"github.com/PiotrMackowski/ClosedSSPM/internal/collector"
	"github.com/PiotrMackowski/ClosedSSPM/internal/finding"
)

// Reporter generates CSV reports.
type Reporter struct{}

// columns defines the CSV header row.
var columns = []string{
	"ID", "PolicyID", "Title", "Description", "Severity", "Category",
	"Resource", "Remediation", "EvidenceResourceType", "EvidenceResourceID",
	"EvidenceDisplayName", "EvidenceDescription",
}

// Generate writes a CSV report to the given writer.
func (r *Reporter) Generate(w io.Writer, findings []finding.Finding, _ *collector.Snapshot) error {
	// Sort findings by severity (critical first).
	sort.Slice(findings, func(i, j int) bool {
		return finding.SeverityOrder(findings[i].Severity) < finding.SeverityOrder(findings[j].Severity)
	})

	cw := csv.NewWriter(w)
	defer cw.Flush()

	if err := cw.Write(columns); err != nil {
		return fmt.Errorf("writing CSV header: %w", err)
	}

	for _, f := range findings {
		evResType, evResID, evName, evDesc := evidenceColumns(f.Evidence)
		row := []string{
			f.ID,
			f.PolicyID,
			f.Title,
			f.Description,
			string(f.Severity),
			f.Category,
			f.Resource,
			f.Remediation,
			evResType,
			evResID,
			evName,
			evDesc,
		}
		if err := cw.Write(row); err != nil {
			return fmt.Errorf("writing CSV row: %w", err)
		}
	}

	return nil
}

// evidenceColumns returns the first evidence entry's resource type, resource ID, display name, and description.
func evidenceColumns(evidence []finding.Evidence) (resType, resID, displayName, description string) {
	if len(evidence) == 0 {
		return "", "", "", ""
	}
	ev := evidence[0]
	return ev.ResourceType, ev.ResourceID, ev.DisplayName, ev.Description
}
