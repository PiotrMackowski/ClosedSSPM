// Package html generates self-contained HTML audit reports.
package html

import (
	"embed"
	"fmt"
	"html/template"
	"io"
	"sort"
	"time"

	"github.com/PiotrMackowski/ClosedSSPM/internal/collector"
	"github.com/PiotrMackowski/ClosedSSPM/internal/finding"
)

//go:embed templates/*.html
var templateFS embed.FS

// ReportData contains all data passed to the HTML template.
type ReportData struct {
	Title        string
	GeneratedAt  string
	InstanceURL  string
	Platform     string
	Summary      finding.Summary
	Findings     []finding.Finding
	ByCategory   map[string][]finding.Finding
	BySeverity   map[finding.Severity][]finding.Finding
	TableStats   []TableStat
	SeverityList []finding.Severity
}

// TableStat shows collection stats for a single table.
type TableStat struct {
	Name  string
	Count int
}

// Reporter generates HTML reports.
type Reporter struct{}

// Generate writes an HTML report to the given writer.
func (r *Reporter) Generate(w io.Writer, findings []finding.Finding, snapshot *collector.Snapshot) error {
	tmpl, err := template.New("report.html").Funcs(template.FuncMap{
		"severityClass": severityClass,
		"scoreClass":    scoreClass,
	}).ParseFS(templateFS, "templates/report.html")
	if err != nil {
		return fmt.Errorf("parsing report template: %w", err)
	}

	// Sort findings by severity (critical first).
	sort.Slice(findings, func(i, j int) bool {
		return finding.SeverityOrder(findings[i].Severity) < finding.SeverityOrder(findings[j].Severity)
	})

	// Group by category and severity.
	byCategory := make(map[string][]finding.Finding)
	bySeverity := make(map[finding.Severity][]finding.Finding)
	for _, f := range findings {
		byCategory[f.Category] = append(byCategory[f.Category], f)
		bySeverity[f.Severity] = append(bySeverity[f.Severity], f)
	}

	// Table stats.
	var tableStats []TableStat
	if snapshot != nil {
		for name, td := range snapshot.Tables {
			tableStats = append(tableStats, TableStat{Name: name, Count: td.Count})
		}
		sort.Slice(tableStats, func(i, j int) bool {
			return tableStats[i].Name < tableStats[j].Name
		})
	}

	data := ReportData{
		Title:       "ClosedSSPM Security Audit Report",
		GeneratedAt: time.Now().UTC().Format("2006-01-02 15:04:05 UTC"),
		Summary:     finding.NewSummary(findings),
		Findings:    findings,
		ByCategory:  byCategory,
		BySeverity:  bySeverity,
		TableStats:  tableStats,
		SeverityList: []finding.Severity{
			finding.Critical, finding.High, finding.Medium, finding.Low, finding.Info,
		},
	}

	if snapshot != nil {
		data.InstanceURL = snapshot.InstanceURL
		data.Platform = snapshot.Platform
	}

	return tmpl.Execute(w, data)
}

func severityClass(s finding.Severity) string {
	switch s {
	case finding.Critical:
		return "critical"
	case finding.High:
		return "high"
	case finding.Medium:
		return "medium"
	case finding.Low:
		return "low"
	case finding.Info:
		return "info"
	default:
		return "unknown"
	}
}

func scoreClass(score string) string {
	switch score {
	case "A":
		return "score-a"
	case "B":
		return "score-b"
	case "C":
		return "score-c"
	case "D":
		return "score-d"
	case "F":
		return "score-f"
	default:
		return ""
	}
}
