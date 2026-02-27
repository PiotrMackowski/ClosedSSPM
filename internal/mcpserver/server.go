// Package mcpserver implements the MCP server for AI-assisted security audit analysis.
package mcpserver

import (
	"context"
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"strings"

	"github.com/PiotrMackowski/ClosedSSPM/internal/collector"
	"github.com/PiotrMackowski/ClosedSSPM/internal/finding"
	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
)

const (
	// maxQueryLimit caps the number of records returned per query to prevent
	// excessive memory use / output size from MCP tool calls.
	maxQueryLimit = 500

	// defaultQueryLimit is the default number of records returned.
	defaultQueryLimit = 50

	// maxInputLength caps generic string input length for MCP parameters.
	maxInputLength = 256
)

// validIdentifier matches ServiceNow table names and field names (alphanumeric + underscores).
var validIdentifier = regexp.MustCompile(`^[a-zA-Z_][a-zA-Z0-9_]{0,80}$`)

// validSeverities lists allowed severity filter values.
var validSeverities = map[string]bool{
	"CRITICAL": true,
	"HIGH":     true,
	"MEDIUM":   true,
	"LOW":      true,
	"INFO":     true,
}

// validCategories lists allowed category filter values.
var validCategories = map[string]bool{
	"ACL":          true,
	"ROLES":        true,
	"SCRIPTS":      true,
	"INTEGRATIONS": true,
	"CONFIG":       true,
	"USERS":        true,
}

// AuditData holds the loaded audit data for MCP tool queries.
type AuditData struct {
	Snapshot *collector.Snapshot
	Findings []finding.Finding
	Summary  finding.Summary
}

// NewMCPServer creates a new MCP server with all security audit tools registered.
func NewMCPServer(data *AuditData) *server.MCPServer {
	s := server.NewMCPServer(
		"ClosedSSPM",
		"0.1.0",
		server.WithToolCapabilities(false),
		server.WithRecovery(),
	)

	registerTools(s, data)
	registerResources(s, data)

	return s
}

func registerTools(s *server.MCPServer, data *AuditData) {
	// list_findings: List all findings with optional filters.
	s.AddTool(
		mcp.NewTool("list_findings",
			mcp.WithDescription("List security audit findings. Optionally filter by severity or category."),
			mcp.WithString("severity",
				mcp.Description("Filter by severity: CRITICAL, HIGH, MEDIUM, LOW, INFO"),
			),
			mcp.WithString("category",
				mcp.Description("Filter by category (e.g. ACL, Roles, Scripts, Integrations, Config, Users)"),
			),
		),
		listFindingsHandler(data),
	)

	// get_finding: Get a specific finding by ID.
	s.AddTool(
		mcp.NewTool("get_finding",
			mcp.WithDescription("Get detailed information about a specific finding by its ID."),
			mcp.WithString("finding_id",
				mcp.Required(),
				mcp.Description("The finding ID (e.g. SNOW-ACL-001-abc123)"),
			),
		),
		getFindingHandler(data),
	)

	// get_summary: Get the audit summary.
	s.AddTool(
		mcp.NewTool("get_summary",
			mcp.WithDescription("Get the overall audit summary including posture score, finding counts by severity and category."),
		),
		getSummaryHandler(data),
	)

	// query_snapshot: Query raw collected data.
	s.AddTool(
		mcp.NewTool("query_snapshot",
			mcp.WithDescription("Query raw collected data from a specific ServiceNow table in the snapshot."),
			mcp.WithString("table",
				mcp.Required(),
				mcp.Description("The ServiceNow table name (e.g. sys_security_acl, sys_user_has_role)"),
			),
			mcp.WithString("field",
				mcp.Description("Filter records where this field matches the given value"),
			),
			mcp.WithString("value",
				mcp.Description("Value to match against the field"),
			),
			mcp.WithNumber("limit",
				mcp.Description("Max number of records to return (default 50, max 500)"),
			),
		),
		querySnapshotHandler(data),
	)

	// suggest_remediation: Get remediation advice for a finding.
	s.AddTool(
		mcp.NewTool("suggest_remediation",
			mcp.WithDescription("Get detailed remediation steps and context for a specific finding."),
			mcp.WithString("finding_id",
				mcp.Required(),
				mcp.Description("The finding ID to get remediation for"),
			),
		),
		suggestRemediationHandler(data),
	)

	// list_tables: List all collected tables with record counts.
	s.AddTool(
		mcp.NewTool("list_tables",
			mcp.WithDescription("List all tables collected in the snapshot with record counts."),
		),
		listTablesHandler(data),
	)
}

func registerResources(s *server.MCPServer, data *AuditData) {
	// Audit summary resource.
	s.AddResource(
		mcp.NewResource(
			"closedsspm://summary",
			"Audit Summary",
			mcp.WithResourceDescription("Overall security posture summary"),
			mcp.WithMIMEType("application/json"),
		),
		func(ctx context.Context, req mcp.ReadResourceRequest) ([]mcp.ResourceContents, error) {
			summaryJSON, _ := json.MarshalIndent(data.Summary, "", "  ")
			return []mcp.ResourceContents{
				mcp.TextResourceContents{
					URI:      "closedsspm://summary",
					MIMEType: "application/json",
					Text:     string(summaryJSON),
				},
			}, nil
		},
	)

	// Snapshot metadata resource.
	if data.Snapshot != nil {
		s.AddResource(
			mcp.NewResource(
				"closedsspm://snapshot/meta",
				"Snapshot Metadata",
				mcp.WithResourceDescription("Information about the collected snapshot"),
				mcp.WithMIMEType("application/json"),
			),
			func(ctx context.Context, req mcp.ReadResourceRequest) ([]mcp.ResourceContents, error) {
				meta := map[string]interface{}{
					"platform":     data.Snapshot.Platform,
					"instance_url": data.Snapshot.InstanceURL,
					"collected_at": data.Snapshot.CollectedAt,
					"collected_by": data.Snapshot.CollectedBy,
					"tables":       len(data.Snapshot.Tables),
					"metadata":     data.Snapshot.Metadata,
				}
				metaJSON, _ := json.MarshalIndent(meta, "", "  ")
				return []mcp.ResourceContents{
					mcp.TextResourceContents{
						URI:      "closedsspm://snapshot/meta",
						MIMEType: "application/json",
						Text:     string(metaJSON),
					},
				}, nil
			},
		)
	}
}

// --- Tool Handlers ---

func listFindingsHandler(data *AuditData) server.ToolHandlerFunc {
	return func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		severity := strings.TrimSpace(req.GetString("severity", ""))
		category := strings.TrimSpace(req.GetString("category", ""))

		// Validate severity filter.
		if severity != "" {
			severity = strings.ToUpper(severity)
			if !validSeverities[severity] {
				return mcp.NewToolResultError(
					fmt.Sprintf("invalid severity %q; allowed values: CRITICAL, HIGH, MEDIUM, LOW, INFO", severity),
				), nil
			}
		}

		// Validate category filter.
		if category != "" {
			if !validCategories[strings.ToUpper(category)] {
				return mcp.NewToolResultError(
					fmt.Sprintf("invalid category %q; allowed values: ACL, Roles, Scripts, Integrations, Config, Users", category),
				), nil
			}
		}

		var filtered []finding.Finding
		for _, f := range data.Findings {
			if severity != "" && string(f.Severity) != strings.ToUpper(severity) {
				continue
			}
			if category != "" && !strings.EqualFold(f.Category, category) {
				continue
			}
			filtered = append(filtered, f)
		}

		// Sort by severity.
		sort.Slice(filtered, func(i, j int) bool {
			return finding.SeverityOrder(filtered[i].Severity) < finding.SeverityOrder(filtered[j].Severity)
		})

		type findingSummary struct {
			ID       string           `json:"id"`
			PolicyID string           `json:"policy_id"`
			Title    string           `json:"title"`
			Severity finding.Severity `json:"severity"`
			Category string           `json:"category"`
			Resource string           `json:"resource"`
		}

		summaries := make([]findingSummary, len(filtered))
		for i, f := range filtered {
			summaries[i] = findingSummary{
				ID:       f.ID,
				PolicyID: f.PolicyID,
				Title:    f.Title,
				Severity: f.Severity,
				Category: f.Category,
				Resource: f.Resource,
			}
		}

		result, _ := json.MarshalIndent(map[string]interface{}{
			"count":    len(summaries),
			"findings": summaries,
		}, "", "  ")

		return mcp.NewToolResultText(string(result)), nil
	}
}

func getFindingHandler(data *AuditData) server.ToolHandlerFunc {
	return func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		findingID, err := req.RequireString("finding_id")
		if err != nil {
			return mcp.NewToolResultError(err.Error()), nil
		}
		if len(findingID) > maxInputLength {
			return mcp.NewToolResultError("finding_id exceeds maximum length"), nil
		}

		for _, f := range data.Findings {
			if f.ID == findingID || f.PolicyID == findingID {
				result, _ := json.MarshalIndent(f, "", "  ")
				return mcp.NewToolResultText(string(result)), nil
			}
		}

		return mcp.NewToolResultError(fmt.Sprintf("finding %q not found", findingID)), nil
	}
}

func getSummaryHandler(data *AuditData) server.ToolHandlerFunc {
	return func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		result, _ := json.MarshalIndent(data.Summary, "", "  ")
		return mcp.NewToolResultText(string(result)), nil
	}
}

func querySnapshotHandler(data *AuditData) server.ToolHandlerFunc {
	return func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		table, err := req.RequireString("table")
		if err != nil {
			return mcp.NewToolResultError(err.Error()), nil
		}

		// Validate table name format to prevent injection.
		if !validIdentifier.MatchString(table) {
			return mcp.NewToolResultError(
				fmt.Sprintf("invalid table name %q; must be alphanumeric with underscores", table),
			), nil
		}

		if data.Snapshot == nil {
			return mcp.NewToolResultError("no snapshot loaded"), nil
		}

		records := data.Snapshot.GetRecords(table)
		if records == nil {
			// List available tables.
			var tables []string
			for t := range data.Snapshot.Tables {
				tables = append(tables, t)
			}
			sort.Strings(tables)
			return mcp.NewToolResultError(
				fmt.Sprintf("table %q not found in snapshot. Available tables: %s", table, strings.Join(tables, ", ")),
			), nil
		}

		field := strings.TrimSpace(req.GetString("field", ""))
		value := req.GetString("value", "")

		// Validate field name format if provided.
		if field != "" && !validIdentifier.MatchString(field) {
			return mcp.NewToolResultError(
				fmt.Sprintf("invalid field name %q; must be alphanumeric with underscores", field),
			), nil
		}
		if len(value) > maxInputLength {
			return mcp.NewToolResultError("value exceeds maximum length"), nil
		}

		limit := int(req.GetFloat("limit", float64(defaultQueryLimit)))
		if limit <= 0 {
			limit = defaultQueryLimit
		}
		if limit > maxQueryLimit {
			limit = maxQueryLimit
		}

		var filtered []collector.Record
		for _, r := range records {
			if field != "" {
				fieldVal := fmt.Sprintf("%v", r[field])
				if !strings.Contains(strings.ToLower(fieldVal), strings.ToLower(value)) {
					continue
				}
			}
			filtered = append(filtered, r)
			if len(filtered) >= limit {
				break
			}
		}

		result, _ := json.MarshalIndent(map[string]interface{}{
			"table":   table,
			"count":   len(filtered),
			"total":   len(records),
			"records": filtered,
		}, "", "  ")

		return mcp.NewToolResultText(string(result)), nil
	}
}

func suggestRemediationHandler(data *AuditData) server.ToolHandlerFunc {
	return func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		findingID, err := req.RequireString("finding_id")
		if err != nil {
			return mcp.NewToolResultError(err.Error()), nil
		}
		if len(findingID) > maxInputLength {
			return mcp.NewToolResultError("finding_id exceeds maximum length"), nil
		}

		for _, f := range data.Findings {
			if f.ID == findingID || f.PolicyID == findingID {
				remediation := map[string]interface{}{
					"finding_id":  f.ID,
					"title":       f.Title,
					"severity":    f.Severity,
					"remediation": f.Remediation,
					"references":  f.References,
					"evidence":    f.Evidence,
				}
				result, _ := json.MarshalIndent(remediation, "", "  ")
				return mcp.NewToolResultText(string(result)), nil
			}
		}

		return mcp.NewToolResultError(fmt.Sprintf("finding %q not found", findingID)), nil
	}
}

func listTablesHandler(data *AuditData) server.ToolHandlerFunc {
	return func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		if data.Snapshot == nil {
			return mcp.NewToolResultError("no snapshot loaded"), nil
		}

		type tableSummary struct {
			Name  string `json:"name"`
			Count int    `json:"count"`
		}

		var tables []tableSummary
		for name, td := range data.Snapshot.Tables {
			tables = append(tables, tableSummary{Name: name, Count: td.Count})
		}
		sort.Slice(tables, func(i, j int) bool {
			return tables[i].Name < tables[j].Name
		})

		result, _ := json.MarshalIndent(map[string]interface{}{
			"total_tables": len(tables),
			"tables":       tables,
		}, "", "  ")

		return mcp.NewToolResultText(string(result)), nil
	}
}
