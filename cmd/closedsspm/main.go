// ClosedSSPM - Open Source SaaS Security Posture Management
//
// Main CLI entrypoint. Provides commands for auditing, collecting,
// evaluating, and exposing security findings via MCP.
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/PiotrMackowski/ClosedSSPM/internal/collector"
	"github.com/PiotrMackowski/ClosedSSPM/internal/connector"
	"github.com/PiotrMackowski/ClosedSSPM/internal/finding"
	"github.com/PiotrMackowski/ClosedSSPM/internal/mcpserver"
	"github.com/PiotrMackowski/ClosedSSPM/internal/policy"
	csvreport "github.com/PiotrMackowski/ClosedSSPM/internal/report/csv"
	htmlreport "github.com/PiotrMackowski/ClosedSSPM/internal/report/html"
	jsonreport "github.com/PiotrMackowski/ClosedSSPM/internal/report/json"
	sarifreport "github.com/PiotrMackowski/ClosedSSPM/internal/report/sarif"
	"github.com/PiotrMackowski/ClosedSSPM/policies"
	"github.com/mark3labs/mcp-go/server"
	"github.com/spf13/cobra"
)

var (
	version = "dev"
	commit  = "none"
	date    = "unknown"
)

func main() {
	rootCmd := &cobra.Command{
		Use:   "closedsspm",
		Short: "ClosedSSPM - Open Source SaaS Security Posture Management",
		Long: fmt.Sprintf(`ClosedSSPM audits SaaS platforms for security misconfigurations.

Supported platforms: %s

Use --platform to select one or more connectors (comma-separated or "all").
Credentials are read from environment variables specific to each platform.
Run 'closedsspm audit --help' for details.`, strings.Join(connector.List(), ", ")),
		Version: fmt.Sprintf("%s (commit: %s, built: %s)", version, commit, date),
	}

	rootCmd.AddCommand(
		newAuditCmd(),
		newCollectCmd(),
		newEvaluateCmd(),
		newMCPCmd(),
		newChecksCmd(),
		newPlatformCmd(),
	)

	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}

// --- Helper Functions ---

// loadSnapshot loads a snapshot from a JSON file.
func loadSnapshot(path string) (*collector.Snapshot, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading snapshot file: %w", err)
	}
	var snapshot collector.Snapshot
	if err := json.Unmarshal(data, &snapshot); err != nil {
		return nil, fmt.Errorf("parsing snapshot file: %w", err)
	}
	return &snapshot, nil
}

// saveSnapshot saves a snapshot to a JSON file.
func saveSnapshot(snapshot *collector.Snapshot, path string) error {
	data, err := json.MarshalIndent(snapshot, "", "  ")
	if err != nil {
		return fmt.Errorf("marshaling snapshot: %w", err)
	}
	if err := os.WriteFile(path, data, 0600); err != nil {
		return fmt.Errorf("writing snapshot file: %w", err)
	}
	return nil
}

// getPoliciesDir returns an explicit policies directory from the flag, or empty
// string if none was specified (signaling embedded policies should be used).
func getPoliciesDir(cmd *cobra.Command) string {
	dir, _ := cmd.Flags().GetString("policies")
	if dir != "" {
		return dir
	}
	// Check relative to binary.
	exe, err := os.Executable()
	if err == nil {
		candidate := filepath.Join(filepath.Dir(exe), "policies")
		if info, err := os.Stat(candidate); err == nil && info.IsDir() {
			return candidate
		}
	}
	// Check current directory.
	if info, err := os.Stat("policies"); err == nil && info.IsDir() {
		return "policies"
	}
	// No external directory found; return empty to trigger embedded fallback.
	return ""
}

// loadPolicies loads policies from disk if dir is non-empty, otherwise from embedded.
func loadPolicies(dir string) ([]policy.Policy, string, error) {
	if dir != "" {
		p, err := policy.LoadPolicies(dir)
		if err != nil {
			return nil, "", fmt.Errorf("loading policies: %w", err)
		}
		return p, dir, nil
	}
	// Fall back to embedded policies.
	p, err := policy.LoadPoliciesFS(policies.Embedded, ".")
	if err != nil {
		return nil, "", fmt.Errorf("loading embedded policies: %w", err)
	}
	return p, "(embedded)", nil
}

// evaluateFindings loads policies and evaluates them against a snapshot.
func evaluateFindings(snapshot *collector.Snapshot, policiesDir string) ([]finding.Finding, error) {
	pols, source, err := loadPolicies(policiesDir)
	if err != nil {
		return nil, err
	}
	slog.Info("Loaded policies", "count", len(pols), "source", source)

	evaluator := policy.NewEvaluator(pols)
	findings, err := evaluator.Evaluate(snapshot)
	if err != nil {
		return nil, fmt.Errorf("evaluating policies: %w", err)
	}

	// Set timestamps.
	now := time.Now().UTC()
	for i := range findings {
		findings[i].Timestamp = now
	}

	return findings, nil
}

// writeReport writes findings to the specified output format.
func writeReport(findings []finding.Finding, snapshot *collector.Snapshot, output, format string) error {
	f, err := os.Create(output)
	if err != nil {
		return fmt.Errorf("creating output file: %w", err)
	}
	defer f.Close()

	switch format {
	case "html":
		reporter := &htmlreport.Reporter{}
		return reporter.Generate(f, findings, snapshot)
	case "json":
		reporter := &jsonreport.Reporter{}
		return reporter.Generate(f, findings, snapshot)
	case "csv":
		reporter := &csvreport.Reporter{}
		return reporter.Generate(f, findings, snapshot)
	case "sarif":
		reporter := &sarifreport.Reporter{}
		return reporter.Generate(f, findings, snapshot)
	default:
		return fmt.Errorf("unsupported output format: %s (use html, json, csv, or sarif)", format)
	}
}

// parsePlatforms resolves the --platform flag into a list of platform names.
// Accepts a single name, comma-separated names, or "all" to scan every
// registered connector.
func parsePlatforms(raw string) ([]string, error) {
	if strings.EqualFold(raw, "all") {
		platforms := connector.List()
		if len(platforms) == 0 {
			return nil, fmt.Errorf("no platforms registered")
		}
		return platforms, nil
	}

	var platforms []string
	for _, p := range strings.Split(raw, ",") {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		if _, _, err := connector.Get(p); err != nil {
			return nil, err
		}
		platforms = append(platforms, p)
	}
	if len(platforms) == 0 {
		return nil, fmt.Errorf("no platforms specified")
	}
	return platforms, nil
}

// mergeSnapshots creates a combined snapshot from multiple per-platform snapshots.
// The merged snapshot uses "multi" as the platform name and concatenates instance URLs.
func mergeSnapshots(snapshots []*collector.Snapshot) *collector.Snapshot {
	if len(snapshots) == 1 {
		return snapshots[0]
	}

	var urls []string
	var platformNames []string
	for _, s := range snapshots {
		platformNames = append(platformNames, s.Platform)
		if s.InstanceURL != "" {
			urls = append(urls, s.InstanceURL)
		}
	}

	merged := collector.NewSnapshot(
		strings.Join(platformNames, "+"),
		strings.Join(urls, ", "),
	)

	for _, s := range snapshots {
		for _, td := range s.Tables {
			prefixed := &collector.TableData{
				Table:       s.Platform + "/" + td.Table,
				Records:     td.Records,
				Count:       td.Count,
				CollectedAt: td.CollectedAt,
			}
			merged.AddTableData(prefixed)
		}
	}
	return merged
}

// checkFailOn validates the --fail-on flag and exits with code 2 if findings
// at or above the threshold exist. This distinguishes "audit found issues"
// from "tool error" (exit code 1).
func checkFailOn(cmd *cobra.Command, findings []finding.Finding) {
	failOn, _ := cmd.Flags().GetString("fail-on")
	if failOn == "" || failOn == "none" {
		return
	}
	threshold, err := finding.ParseSeverity(failOn)
	if err != nil {
		slog.Error("Invalid --fail-on value", "err", err)
		os.Exit(1)
	}
	if finding.HasFindingsAtOrAbove(findings, threshold) {
		slog.Warn("Findings exceed threshold", "threshold", string(threshold))
		os.Exit(2)
	}
}

// --- Commands ---

func runAudit(cmd *cobra.Command, _ []string) error {
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	platformRaw, _ := cmd.Flags().GetString("platform")
	output, _ := cmd.Flags().GetString("output")
	format, _ := cmd.Flags().GetString("format")
	snapshotOutput, _ := cmd.Flags().GetString("save-snapshot")
	policiesDir := getPoliciesDir(cmd)

	platforms, err := parsePlatforms(platformRaw)
	if err != nil {
		return err
	}

	// Collect and evaluate each platform independently so that
	// policy platform-filtering works correctly.
	var allFindings []finding.Finding
	var snapshots []*collector.Snapshot

	for _, p := range platforms {
		factory, configBuilder, err := connector.Get(p)
		if err != nil {
			return err
		}

		config := configBuilder(cmd)

		slog.Info("Starting data collection", "platform", p)
		coll := factory()
		snapshot, err := coll.Collect(ctx, config)
		if err != nil {
			return fmt.Errorf("collection failed for %s: %w", p, err)
		}
		slog.Info("Collection complete", "platform", p, "tables", len(snapshot.Tables))

		// Evaluate per-platform so that policies with platform filters
		// match correctly (e.g. platform: entra matches snapshot.Platform == "entra").
		findings, err := evaluateFindings(snapshot, policiesDir)
		if err != nil {
			return fmt.Errorf("evaluation failed for %s: %w", p, err)
		}
		for i := range findings {
			findings[i].Platform = p
		}
		allFindings = append(allFindings, findings...)
		snapshots = append(snapshots, snapshot)
	}

	merged := mergeSnapshots(snapshots)

	// Optionally save the merged snapshot.
	if snapshotOutput != "" {
		if err := saveSnapshot(merged, snapshotOutput); err != nil {
			return err
		}
		slog.Info("Snapshot saved", "path", snapshotOutput)
	}

	summary := finding.NewSummary(allFindings)
	slog.Info("Evaluation complete",
		"platforms", len(platforms),
		"findings", summary.Total,
		"score", summary.PostureScore,
	)

	// Report.
	if err := writeReport(allFindings, merged, output, format); err != nil {
		return err
	}
	slog.Info("Report written", "path", output)

	checkFailOn(cmd, allFindings)

	return nil
}

func newAuditCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "audit",
		Short: "Run a full security audit (collect + evaluate + report)",
		Long:  `Connects to a SaaS platform, collects security-relevant data,\nevaluates it against all policies, and generates a report.`,
		RunE:  runAudit,
	}

	cmd.Flags().String("platform", "servicenow",
		"SaaS platform(s) to audit: a single name, comma-separated list, or \"all\" (available: "+strings.Join(connector.List(), ", ")+")")
	cmd.Flags().String("instance", "", "Platform instance URL (or set via env var)")
	cmd.Flags().String("output", "report.html", "Output file path")
	cmd.Flags().String("format", "html", "Report format: html, json, csv, or sarif")
	cmd.Flags().String("save-snapshot", "", "Also save the raw snapshot to this file")
	cmd.Flags().String("policies", "", "Path to policies directory")
	cmd.Flags().Int("concurrency", 5, "Max parallel API requests")
	cmd.Flags().Float64("rate-limit", 10.0, "Max API requests per second")
	cmd.Flags().String("fail-on", "", "Exit with code 2 if findings at or above this severity exist (CRITICAL, HIGH, MEDIUM, LOW, INFO)")

	return cmd
}

func newCollectCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "collect",
		Short: "Collect data from a SaaS platform (no evaluation)",
		Long:  `Connects to a SaaS platform and saves a snapshot for offline analysis.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
			defer cancel()

			platformRaw, _ := cmd.Flags().GetString("platform")
			output, _ := cmd.Flags().GetString("output")

			platforms, err := parsePlatforms(platformRaw)
			if err != nil {
				return err
			}

			var snapshots []*collector.Snapshot
			for _, p := range platforms {
				factory, configBuilder, err := connector.Get(p)
				if err != nil {
					return err
				}

				config := configBuilder(cmd)

				slog.Info("Starting data collection", "platform", p)
				coll := factory()
				snapshot, err := coll.Collect(ctx, config)
				if err != nil {
					return fmt.Errorf("collection failed for %s: %w", p, err)
				}
				slog.Info("Collection complete", "platform", p, "tables", len(snapshot.Tables))

				snapshots = append(snapshots, snapshot)
			}

			merged := mergeSnapshots(snapshots)

			if err := saveSnapshot(merged, output); err != nil {
				return err
			}
			slog.Info("Snapshot saved", "path", output, "tables", len(merged.Tables))

			return nil
		},
	}

	cmd.Flags().String("platform", "servicenow",
		"SaaS platform(s) to collect from: a single name, comma-separated list, or \"all\" (available: "+strings.Join(connector.List(), ", ")+")")
	cmd.Flags().String("instance", "", "Platform instance URL (or set via env var)")
	cmd.Flags().String("output", "snapshot.json", "Output snapshot file path")
	cmd.Flags().Int("concurrency", 5, "Max parallel API requests")
	cmd.Flags().Float64("rate-limit", 10.0, "Max API requests per second")

	return cmd
}

func newEvaluateCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "evaluate",
		Short: "Evaluate policies against a saved snapshot",
		Long:  `Loads a previously saved snapshot and evaluates all policies against it.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			snapshotPath, _ := cmd.Flags().GetString("snapshot")
			output, _ := cmd.Flags().GetString("output")
			format, _ := cmd.Flags().GetString("format")
			policiesDir := getPoliciesDir(cmd)

			snapshot, err := loadSnapshot(snapshotPath)
			if err != nil {
				return err
			}
			slog.Info("Loaded snapshot", "path", snapshotPath, "tables", len(snapshot.Tables))

			findings, err := evaluateFindings(snapshot, policiesDir)
			if err != nil {
				return err
			}

			summary := finding.NewSummary(findings)
			slog.Info("Evaluation complete", "findings", summary.Total, "score", summary.PostureScore)

			if err := writeReport(findings, snapshot, output, format); err != nil {
				return err
			}
			slog.Info("Report written", "path", output)

			checkFailOn(cmd, findings)

			return nil
		},
	}

	cmd.Flags().String("snapshot", "snapshot.json", "Path to snapshot file")
	cmd.Flags().String("output", "report.html", "Output file path")
	cmd.Flags().String("format", "html", "Report format: html, json, csv, or sarif")
	cmd.Flags().String("policies", "", "Path to policies directory")
	cmd.Flags().String("fail-on", "", "Exit with code 2 if findings at or above this severity exist (CRITICAL, HIGH, MEDIUM, LOW, INFO)")

	return cmd
}

func newMCPCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "mcp",
		Short: "Start the MCP server for AI-assisted audit analysis",
		Long: `Starts a Model Context Protocol (MCP) server over stdio.
Loads a snapshot and findings, then exposes them as MCP tools and resources
for AI-assisted analysis.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			snapshotPath, _ := cmd.Flags().GetString("snapshot")
			policiesDir := getPoliciesDir(cmd)

			snapshot, err := loadSnapshot(snapshotPath)
			if err != nil {
				return err
			}
			slog.Info("Loaded snapshot", "path", snapshotPath, "tables", len(snapshot.Tables))

			findings, err := evaluateFindings(snapshot, policiesDir)
			if err != nil {
				return err
			}

			summary := finding.NewSummary(findings)
			slog.Info("Evaluation complete", "findings", summary.Total, "score", summary.PostureScore)

			data := &mcpserver.AuditData{
				Snapshot: snapshot,
				Findings: findings,
				Summary:  summary,
			}

			mcpSrv := mcpserver.NewMCPServer(data)

			slog.Info("Starting MCP server", "transport", "stdio")
			if err := server.ServeStdio(mcpSrv); err != nil {
				return fmt.Errorf("MCP server error: %w", err)
			}

			return nil
		},
	}

	cmd.Flags().String("snapshot", "snapshot.json", "Path to snapshot file")
	cmd.Flags().String("policies", "", "Path to policies directory")

	return cmd
}

func newChecksCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "checks",
		Short: "Manage and list available security checks",
	}

	listCmd := &cobra.Command{
		Use:   "list",
		Short: "List all available security checks",
		RunE: func(cmd *cobra.Command, args []string) error {
			policiesDir := getPoliciesDir(cmd)

			pols, source, err := loadPolicies(policiesDir)
			if err != nil {
				return fmt.Errorf("loading policies: %w", err)
			}
			slog.Info("Loaded policies", "count", len(pols), "source", source)

			fmt.Printf("%-16s %-10s %-12s %s\n", "ID", "SEVERITY", "CATEGORY", "TITLE")
			fmt.Println("------------------------------------------------------------------------------------")
			for _, p := range pols {
				enabled := ""
				if !p.IsEnabled() {
					enabled = " (disabled)"
				}
				fmt.Printf("%-16s %-10s %-12s %s%s\n", p.ID, p.Severity, p.Category, p.Title, enabled)
			}
			fmt.Printf("\nTotal: %d checks\n", len(pols))

			return nil
		},
	}
	listCmd.Flags().String("policies", "", "Path to policies directory")

	showCmd := &cobra.Command{
		Use:   "show [policy-id]",
		Short: "Show details of a specific security check",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			policiesDir := getPoliciesDir(cmd)
			pols, _, err := loadPolicies(policiesDir)
			if err != nil {
				return fmt.Errorf("loading policies: %w", err)
			}

			target := strings.ToUpper(args[0])
			for _, p := range pols {
				if strings.ToUpper(p.ID) == target {
					out := cmd.OutOrStdout()
					fmt.Fprintf(out, "ID:          %s\n", p.ID)
					fmt.Fprintf(out, "Title:       %s\n", p.Title)
					fmt.Fprintf(out, "Platform:    %s\n", p.Platform)
					fmt.Fprintf(out, "Severity:    %s\n", p.Severity)
					fmt.Fprintf(out, "Category:    %s\n", p.Category)
					fmt.Fprintf(out, "Enabled:     %v\n", p.IsEnabled())
					fmt.Fprintf(out, "Description: %s\n", p.Description)
					fmt.Fprintf(out, "Remediation: %s\n", p.Remediation)
					if len(p.References) > 0 {
						fmt.Fprintln(out, "References:")
						for _, ref := range p.References {
							fmt.Fprintf(out, "  - %s\n", ref)
						}
					}
					fmt.Fprintf(out, "Query Table: %s\n", p.Query.Table)
					if len(p.Query.FieldConditions) > 0 {
						fmt.Fprintln(out, "Conditions:")
						for _, c := range p.Query.FieldConditions {
							if c.Value != "" {
								fmt.Fprintf(out, "  - %s %s %q\n", c.Field, c.Operator, c.Value)
							} else {
								fmt.Fprintf(out, "  - %s %s\n", c.Field, c.Operator)
							}
						}
					}
					return nil
				}
			}
			return fmt.Errorf("policy %q not found", args[0])
		},
	}
	showCmd.Flags().String("policies", "", "Path to policies directory")

	cmd.AddCommand(listCmd)
	cmd.AddCommand(showCmd)
	return cmd
}

func newPlatformCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "platform",
		Short: "Platform information and utilities",
	}

	envCmd := &cobra.Command{
		Use:   "env [platform]",
		Short: "Show required environment variables for a platform",
		Long:  "Without arguments, lists env vars for all platforms.\nWith a platform name, shows details for that platform only.",
		RunE: func(cmd *cobra.Command, args []string) error {
			out := cmd.OutOrStdout()
			if len(args) == 0 {
				for _, name := range connector.List() {
					help := connector.EnvHelp(name)
					fmt.Fprintf(out, "=== %s ===\n%s\n\n", name, help)
				}
				return nil
			}
			name := strings.ToLower(args[0])
			help := connector.EnvHelp(name)
			if help == "" {
				return fmt.Errorf("unknown platform %q; available: %s", name, strings.Join(connector.List(), ", "))
			}
			fmt.Fprintln(out, help)
			return nil
		},
	}

	cmd.AddCommand(envCmd)
	return cmd
}
