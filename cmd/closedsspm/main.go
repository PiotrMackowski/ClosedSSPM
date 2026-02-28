// ClosedSSPM - Open Source SaaS Security Posture Management
//
// Main CLI entrypoint. Provides commands for auditing, collecting,
// evaluating, and exposing security findings via MCP.
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
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
	"github.com/PiotrMackowski/ClosedSSPM/policies"
	htmlreport "github.com/PiotrMackowski/ClosedSSPM/internal/report/html"
	csvreport "github.com/PiotrMackowski/ClosedSSPM/internal/report/csv"
	jsonreport "github.com/PiotrMackowski/ClosedSSPM/internal/report/json"
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

Use --platform to select which connector to use (default: servicenow).
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
	log.Printf("Loaded %d policies from %s", len(pols), source)

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
	default:
		return fmt.Errorf("unsupported output format: %s (use html, json, or csv)", format)
	}
}

// --- Commands ---

func newAuditCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "audit",
		Short: "Run a full security audit (collect + evaluate + report)",
		Long:  `Connects to a SaaS platform, collects security-relevant data,\nevaluates it against all policies, and generates a report.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
			defer cancel()

			platform, _ := cmd.Flags().GetString("platform")
			factory, configBuilder, err := connector.Get(platform)
			if err != nil {
				return err
			}

			config := configBuilder(cmd)
			output, _ := cmd.Flags().GetString("output")
			format, _ := cmd.Flags().GetString("format")
			snapshotOutput, _ := cmd.Flags().GetString("save-snapshot")
			policiesDir := getPoliciesDir(cmd)

			// Collect.
			log.Printf("Starting %s data collection...", platform)
			coll := factory()
			snapshot, err := coll.Collect(ctx, config)
			if err != nil {
				return fmt.Errorf("collection failed: %w", err)
			}
			log.Printf("Collection complete: %d tables collected", len(snapshot.Tables))

			// Optionally save snapshot.
			if snapshotOutput != "" {
				if err := saveSnapshot(snapshot, snapshotOutput); err != nil {
					return err
				}
				log.Printf("Snapshot saved to %s", snapshotOutput)
			}

			// Evaluate.
			findings, err := evaluateFindings(snapshot, policiesDir)
			if err != nil {
				return err
			}

			summary := finding.NewSummary(findings)
			log.Printf("Evaluation complete: %d findings (Score: %s)", summary.Total, summary.PostureScore)

			// Report.
			if err := writeReport(findings, snapshot, output, format); err != nil {
				return err
			}
			log.Printf("Report written to %s", output)

			return nil
		},
	}

	cmd.Flags().String("platform", "servicenow", "SaaS platform to audit (available: "+strings.Join(connector.List(), ", ")+")")
	cmd.Flags().String("instance", "", "Platform instance URL (or set via env var)")
	cmd.Flags().String("output", "report.html", "Output file path")
	cmd.Flags().String("format", "html", "Report format: html, json, or csv")
	cmd.Flags().String("save-snapshot", "", "Also save the raw snapshot to this file")
	cmd.Flags().String("policies", "", "Path to policies directory")
	cmd.Flags().Int("concurrency", 5, "Max parallel API requests")
	cmd.Flags().Float64("rate-limit", 10.0, "Max API requests per second")

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

			platform, _ := cmd.Flags().GetString("platform")
			factory, configBuilder, err := connector.Get(platform)
			if err != nil {
				return err
			}

			config := configBuilder(cmd)
			output, _ := cmd.Flags().GetString("output")

			log.Printf("Starting %s data collection...", platform)
			coll := factory()
			snapshot, err := coll.Collect(ctx, config)
			if err != nil {
				return fmt.Errorf("collection failed: %w", err)
			}

			if err := saveSnapshot(snapshot, output); err != nil {
				return err
			}
			log.Printf("Snapshot saved to %s (%d tables)", output, len(snapshot.Tables))

			return nil
		},
	}

	cmd.Flags().String("platform", "servicenow", "SaaS platform to collect from (available: "+strings.Join(connector.List(), ", ")+")")
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
			log.Printf("Loaded snapshot from %s (%d tables)", snapshotPath, len(snapshot.Tables))

			findings, err := evaluateFindings(snapshot, policiesDir)
			if err != nil {
				return err
			}

			summary := finding.NewSummary(findings)
			log.Printf("Evaluation complete: %d findings (Score: %s)", summary.Total, summary.PostureScore)

			if err := writeReport(findings, snapshot, output, format); err != nil {
				return err
			}
			log.Printf("Report written to %s", output)

			return nil
		},
	}

	cmd.Flags().String("snapshot", "snapshot.json", "Path to snapshot file")
	cmd.Flags().String("output", "report.html", "Output file path")
	cmd.Flags().String("format", "html", "Report format: html, json, or csv")
	cmd.Flags().String("policies", "", "Path to policies directory")

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
			log.Printf("Loaded snapshot from %s (%d tables)", snapshotPath, len(snapshot.Tables))

			findings, err := evaluateFindings(snapshot, policiesDir)
			if err != nil {
				return err
			}

			summary := finding.NewSummary(findings)
			log.Printf("Loaded %d findings (Score: %s)", summary.Total, summary.PostureScore)

			data := &mcpserver.AuditData{
				Snapshot: snapshot,
				Findings: findings,
				Summary:  summary,
			}

			mcpSrv := mcpserver.NewMCPServer(data)

			log.Println("Starting MCP server on stdio...")
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
			log.Printf("Loaded %d policies from %s", len(pols), source)

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

	cmd.AddCommand(listCmd)
	return cmd
}
