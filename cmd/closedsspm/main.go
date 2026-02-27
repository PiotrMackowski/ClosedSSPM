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
	"syscall"
	"time"

	"github.com/PiotrMackowski/ClosedSSPM/internal/collector"
	"github.com/PiotrMackowski/ClosedSSPM/internal/connector/servicenow"
	"github.com/PiotrMackowski/ClosedSSPM/internal/finding"
	"github.com/PiotrMackowski/ClosedSSPM/internal/mcpserver"
	"github.com/PiotrMackowski/ClosedSSPM/internal/policy"
	htmlreport "github.com/PiotrMackowski/ClosedSSPM/internal/report/html"
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
		Long: `ClosedSSPM audits SaaS platforms for security misconfigurations.
Currently supports ServiceNow with planned support for additional platforms.

Credentials are read from environment variables:
  SNOW_INSTANCE    - ServiceNow instance URL (e.g. https://mycompany.service-now.com)
  SNOW_USERNAME    - Username for basic auth
  SNOW_PASSWORD    - Password for basic auth
  SNOW_CLIENT_ID   - OAuth client ID (alternative to basic auth)
  SNOW_CLIENT_SECRET - OAuth client secret (alternative to basic auth)`,
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

// getConnectorConfig builds a ConnectorConfig from environment variables and flags.
func getConnectorConfig(cmd *cobra.Command) collector.ConnectorConfig {
	instance := envOrFlag(cmd, "instance", "SNOW_INSTANCE")
	username := os.Getenv("SNOW_USERNAME")
	password := os.Getenv("SNOW_PASSWORD")
	clientID := os.Getenv("SNOW_CLIENT_ID")
	clientSecret := os.Getenv("SNOW_CLIENT_SECRET")

	authMethod := "basic"
	if clientID != "" && clientSecret != "" {
		authMethod = "oauth"
	}

	concurrency, _ := cmd.Flags().GetInt("concurrency")
	rateLimit, _ := cmd.Flags().GetFloat64("rate-limit")

	return collector.ConnectorConfig{
		InstanceURL:  instance,
		AuthMethod:   authMethod,
		Username:     username,
		Password:     password,
		ClientID:     clientID,
		ClientSecret: clientSecret,
		Concurrency:  concurrency,
		RateLimit:    rateLimit,
	}
}

func envOrFlag(cmd *cobra.Command, flag, env string) string {
	val, _ := cmd.Flags().GetString(flag)
	if val != "" {
		return val
	}
	return os.Getenv(env)
}

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

// getPoliciesDir returns the policies directory, checking common locations.
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
	return "policies"
}

// evaluateFindings loads policies and evaluates them against a snapshot.
func evaluateFindings(snapshot *collector.Snapshot, policiesDir string) ([]finding.Finding, error) {
	policies, err := policy.LoadPolicies(policiesDir)
	if err != nil {
		return nil, fmt.Errorf("loading policies: %w", err)
	}
	log.Printf("Loaded %d policies from %s", len(policies), policiesDir)

	evaluator := policy.NewEvaluator(policies)
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
	default:
		return fmt.Errorf("unsupported output format: %s", format)
	}
}

// --- Commands ---

func newAuditCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "audit",
		Short: "Run a full security audit (collect + evaluate + report)",
		Long: `Connects to a ServiceNow instance, collects security-relevant data,
evaluates it against all policies, and generates a report.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
			defer cancel()

			config := getConnectorConfig(cmd)
			output, _ := cmd.Flags().GetString("output")
			format, _ := cmd.Flags().GetString("format")
			snapshotOutput, _ := cmd.Flags().GetString("save-snapshot")
			policiesDir := getPoliciesDir(cmd)

			// Collect.
			log.Println("Starting ServiceNow data collection...")
			coll := &servicenow.ServiceNowCollector{}
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

	cmd.Flags().String("instance", "", "ServiceNow instance URL (or set SNOW_INSTANCE)")
	cmd.Flags().String("output", "report.html", "Output file path")
	cmd.Flags().String("format", "html", "Report format: html or json")
	cmd.Flags().String("save-snapshot", "", "Also save the raw snapshot to this file")
	cmd.Flags().String("policies", "", "Path to policies directory")
	cmd.Flags().Int("concurrency", 5, "Max parallel API requests")
	cmd.Flags().Float64("rate-limit", 10.0, "Max API requests per second")

	return cmd
}

func newCollectCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "collect",
		Short: "Collect data from a ServiceNow instance (no evaluation)",
		Long:  `Connects to a ServiceNow instance and saves a snapshot for offline analysis.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
			defer cancel()

			config := getConnectorConfig(cmd)
			output, _ := cmd.Flags().GetString("output")

			log.Println("Starting ServiceNow data collection...")
			coll := &servicenow.ServiceNowCollector{}
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

	cmd.Flags().String("instance", "", "ServiceNow instance URL (or set SNOW_INSTANCE)")
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
	cmd.Flags().String("format", "html", "Report format: html or json")
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

			policies, err := policy.LoadPolicies(policiesDir)
			if err != nil {
				return fmt.Errorf("loading policies: %w", err)
			}

			fmt.Printf("%-16s %-10s %-12s %s\n", "ID", "SEVERITY", "CATEGORY", "TITLE")
			fmt.Println("------------------------------------------------------------------------------------")
			for _, p := range policies {
				enabled := ""
				if !p.IsEnabled() {
					enabled = " (disabled)"
				}
				fmt.Printf("%-16s %-10s %-12s %s%s\n", p.ID, p.Severity, p.Category, p.Title, enabled)
			}
			fmt.Printf("\nTotal: %d checks\n", len(policies))

			return nil
		},
	}
	listCmd.Flags().String("policies", "", "Path to policies directory")

	cmd.AddCommand(listCmd)
	return cmd
}
