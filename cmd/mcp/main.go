// MCP server standalone entrypoint.
// This is a convenience binary that only starts the MCP server.
package main

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"os"

	"github.com/PiotrMackowski/ClosedSSPM/internal/collector"
	"github.com/PiotrMackowski/ClosedSSPM/internal/finding"
	"github.com/PiotrMackowski/ClosedSSPM/internal/mcpserver"
	"github.com/PiotrMackowski/ClosedSSPM/internal/policy"
	"github.com/PiotrMackowski/ClosedSSPM/policies"
	"github.com/mark3labs/mcp-go/server"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "Usage: closedsspm-mcp <snapshot.json> [policies_dir]")
		os.Exit(1)
	}

	snapshotPath := os.Args[1]
	var policiesDir string
	if len(os.Args) > 2 {
		policiesDir = os.Args[2]
	}

	// Load snapshot.
	data, err := os.ReadFile(snapshotPath)
	if err != nil {
		slog.Error("Failed to read snapshot", "err", err)
		os.Exit(1)
	}
	var snapshot collector.Snapshot
	if err := json.Unmarshal(data, &snapshot); err != nil {
		slog.Error("Failed to parse snapshot", "err", err)
		os.Exit(1)
	}

	// Load and evaluate policies.
	var pols []policy.Policy
	if policiesDir != "" {
		pols, err = policy.LoadPolicies(policiesDir)
		if err != nil {
			slog.Error("Failed to load policies", "dir", policiesDir, "err", err)
			os.Exit(1)
		}
		slog.Info("Loaded policies", "count", len(pols), "source", policiesDir)
	} else {
		pols, err = policy.LoadPoliciesFS(policies.Embedded, ".")
		if err != nil {
			slog.Error("Failed to load embedded policies", "err", err)
			os.Exit(1)
		}
		slog.Info("Loaded embedded policies", "count", len(pols))
	}

	evaluator := policy.NewEvaluator(pols)
	findings, err := evaluator.Evaluate(&snapshot)
	if err != nil {
		slog.Error("Failed to evaluate policies", "err", err)
		os.Exit(1)
	}

	summary := finding.NewSummary(findings)
	slog.Info("Evaluation complete", "findings", summary.Total, "score", summary.PostureScore, "tables", len(snapshot.Tables))

	auditData := &mcpserver.AuditData{
		Snapshot: &snapshot,
		Findings: findings,
		Summary:  summary,
	}

	mcpSrv := mcpserver.NewMCPServer(auditData)

	slog.Info("Starting MCP server", "transport", "stdio")
	if err := server.ServeStdio(mcpSrv); err != nil {
		slog.Error("MCP server error", "err", err)
		os.Exit(1)
	}
}
