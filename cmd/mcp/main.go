// MCP server standalone entrypoint.
// This is a convenience binary that only starts the MCP server.
package main

import (
	"encoding/json"
	"fmt"
	"log"
	"os"

	"github.com/PiotrMackowski/ClosedSSPM/internal/collector"
	"github.com/PiotrMackowski/ClosedSSPM/internal/finding"
	"github.com/PiotrMackowski/ClosedSSPM/internal/mcpserver"
	"github.com/PiotrMackowski/ClosedSSPM/internal/policy"
	"github.com/mark3labs/mcp-go/server"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "Usage: closedsspm-mcp <snapshot.json> [policies_dir]")
		os.Exit(1)
	}

	snapshotPath := os.Args[1]
	policiesDir := "policies"
	if len(os.Args) > 2 {
		policiesDir = os.Args[2]
	}

	// Load snapshot.
	data, err := os.ReadFile(snapshotPath)
	if err != nil {
		log.Fatalf("Failed to read snapshot: %v", err)
	}
	var snapshot collector.Snapshot
	if err := json.Unmarshal(data, &snapshot); err != nil {
		log.Fatalf("Failed to parse snapshot: %v", err)
	}

	// Load and evaluate policies.
	policies, err := policy.LoadPolicies(policiesDir)
	if err != nil {
		log.Fatalf("Failed to load policies: %v", err)
	}

	evaluator := policy.NewEvaluator(policies)
	findings, err := evaluator.Evaluate(&snapshot)
	if err != nil {
		log.Fatalf("Failed to evaluate policies: %v", err)
	}

	summary := finding.NewSummary(findings)
	log.Printf("Loaded %d findings (Score: %s) from %d tables", summary.Total, summary.PostureScore, len(snapshot.Tables))

	auditData := &mcpserver.AuditData{
		Snapshot: &snapshot,
		Findings: findings,
		Summary:  summary,
	}

	mcpSrv := mcpserver.NewMCPServer(auditData)

	log.Println("Starting ClosedSSPM MCP server on stdio...")
	if err := server.ServeStdio(mcpSrv); err != nil {
		log.Fatalf("MCP server error: %v", err)
	}
}
