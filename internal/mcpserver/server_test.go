package mcpserver

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/PiotrMackowski/ClosedSSPM/internal/collector"
	"github.com/PiotrMackowski/ClosedSSPM/internal/finding"
	"github.com/mark3labs/mcp-go/mcp"
)

func newTestAuditData() *AuditData {
	snapshot := collector.NewSnapshot("servicenow", "https://test.service-now.com")
	snapshot.AddTableData(&collector.TableData{
		Table: "sys_security_acl",
		Records: []collector.Record{
			{"sys_id": "acl1", "name": "test_acl", "condition": "", "active": "true"},
			{"sys_id": "acl2", "name": "good_acl", "condition": "has_condition", "active": "true"},
		},
		Count: 2,
	})
	snapshot.AddTableData(&collector.TableData{
		Table: "sys_user",
		Records: []collector.Record{
			{"sys_id": "u1", "user_name": "admin_user", "active": "true"},
		},
		Count: 1,
	})

	findings := []finding.Finding{
		{
			ID:          "SNOW-ACL-001-acl1",
			PolicyID:    "SNOW-ACL-001",
			Title:       "ACL with no protection",
			Description: "An ACL has no condition or script",
			Severity:    finding.Critical,
			Category:    "ACL",
			Resource:    "sys_security_acl:acl1",
			Evidence: []finding.Evidence{
			{ResourceType: "sys_security_acl", ResourceID: "acl1", DisplayName: "test_acl"},
			},
			Remediation: "Add a condition or script",
			References:  []string{"https://docs.servicenow.com/acl"},
		},
		{
			ID:          "SNOW-ROLE-001-u1",
			PolicyID:    "SNOW-ROLE-001",
			Title:       "User with admin role",
			Description: "A user has admin role",
			Severity:    finding.High,
			Category:    "Roles",
			Resource:    "sys_user:u1",
			Evidence: []finding.Evidence{
			{ResourceType: "sys_user", ResourceID: "u1", DisplayName: "admin_user"},
			},
			Remediation: "Review admin access",
		},
	}

	summary := finding.NewSummary(findings)

	return &AuditData{
		Snapshot: snapshot,
		Findings: findings,
		Summary:  summary,
	}
}

func TestNewMCPServer(t *testing.T) {
	data := newTestAuditData()
	s := NewMCPServer(data)
	if s == nil {
		t.Fatal("NewMCPServer() returned nil")
	}
}

func TestListFindingsHandler_All(t *testing.T) {
	data := newTestAuditData()
	handler := listFindingsHandler(data)

	req := mcp.CallToolRequest{}
	result, err := handler(context.Background(), req)
	if err != nil {
		t.Fatalf("handler error: %v", err)
	}

	// Parse the result text.
	text := result.Content[0].(mcp.TextContent).Text
	var parsed map[string]interface{}
	if err := json.Unmarshal([]byte(text), &parsed); err != nil {
		t.Fatalf("Failed to parse result JSON: %v", err)
	}

	count := int(parsed["count"].(float64))
	if count != 2 {
		t.Errorf("count = %d, want 2", count)
	}
}

func TestListFindingsHandler_FilterBySeverity(t *testing.T) {
	data := newTestAuditData()
	handler := listFindingsHandler(data)

	req := mcp.CallToolRequest{}
	req.Params.Arguments = map[string]interface{}{
		"severity": "CRITICAL",
	}

	result, err := handler(context.Background(), req)
	if err != nil {
		t.Fatalf("handler error: %v", err)
	}

	text := result.Content[0].(mcp.TextContent).Text
	var parsed map[string]interface{}
	if err := json.Unmarshal([]byte(text), &parsed); err != nil {
		t.Fatalf("Failed to parse result JSON: %v", err)
	}

	count := int(parsed["count"].(float64))
	if count != 1 {
		t.Errorf("count = %d, want 1 (only CRITICAL)", count)
	}
}

func TestListFindingsHandler_FilterByCategory(t *testing.T) {
	data := newTestAuditData()
	handler := listFindingsHandler(data)

	req := mcp.CallToolRequest{}
	req.Params.Arguments = map[string]interface{}{
		"category": "Roles",
	}

	result, err := handler(context.Background(), req)
	if err != nil {
		t.Fatalf("handler error: %v", err)
	}

	text := result.Content[0].(mcp.TextContent).Text
	var parsed map[string]interface{}
	if err := json.Unmarshal([]byte(text), &parsed); err != nil {
		t.Fatalf("Failed to parse result JSON: %v", err)
	}

	count := int(parsed["count"].(float64))
	if count != 1 {
		t.Errorf("count = %d, want 1 (only Roles)", count)
	}
}

func TestGetFindingHandler_Found(t *testing.T) {
	data := newTestAuditData()
	handler := getFindingHandler(data)

	req := mcp.CallToolRequest{}
	req.Params.Arguments = map[string]interface{}{
		"finding_id": "SNOW-ACL-001-acl1",
	}

	result, err := handler(context.Background(), req)
	if err != nil {
		t.Fatalf("handler error: %v", err)
	}

	text := result.Content[0].(mcp.TextContent).Text
	var parsed map[string]interface{}
	if err := json.Unmarshal([]byte(text), &parsed); err != nil {
		t.Fatalf("Failed to parse result JSON: %v", err)
	}

	if parsed["id"] != "SNOW-ACL-001-acl1" {
		t.Errorf("id = %v, want %q", parsed["id"], "SNOW-ACL-001-acl1")
	}
}

func TestGetFindingHandler_ByPolicyID(t *testing.T) {
	data := newTestAuditData()
	handler := getFindingHandler(data)

	req := mcp.CallToolRequest{}
	req.Params.Arguments = map[string]interface{}{
		"finding_id": "SNOW-ACL-001",
	}

	result, err := handler(context.Background(), req)
	if err != nil {
		t.Fatalf("handler error: %v", err)
	}

	text := result.Content[0].(mcp.TextContent).Text
	var parsed map[string]interface{}
	if err := json.Unmarshal([]byte(text), &parsed); err != nil {
		t.Fatalf("Failed to parse result JSON: %v", err)
	}

	// Should find by policy ID match.
	if parsed["policy_id"] != "SNOW-ACL-001" {
		t.Errorf("policy_id = %v, want %q", parsed["policy_id"], "SNOW-ACL-001")
	}
}

func TestGetFindingHandler_NotFound(t *testing.T) {
	data := newTestAuditData()
	handler := getFindingHandler(data)

	req := mcp.CallToolRequest{}
	req.Params.Arguments = map[string]interface{}{
		"finding_id": "NONEXISTENT",
	}

	result, err := handler(context.Background(), req)
	if err != nil {
		t.Fatalf("handler error: %v", err)
	}

	if !result.IsError {
		t.Error("Should return error for nonexistent finding")
	}
}

func TestGetSummaryHandler(t *testing.T) {
	data := newTestAuditData()
	handler := getSummaryHandler(data)

	req := mcp.CallToolRequest{}
	result, err := handler(context.Background(), req)
	if err != nil {
		t.Fatalf("handler error: %v", err)
	}

	text := result.Content[0].(mcp.TextContent).Text
	var parsed map[string]interface{}
	if err := json.Unmarshal([]byte(text), &parsed); err != nil {
		t.Fatalf("Failed to parse result JSON: %v", err)
	}

	total := int(parsed["total"].(float64))
	if total != 2 {
		t.Errorf("total = %d, want 2", total)
	}

	if parsed["posture_score"] != "F" {
		t.Errorf("posture_score = %v, want %q (has critical)", parsed["posture_score"], "F")
	}
}

func TestQuerySnapshotHandler_AllRecords(t *testing.T) {
	data := newTestAuditData()
	handler := querySnapshotHandler(data)

	req := mcp.CallToolRequest{}
	req.Params.Arguments = map[string]interface{}{
		"table": "sys_security_acl",
	}

	result, err := handler(context.Background(), req)
	if err != nil {
		t.Fatalf("handler error: %v", err)
	}

	text := result.Content[0].(mcp.TextContent).Text
	var parsed map[string]interface{}
	if err := json.Unmarshal([]byte(text), &parsed); err != nil {
		t.Fatalf("Failed to parse result JSON: %v", err)
	}

	count := int(parsed["count"].(float64))
	if count != 2 {
		t.Errorf("count = %d, want 2", count)
	}
}

func TestQuerySnapshotHandler_FilterByField(t *testing.T) {
	data := newTestAuditData()
	handler := querySnapshotHandler(data)

	req := mcp.CallToolRequest{}
	req.Params.Arguments = map[string]interface{}{
		"table": "sys_security_acl",
		"field": "name",
		"value": "good",
	}

	result, err := handler(context.Background(), req)
	if err != nil {
		t.Fatalf("handler error: %v", err)
	}

	text := result.Content[0].(mcp.TextContent).Text
	var parsed map[string]interface{}
	if err := json.Unmarshal([]byte(text), &parsed); err != nil {
		t.Fatalf("Failed to parse result JSON: %v", err)
	}

	count := int(parsed["count"].(float64))
	if count != 1 {
		t.Errorf("count = %d, want 1 (only good_acl matches)", count)
	}
}

func TestQuerySnapshotHandler_TableNotFound(t *testing.T) {
	data := newTestAuditData()
	handler := querySnapshotHandler(data)

	req := mcp.CallToolRequest{}
	req.Params.Arguments = map[string]interface{}{
		"table": "nonexistent_table",
	}

	result, err := handler(context.Background(), req)
	if err != nil {
		t.Fatalf("handler error: %v", err)
	}

	if !result.IsError {
		t.Error("Should return error for nonexistent table")
	}
}

func TestQuerySnapshotHandler_NoSnapshot(t *testing.T) {
	data := &AuditData{Snapshot: nil}
	handler := querySnapshotHandler(data)

	req := mcp.CallToolRequest{}
	req.Params.Arguments = map[string]interface{}{
		"table": "sys_security_acl",
	}

	result, err := handler(context.Background(), req)
	if err != nil {
		t.Fatalf("handler error: %v", err)
	}

	if !result.IsError {
		t.Error("Should return error when no snapshot loaded")
	}
}

func TestSuggestRemediationHandler_Found(t *testing.T) {
	data := newTestAuditData()
	handler := suggestRemediationHandler(data)

	req := mcp.CallToolRequest{}
	req.Params.Arguments = map[string]interface{}{
		"finding_id": "SNOW-ACL-001-acl1",
	}

	result, err := handler(context.Background(), req)
	if err != nil {
		t.Fatalf("handler error: %v", err)
	}

	text := result.Content[0].(mcp.TextContent).Text
	var parsed map[string]interface{}
	if err := json.Unmarshal([]byte(text), &parsed); err != nil {
		t.Fatalf("Failed to parse result JSON: %v", err)
	}

	if parsed["remediation"] != "Add a condition or script" {
		t.Errorf("remediation = %v, want %q", parsed["remediation"], "Add a condition or script")
	}
}

func TestSuggestRemediationHandler_NotFound(t *testing.T) {
	data := newTestAuditData()
	handler := suggestRemediationHandler(data)

	req := mcp.CallToolRequest{}
	req.Params.Arguments = map[string]interface{}{
		"finding_id": "NONEXISTENT",
	}

	result, err := handler(context.Background(), req)
	if err != nil {
		t.Fatalf("handler error: %v", err)
	}

	if !result.IsError {
		t.Error("Should return error for nonexistent finding")
	}
}

func TestListTablesHandler(t *testing.T) {
	data := newTestAuditData()
	handler := listTablesHandler(data)

	req := mcp.CallToolRequest{}
	result, err := handler(context.Background(), req)
	if err != nil {
		t.Fatalf("handler error: %v", err)
	}

	text := result.Content[0].(mcp.TextContent).Text
	var parsed map[string]interface{}
	if err := json.Unmarshal([]byte(text), &parsed); err != nil {
		t.Fatalf("Failed to parse result JSON: %v", err)
	}

	totalTables := int(parsed["total_tables"].(float64))
	if totalTables != 2 {
		t.Errorf("total_tables = %d, want 2", totalTables)
	}
}

func TestListTablesHandler_NoSnapshot(t *testing.T) {
	data := &AuditData{Snapshot: nil}
	handler := listTablesHandler(data)

	req := mcp.CallToolRequest{}
	result, err := handler(context.Background(), req)
	if err != nil {
		t.Fatalf("handler error: %v", err)
	}

	if !result.IsError {
		t.Error("Should return error when no snapshot loaded")
	}
}

// --- Input validation tests ---

func TestListFindingsHandler_InvalidSeverity(t *testing.T) {
	data := newTestAuditData()
	handler := listFindingsHandler(data)

	req := mcp.CallToolRequest{}
	req.Params.Arguments = map[string]interface{}{
		"severity": "INVALID",
	}

	result, err := handler(context.Background(), req)
	if err != nil {
		t.Fatalf("handler error: %v", err)
	}

	if !result.IsError {
		t.Error("Should return error for invalid severity")
	}
}

func TestListFindingsHandler_InvalidCategory(t *testing.T) {
	data := newTestAuditData()
	handler := listFindingsHandler(data)

	req := mcp.CallToolRequest{}
	req.Params.Arguments = map[string]interface{}{
		"category": "NONEXISTENT",
	}

	result, err := handler(context.Background(), req)
	if err != nil {
		t.Fatalf("handler error: %v", err)
	}

	if !result.IsError {
		t.Error("Should return error for invalid category")
	}
}

func TestQuerySnapshotHandler_InvalidTableName(t *testing.T) {
	data := newTestAuditData()
	handler := querySnapshotHandler(data)

	tests := []struct {
		name  string
		table string
	}{
		{"SQL injection attempt", "sys_user; DROP TABLE--"},
		{"path traversal", "../../../etc/passwd"},
		{"empty string", ""},
		{"special chars", "table@name!"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := mcp.CallToolRequest{}
			req.Params.Arguments = map[string]interface{}{
				"table": tt.table,
			}

			result, err := handler(context.Background(), req)
			if err != nil {
				t.Fatalf("handler error: %v", err)
			}

			if !result.IsError {
				t.Error("Should return error for invalid table name")
			}
		})
	}
}

func TestQuerySnapshotHandler_InvalidFieldName(t *testing.T) {
	data := newTestAuditData()
	handler := querySnapshotHandler(data)

	req := mcp.CallToolRequest{}
	req.Params.Arguments = map[string]interface{}{
		"table": "sys_security_acl",
		"field": "field; DROP TABLE--",
		"value": "test",
	}

	result, err := handler(context.Background(), req)
	if err != nil {
		t.Fatalf("handler error: %v", err)
	}

	if !result.IsError {
		t.Error("Should return error for invalid field name")
	}
}

func TestQuerySnapshotHandler_LimitBounds(t *testing.T) {
	data := newTestAuditData()
	handler := querySnapshotHandler(data)

	tests := []struct {
		name     string
		limit    float64
		wantBoth bool // just check it doesn't error
	}{
		{"negative limit uses default", -1, true},
		{"zero limit uses default", 0, true},
		{"excessive limit is capped", 999999, true},
		{"normal limit", 10, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := mcp.CallToolRequest{}
			req.Params.Arguments = map[string]interface{}{
				"table": "sys_security_acl",
				"limit": tt.limit,
			}

			result, err := handler(context.Background(), req)
			if err != nil {
				t.Fatalf("handler error: %v", err)
			}

			if result.IsError {
				t.Errorf("unexpected error for limit %v", tt.limit)
			}
		})
	}
}

func TestGetFindingHandler_ExcessiveLength(t *testing.T) {
	data := newTestAuditData()
	handler := getFindingHandler(data)

	longID := make([]byte, 300)
	for i := range longID {
		longID[i] = 'a'
	}

	req := mcp.CallToolRequest{}
	req.Params.Arguments = map[string]interface{}{
		"finding_id": string(longID),
	}

	result, err := handler(context.Background(), req)
	if err != nil {
		t.Fatalf("handler error: %v", err)
	}

	if !result.IsError {
		t.Error("Should return error for excessively long finding_id")
	}
}

func TestSuggestRemediationHandler_ExcessiveLength(t *testing.T) {
	data := newTestAuditData()
	handler := suggestRemediationHandler(data)

	longID := make([]byte, 300)
	for i := range longID {
		longID[i] = 'a'
	}

	req := mcp.CallToolRequest{}
	req.Params.Arguments = map[string]interface{}{
		"finding_id": string(longID),
	}

	result, err := handler(context.Background(), req)
	if err != nil {
		t.Fatalf("handler error: %v", err)
	}

	if !result.IsError {
		t.Error("Should return error for excessively long finding_id")
	}
}
