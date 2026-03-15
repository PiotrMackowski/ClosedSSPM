package policy

import (
	"path/filepath"
	"testing"

	"github.com/PiotrMackowski/ClosedSSPM/internal/collector"
)

func TestEvaluateGoogleWorkspacePolicies(t *testing.T) {
	policies, err := LoadPolicies(filepath.Join("..", "..", "policies", "googleworkspace"))
	if err != nil {
		t.Fatalf("Failed to load policies: %v", err)
	}

	snapshot := collector.NewSnapshot("googleworkspace", "https://admin.google.com")

	// 1. oauth_tokens table
	tokens := []collector.Record{
		// Bad: triggers GW-OAUTH-001 (Gmail full), GW-OAUTH-003 (Admin SDK),
		//       GW-OAUTH-007 (anonymous), GW-OAUTH-008 (native app)
		{"sys_id": "tok_multi_bad", "scopes": "https://mail.google.com/ https://www.googleapis.com/auth/admin.directory.user", "anonymous": true, "native_app": true},
		// Bad: triggers GW-OAUTH-002 (Drive full), GW-OAUTH-004 (Gmail send),
		//       GW-OAUTH-005 (Contacts), GW-OAUTH-006 (Calendar)
		{"sys_id": "tok_drive_send_bad", "scopes": "https://www.googleapis.com/auth/drive https://www.googleapis.com/auth/gmail.send https://www.googleapis.com/auth/contacts https://www.googleapis.com/auth/calendar", "anonymous": false, "native_app": false},
		// Good: read-only scope, not anonymous, not native
		{"sys_id": "tok_good", "scopes": "https://www.googleapis.com/auth/gmail.readonly", "anonymous": false, "native_app": false},
	}
	snapshot.AddTableData(&collector.TableData{Table: "oauth_tokens", Records: tokens, Count: len(tokens)})

	// 2. token_activity table
	activity := []collector.Record{
		// Bad: triggers GW-OAUTH-009 (authorize event)
		{"sys_id": "act_009_bad", "event_name": "authorize"},
		// Good: revoke event
		{"sys_id": "act_good", "event_name": "revoke"},
	}
	snapshot.AddTableData(&collector.TableData{Table: "token_activity", Records: activity, Count: len(activity)})

	// 3. users table
	users := []collector.Record{
		// Bad: triggers GW-OAUTH-010 (suspended user)
		{"sys_id": "user_010_bad", "suspended": true},
		// Good: active user
		{"sys_id": "user_good", "suspended": false},
	}
	snapshot.AddTableData(&collector.TableData{Table: "users", Records: users, Count: len(users)})

	evaluator := NewEvaluator(policies)
	findings, err := evaluator.Evaluate(snapshot)
	if err != nil {
		t.Fatalf("Evaluate error: %v", err)
	}

	counts := make(map[string]int)
	for _, f := range findings {
		counts[f.PolicyID]++
	}

	expectedCounts := map[string]int{
		// oauth_tokens scope checks
		"GW-OAUTH-001": 1, // Gmail full access: tok_multi_bad
		"GW-OAUTH-002": 1, // Drive full access: tok_drive_send_bad
		"GW-OAUTH-003": 1, // Admin SDK: tok_multi_bad
		"GW-OAUTH-004": 1, // Gmail send: tok_drive_send_bad
		"GW-OAUTH-005": 1, // Contacts: tok_drive_send_bad
		"GW-OAUTH-006": 1, // Calendar: tok_drive_send_bad

		// oauth_tokens attribute checks
		"GW-OAUTH-007": 1, // Anonymous app: tok_multi_bad
		"GW-OAUTH-008": 1, // Native app: tok_multi_bad

		// token_activity checks
		"GW-OAUTH-009": 1, // Authorize event: act_009_bad

		// users checks
		"GW-OAUTH-010": 1, // Suspended user: user_010_bad
	}

	for id, count := range counts {
		if _, ok := expectedCounts[id]; !ok {
			t.Errorf("Unexpected policy finding: %s (count %d)", id, count)
		}
	}

	for id, expected := range expectedCounts {
		actual := counts[id]
		if actual != expected {
			t.Errorf("Policy %s: expected %d findings, got %d", id, expected, actual)
		}
	}
}
