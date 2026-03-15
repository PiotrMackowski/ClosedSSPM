package policy

import (
	"path/filepath"
	"testing"

	"github.com/PiotrMackowski/ClosedSSPM/internal/collector"
)

func TestEvaluateEntraPolicies(t *testing.T) {
	policies, err := LoadPolicies(filepath.Join("..", "..", "policies", "entra"))
	if err != nil {
		t.Fatalf("Failed to load policies: %v", err)
	}

	snapshot := collector.NewSnapshot("entra", "https://graph.microsoft.com")

	// 1. oauth2_permission_grants table
	grants := []collector.Record{
		// Bad: triggers EN-OAUTH-001 (Mail.ReadWrite), EN-OAUTH-002 (Mail.Send),
		//       EN-OAUTH-006 (RoleManagement.ReadWrite.Directory),
		//       EN-OAUTH-008 (consentType AllPrincipals)
		{"sys_id": "grant_multi_bad", "scope": "Mail.ReadWrite Mail.Send RoleManagement.ReadWrite.Directory", "consentType": "AllPrincipals"},
		// Bad: triggers EN-OAUTH-003 (Directory.ReadWrite.All), EN-OAUTH-004 (Files.ReadWrite.All),
		//       EN-OAUTH-005 (User.ReadWrite.All), EN-OAUTH-007 (Sites.FullControl.All)
		{"sys_id": "grant_dir_files_bad", "scope": "Directory.ReadWrite.All Files.ReadWrite.All User.ReadWrite.All Sites.FullControl.All", "consentType": "Principal"},
		// Good: harmless scope
		{"sys_id": "grant_good", "scope": "User.Read", "consentType": "Principal"},
	}
	snapshot.AddTableData(&collector.TableData{Table: "oauth2_permission_grants", Records: grants, Count: len(grants)})

	// 2. app_credentials table
	creds := []collector.Record{
		// Bad: triggers EN-OAUTH-009 (end_date_time not empty)
		{"sys_id": "cred_009_bad", "end_date_time": "2024-12-31T00:00:00Z", "credential_type": "certificate"},
		// Bad: triggers EN-OAUTH-010 (credential_type password) AND EN-OAUTH-009
		{"sys_id": "cred_010_bad", "end_date_time": "2025-06-01T00:00:00Z", "credential_type": "password"},
		// Good: no expiration, certificate type
		{"sys_id": "cred_good", "end_date_time": "", "credential_type": "certificate"},
	}
	snapshot.AddTableData(&collector.TableData{Table: "app_credentials", Records: creds, Count: len(creds)})

	// 3. app_registrations table
	apps := []collector.Record{
		// Bad: triggers EN-OAUTH-011 (multi-tenant) AND EN-OAUTH-012 (no owner)
		{"sys_id": "app_011_012_bad", "signInAudience": "AzureADMultipleOrgs", "owners": ""},
		// Good: single-tenant with owner
		{"sys_id": "app_good", "signInAudience": "AzureADMyOrg", "owners": "admin@contoso.com"},
	}
	snapshot.AddTableData(&collector.TableData{Table: "app_registrations", Records: apps, Count: len(apps)})

	// 4. service_principals table
	sps := []collector.Record{
		// Bad: triggers EN-OAUTH-013 (no assignment required) AND EN-OAUTH-014 (disabled)
		{"sys_id": "sp_013_014_bad", "appRoleAssignmentRequired": "false", "accountEnabled": "false"},
		// Good: assignment required, enabled
		{"sys_id": "sp_good", "appRoleAssignmentRequired": "true", "accountEnabled": "true"},
	}
	snapshot.AddTableData(&collector.TableData{Table: "service_principals", Records: sps, Count: len(sps)})

	// 5. app_role_assignments table
	assignments := []collector.Record{
		// Bad: triggers EN-OAUTH-015 (application permission)
		{"sys_id": "assign_015_bad", "principalType": "ServicePrincipal"},
		// Good: user-based assignment
		{"sys_id": "assign_good", "principalType": "User"},
	}
	snapshot.AddTableData(&collector.TableData{Table: "app_role_assignments", Records: assignments, Count: len(assignments)})

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
		// oauth2_permission_grants scope checks (grant_multi_bad + grant_dir_files_bad)
		"EN-OAUTH-001": 1, // Mail.ReadWrite in grant_multi_bad
		"EN-OAUTH-002": 1, // Mail.Send in grant_multi_bad
		"EN-OAUTH-003": 1, // Directory.ReadWrite.All in grant_dir_files_bad
		"EN-OAUTH-004": 1, // Files.ReadWrite.All in grant_dir_files_bad
		"EN-OAUTH-005": 1, // User.ReadWrite.All in grant_dir_files_bad
		"EN-OAUTH-006": 1, // RoleManagement.ReadWrite.Directory in grant_multi_bad
		"EN-OAUTH-007": 1, // Sites.FullControl.All in grant_dir_files_bad

		// oauth2_permission_grants consentType check
		"EN-OAUTH-008": 1, // AllPrincipals in grant_multi_bad

		// app_credentials checks
		"EN-OAUTH-009": 2, // end_date_time not empty: cred_009_bad + cred_010_bad
		"EN-OAUTH-010": 1, // credential_type password: cred_010_bad

		// app_registrations checks
		"EN-OAUTH-011": 1, // multi-tenant: app_011_012_bad
		"EN-OAUTH-012": 1, // no owner: app_011_012_bad

		// service_principals checks
		"EN-OAUTH-013": 1, // no assignment required: sp_013_014_bad
		"EN-OAUTH-014": 1, // disabled: sp_013_014_bad

		// app_role_assignments checks
		"EN-OAUTH-015": 1, // ServicePrincipal: assign_015_bad
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
