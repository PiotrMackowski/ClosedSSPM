package policy

import (
	"path/filepath"
	"testing"

	"github.com/PiotrMackowski/ClosedSSPM/internal/collector"
)

func TestEvaluateSnowflakePolicies(t *testing.T) {
	policies, err := LoadPolicies(filepath.Join("..", "..", "policies", "snowflake"))
	if err != nil {
		t.Fatalf("Failed to load policies: %v", err)
	}

	snapshot := collector.NewSnapshot("snowflake", "https://test.snowflakecomputing.com")

	// 1. users table
	users := []collector.Record{
		{"sys_id": "u_iam_001", "has_mfa": "false", "disabled": "false", "default_role": "PUBLIC", "email": "a@a.com", "owner": "ADMIN", "has_password": "true", "has_rsa_public_key": "true"},
		{"sys_id": "u_iam_002", "has_mfa": "true", "disabled": "true", "default_role": "ANALYST", "email": "a@a.com", "owner": "ADMIN", "has_password": "true", "has_rsa_public_key": "true"},
		{"sys_id": "u_iam_003", "has_mfa": "true", "disabled": "false", "default_role": "ACCOUNTADMIN", "email": "a@a.com", "owner": "ADMIN", "has_password": "true", "has_rsa_public_key": "true"},
		{"sys_id": "u_iam_004", "has_mfa": "true", "disabled": "false", "default_role": "PUBLIC", "email": "", "owner": "ADMIN", "has_password": "true", "has_rsa_public_key": "true"},
		{"sys_id": "u_iam_005", "has_mfa": "true", "disabled": "false", "default_role": "PUBLIC", "email": "a@a.com", "owner": "", "has_password": "true", "has_rsa_public_key": "true"},
		{"sys_id": "u_iam_006", "has_mfa": "true", "disabled": "false", "default_role": "PUBLIC", "email": "a@a.com", "owner": "ADMIN", "has_password": "true", "has_rsa_public_key": "false"},
		{"sys_id": "u_iam_007", "has_mfa": "true", "disabled": "false", "default_role": "SYSADMIN", "email": "a@a.com", "owner": "ADMIN", "has_password": "true", "has_rsa_public_key": "true"},
		{"sys_id": "u_good", "has_mfa": "true", "disabled": "false", "default_role": "PUBLIC", "email": "good@a.com", "owner": "ADMIN", "has_password": "true", "has_rsa_public_key": "true"},
	}
	snapshot.AddTableData(&collector.TableData{Table: "users", Records: users, Count: len(users)})

	// 2. account_parameters table
	params := []collector.Record{
		{"sys_id": "p_iam_008_bad", "key": "DISABLE_MFA_ENROLLMENT_PROMPT", "value": "true"},
		{"sys_id": "p_iam_008_good", "key": "DISABLE_MFA_ENROLLMENT_PROMPT", "value": "false"},
		{"sys_id": "p_cfg_001_bad", "key": "ALLOW_UNENCRYPTED_VALUE_FOR_COPY", "value": "true"},
		{"sys_id": "p_cfg_001_good", "key": "ALLOW_UNENCRYPTED_VALUE_FOR_COPY", "value": "false"},
		{"sys_id": "p_cfg_002_bad", "key": "REQUIRE_STORAGE_INTEGRATION_FOR_STAGE_CREATION", "value": "false"},
		{"sys_id": "p_cfg_002_good", "key": "REQUIRE_STORAGE_INTEGRATION_FOR_STAGE_CREATION", "value": "true"},
		{"sys_id": "p_cfg_003_bad", "key": "PREVENT_UNLOAD_TO_INLINE_URL", "value": "false"},
		{"sys_id": "p_cfg_003_good", "key": "PREVENT_UNLOAD_TO_INLINE_URL", "value": "true"},
		{"sys_id": "p_cfg_004_bad", "key": "PREVENT_UNLOAD_TO_INTERNAL_STAGES", "value": "false"},
		{"sys_id": "p_cfg_004_good", "key": "PREVENT_UNLOAD_TO_INTERNAL_STAGES", "value": "true"},
		{"sys_id": "p_cfg_005_bad", "key": "MIN_DATA_RETENTION_TIME_IN_DAYS", "value": "0"},
		{"sys_id": "p_cfg_005_good", "key": "MIN_DATA_RETENTION_TIME_IN_DAYS", "value": "1"},
		{"sys_id": "p_cfg_006_bad", "key": "ENABLE_INTERNAL_STAGES_PRIVATELINK", "value": "false"},
		{"sys_id": "p_cfg_006_good", "key": "ENABLE_INTERNAL_STAGES_PRIVATELINK", "value": "true"},
		{"sys_id": "p_cfg_007_bad", "key": "PERIODIC_DATA_REKEYING", "value": "false"},
		{"sys_id": "p_cfg_007_good", "key": "PERIODIC_DATA_REKEYING", "value": "true"},
		{"sys_id": "p_cfg_008_bad", "key": "SAML_IDENTITY_PROVIDER", "value": ""},
		{"sys_id": "p_cfg_008_good", "key": "SAML_IDENTITY_PROVIDER", "value": "ok"},
		{"sys_id": "p_cfg_015_bad", "key": "CLIENT_SESSION_KEEP_ALIVE", "value": "true"},
		{"sys_id": "p_cfg_015_good", "key": "CLIENT_SESSION_KEEP_ALIVE", "value": "false"},
		{"sys_id": "p_cfg_016_bad", "key": "ALLOW_CLIENT_MFA_CACHING", "value": "true"},
		{"sys_id": "p_cfg_016_good", "key": "ALLOW_CLIENT_MFA_CACHING", "value": "false"},
		{"sys_id": "p_cfg_017_bad", "key": "ENABLE_UNREDACTED_QUERY_SYNTAX_ERROR", "value": "true"},
		{"sys_id": "p_cfg_017_good", "key": "ENABLE_UNREDACTED_QUERY_SYNTAX_ERROR", "value": "false"},
		{"sys_id": "p_cfg_018_bad", "key": "NETWORK_POLICY", "value": ""},
		{"sys_id": "p_cfg_018_good", "key": "NETWORK_POLICY", "value": "ok"},
		{"sys_id": "p_cfg_019_bad", "key": "SSO_LOGIN_PAGE", "value": "false"},
		{"sys_id": "p_cfg_019_good", "key": "SSO_LOGIN_PAGE", "value": "true"},
		{"sys_id": "p_cfg_020_bad", "key": "REQUIRE_STORAGE_INTEGRATION_FOR_STAGE_OPERATION", "value": "false"},
		{"sys_id": "p_cfg_020_good", "key": "REQUIRE_STORAGE_INTEGRATION_FOR_STAGE_OPERATION", "value": "true"},
		{"sys_id": "p_cfg_021_bad", "key": "EXTERNAL_OAUTH_ADD_PRIVILEGED_ROLES_TO_BLOCKED_LIST", "value": "false"},
		{"sys_id": "p_cfg_021_good", "key": "EXTERNAL_OAUTH_ADD_PRIVILEGED_ROLES_TO_BLOCKED_LIST", "value": "true"},
		{"sys_id": "p_cfg_022_bad", "key": "CLIENT_ENCRYPTION_KEY_SIZE", "value": "128"},
		{"sys_id": "p_cfg_022_good", "key": "CLIENT_ENCRYPTION_KEY_SIZE", "value": "256"},
	}
	snapshot.AddTableData(&collector.TableData{Table: "account_parameters", Records: params, Count: len(params)})

	// 3. grants_to_users
	gUsers := []collector.Record{
		{"sys_id": "gu_acl_001_bad", "role": "ACCOUNTADMIN"},
		{"sys_id": "gu_acl_002_bad", "role": "SECURITYADMIN"},
		{"sys_id": "gu_acl_007_bad", "role": "SYSADMIN"},
		{"sys_id": "gu_good", "role": "PUBLIC"},
	}
	snapshot.AddTableData(&collector.TableData{Table: "grants_to_users", Records: gUsers, Count: len(gUsers)})

	// 4. grants_to_roles
	gRoles := []collector.Record{
		{"sys_id": "gr_acl_003_bad", "privilege": "MANAGE GRANTS", "grant_option": "false", "granted_on": "DATABASE"},
		{"sys_id": "gr_acl_004_bad", "privilege": "SELECT", "grant_option": "true", "granted_on": "DATABASE"},
		{"sys_id": "gr_acl_006_bad", "privilege": "CREATE USER", "grant_option": "false", "granted_on": "DATABASE"},
		{"sys_id": "gr_acl_008_bad", "privilege": "OWNERSHIP", "grant_option": "false", "granted_on": "ACCOUNT"},
		{"sys_id": "gr_good", "privilege": "SELECT", "grant_option": "false", "granted_on": "DATABASE"},
	}
	snapshot.AddTableData(&collector.TableData{Table: "grants_to_roles", Records: gRoles, Count: len(gRoles)})

	// 5. roles
	roles := []collector.Record{
		{"sys_id": "r_acl_005_bad", "owner": ""},
		{"sys_id": "r_acl_005_good", "owner": "admin"},
	}
	snapshot.AddTableData(&collector.TableData{Table: "roles", Records: roles, Count: len(roles)})

	// 6. network_policies
	nets := []collector.Record{
		{"sys_id": "n_net_001_bad", "name": "", "blocked_ip_list": "1.1.1.1"},
		{"sys_id": "n_net_002_bad", "name": "corp", "blocked_ip_list": ""},
		{"sys_id": "n_net_good", "name": "good", "blocked_ip_list": "1.1.1.1"},
	}
	snapshot.AddTableData(&collector.TableData{Table: "network_policies", Records: nets, Count: len(nets)})

	// 7. password_policies
	pwd := []collector.Record{
		{"sys_id": "pw_cfg_009_bad", "name": ""},
		{"sys_id": "pw_cfg_009_good", "name": "MY_POLICY"},
	}
	snapshot.AddTableData(&collector.TableData{Table: "password_policies", Records: pwd, Count: len(pwd)})

	// 8. session_policies
	sess := []collector.Record{
		{"sys_id": "sp_cfg_010_bad", "name": ""},
		{"sys_id": "sp_cfg_010_good", "name": "MY_POLICY"},
	}
	snapshot.AddTableData(&collector.TableData{Table: "session_policies", Records: sess, Count: len(sess)})

	// 9. security_integrations
	secInt := []collector.Record{
		{"sys_id": "si_cfg_011_bad", "enabled": "false"},
		{"sys_id": "si_cfg_011_good", "enabled": "true"},
	}
	snapshot.AddTableData(&collector.TableData{Table: "security_integrations", Records: secInt, Count: len(secInt)})

	// 10. warehouses
	wh := []collector.Record{
		{"sys_id": "wh_cfg_012_013_bad", "resource_monitor": "", "auto_suspend": "0"},
		{"sys_id": "wh_good", "resource_monitor": "ok", "auto_suspend": "60"},
	}
	snapshot.AddTableData(&collector.TableData{Table: "warehouses", Records: wh, Count: len(wh)})

	// 11. databases
	db := []collector.Record{
		{"sys_id": "db_cfg_014_bad", "retention_time": "0"},
		{"sys_id": "db_good", "retention_time": "1"},
	}
	snapshot.AddTableData(&collector.TableData{Table: "databases", Records: db, Count: len(db)})

	// 12. shares
	shares := []collector.Record{
		{"sys_id": "sh_share_001_bad", "kind": "OUTBOUND"},
		{"sys_id": "sh_good", "kind": "INBOUND"},
	}
	snapshot.AddTableData(&collector.TableData{Table: "shares", Records: shares, Count: len(shares)})

	// 13. login_history
	logins := []collector.Record{
		{"sys_id": "lh_audit_001_bad", "is_success": "NO", "first_authentication_factor": "SAML", "second_authentication_factor": "ok"},
		{"sys_id": "lh_audit_002_bad", "is_success": "YES", "first_authentication_factor": "SAML", "second_authentication_factor": ""},
		{"sys_id": "lh_audit_003_bad", "is_success": "YES", "first_authentication_factor": "PASSWORD", "second_authentication_factor": ""},
		{"sys_id": "lh_good", "is_success": "YES", "first_authentication_factor": "PASSWORD", "second_authentication_factor": "ok"},
	}
	snapshot.AddTableData(&collector.TableData{Table: "login_history", Records: logins, Count: len(logins)})


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
		"SF-IAM-001": 1,
		"SF-IAM-002": 1,
		"SF-IAM-003": 1,
		"SF-IAM-004": 1,
		"SF-IAM-005": 1,
		"SF-IAM-006": 1,
		"SF-IAM-007": 1,
		"SF-IAM-008": 1,

		"SF-ACL-001": 1,
		"SF-ACL-002": 1,
		"SF-ACL-003": 1,
		"SF-ACL-004": 1,
		"SF-ACL-005": 1,
		"SF-ACL-006": 1,
		"SF-ACL-007": 1,
		"SF-ACL-008": 1,

		"SF-NET-001": 1,
		"SF-NET-002": 1,
		"SF-NET-003": 2,

		"SF-CFG-001": 1,
		"SF-CFG-002": 1,
		"SF-CFG-003": 1,
		"SF-CFG-004": 1,
		"SF-CFG-005": 1,
		"SF-CFG-006": 1,
		"SF-CFG-007": 1,
		"SF-CFG-008": 1,
		"SF-CFG-009": 1,
		"SF-CFG-010": 1,
		"SF-CFG-011": 1,
		"SF-CFG-012": 1,
		"SF-CFG-013": 1,
		"SF-CFG-014": 1,
		"SF-CFG-015": 1,
		"SF-CFG-016": 1,
		"SF-CFG-017": 1,
		"SF-CFG-018": 1,
		"SF-CFG-019": 1,
		"SF-CFG-020": 1,
		"SF-CFG-021": 1,
		"SF-CFG-022": 1,

		"SF-SHARE-001": 1,

		"SF-AUDIT-001": 1,
		"SF-AUDIT-002": 2, // lh_audit_002_bad AND lh_audit_003_bad trigger this
		"SF-AUDIT-003": 1, // only lh_audit_003_bad
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
// Note: Checking total count of expected vs actual to ensure no surprise findings
