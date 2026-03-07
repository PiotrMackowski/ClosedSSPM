package policy

import (
	"path/filepath"
	"testing"

	"github.com/PiotrMackowski/ClosedSSPM/internal/collector"
)

func TestEvaluateServiceNowPolicies(t *testing.T) {
	policies, err := LoadPolicies(filepath.Join("..", "..", "policies", "servicenow"))
	if err != nil {
		t.Fatalf("failed to load policies: %v", err)
	}

	snapshot := collector.NewSnapshot("servicenow", "https://dev219883.service-now.com")

	// sys_security_acl
	snapshot.AddTableData(&collector.TableData{
		Table: "sys_security_acl",
		Records: []collector.Record{
			// ACL-001 & ACL-005
			{"condition": "", "script": "", "active": "true", "description": "has desc", "admin_overrides": "false", "type": ""},
			// ACL-003
			{"active": "false", "condition": "x", "script": "x"},
			// ACL-004
			{"admin_overrides": "true", "active": "true", "condition": "x", "script": "x", "description": "desc"},
			// ACL-006
			{"script": "gs.hasRole('admin')", "active": "true", "condition": "x", "description": "desc"},
			// ACL-007
			{"description": "", "active": "true", "condition": "x", "script": "x"},
			// ACL-008
			{"type": "public", "active": "true", "condition": "x", "script": "x", "description": "desc"},
			// ACL-009
			{"type": "deny_unless", "active": "true", "condition": "x", "script": "x", "description": "desc"},
			// SAST-015: eval() in ACL script
			{"condition": "x", "script": "var x = eval(userInput)", "active": "true", "description": "desc", "admin_overrides": "false", "type": "record"},
			// Good
			{"condition": "x", "script": "x", "active": "true", "description": "desc", "admin_overrides": "false", "type": "record"},
		},
	})

	// sys_security_acl_role
	snapshot.AddTableData(&collector.TableData{
		Table: "sys_security_acl_role",
		Records: []collector.Record{
			// ACL-002
			{"sys_user_role": "*"},
			// Good
			{"sys_user_role": "admin"},
		},
	})

	// sys_properties
	snapshot.AddTableData(&collector.TableData{
		Table: "sys_properties",
		Records: []collector.Record{
			// CFG-001
			{"name": "glide.security.use_secure_cookies", "value": "false"},
			// CFG-002
			{"name": "glide.ui.session_timeout", "value": "10"},
			// CFG-003
			{"name": "glide.security.password.min_length_new", "value": "8"},
			// CFG-004
			{"name": "glide.debug.something", "value": "true"},
			// CFG-006
			{"name": "glide.ip.access.control", "value": ""},
			// CFG-011
			{"name": "glide.authenticate.sso.redirect.url", "value": "http://evil.com"},
			// CFG-012
			{"name": "glide.security.use_csrf_token", "value": "false"},
			// CFG-013
			{"name": "glide.ui.forgetme", "value": "false"},
			// CFG-014
			{"name": "glide.ui.rotate_sessions", "value": "false"},
			// CFG-015
			{"name": "glide.security.strict.updates", "value": "false"},
			// CFG-016
			{"name": "glide.security.strict.actions", "value": "false"},
			// CFG-017
			{"name": "glide.set_x_frame_options", "value": "false"},
			// CFG-018
			{"name": "glide.script.allow.ajaxevaluate", "value": "true"},
			// CFG-019
			{"name": "glide.script.use.sandbox", "value": "false"},
			// CFG-020
			{"name": "glide.soap.strict_security", "value": "false"},
			// CFG-021
			{"name": "glide.basicauth.required.csv", "value": "false"},
			// CFG-022
			{"name": "glide.basicauth.required.excel", "value": "false"},
			// CFG-023
			{"name": "glide.basicauth.required.pdf", "value": "false"},
			// CFG-024
			{"name": "glide.basicauth.required.soap", "value": "false"},
			// CFG-025
			{"name": "glide.basicauth.required.importprocessor", "value": "false"},
			// CFG-026
			{"name": "glide.ui.escape_text", "value": "false"},
			// CFG-027
			{"name": "glide.ui.escape_all_script", "value": "false"},
			// CFG-028
			{"name": "glide.html.escape_script", "value": "false"},
			// CFG-029
			{"name": "glide.login.autocomplete", "value": "true"},
			// CFG-030
			{"name": "com.glide.communications.trustmanager_trust_all", "value": "true"},
			// CFG-031
			{"name": "glide.outbound.sslv3.disabled", "value": "false"},
			// CFG-032
			{"name": "glide.sm.default_mode", "value": "allow"},
		},
	})

	// sys_plugins
	snapshot.AddTableData(&collector.TableData{
		Table: "sys_plugins",
		Records: []collector.Record{
			// CFG-005
			{"id": "com.glide.security.high", "active": "inactive"},
			// Good
			{"id": "com.glide.security.high", "active": "active"},
		},
	})

	// sys_certificate
	snapshot.AddTableData(&collector.TableData{
		Table: "sys_certificate",
		Records: []collector.Record{
			// CFG-007
			{"active": "true", "type": "trust_store"},
			// Good
			{"active": "true", "type": "x509"},
		},
	})

	// ldap_server_config
	snapshot.AddTableData(&collector.TableData{
		Table: "ldap_server_config",
		Records: []collector.Record{
			// CFG-008
			{"ssl": "false", "active": "true"},
			// Good
			{"ssl": "true", "active": "true"},
		},
	})

	// saml2_update1
	snapshot.AddTableData(&collector.TableData{
		Table: "saml2_update1",
		Records: []collector.Record{
			// CFG-009
			{"want_assertions_signed": "false", "active": "true", "signing_algorithm": "sha256"},
			// CFG-010
			{"signing_algorithm": "sha1_with_rsa", "active": "true", "want_assertions_signed": "true"},
			// Good
			{"want_assertions_signed": "true", "active": "true", "signing_algorithm": "sha256"},
		},
	})

	// sys_ws_definition
	snapshot.AddTableData(&collector.TableData{
		Table: "sys_ws_definition",
		Records: []collector.Record{
			// INT-001
			{"requires_authentication": "false", "active": "true"},
			// INT-002
			{"active": "false", "requires_authentication": "true"},
			// Good
			{"requires_authentication": "true", "active": "true"},
		},
	})

	// sys_rest_message
	snapshot.AddTableData(&collector.TableData{
		Table: "sys_rest_message",
		Records: []collector.Record{
			// INT-003
			{"authentication_type": "basic"},
			// Good
			{"authentication_type": "oauth2"},
		},
	})

	// oauth_entity
	snapshot.AddTableData(&collector.TableData{
		Table: "oauth_entity",
		Records: []collector.Record{
			// INT-004
			{"active": "true"},
			// Good
			{"active": "false"},
		},
	})

	// ecc_agent
	snapshot.AddTableData(&collector.TableData{
		Table: "ecc_agent",
		Records: []collector.Record{
			// INT-005
			{"validated": "false"},
			// Good
			{"validated": "true"},
		},
	})

	// sys_ws_operation
	snapshot.AddTableData(&collector.TableData{
		Table: "sys_ws_operation",
		Records: []collector.Record{
			// INT-006
			{"requires_acl_authorization": "false", "active": "true", "operation_script": "valid"},
			// INT-007
			{"operation_script": "var x = eval('bad')", "active": "true", "requires_acl_authorization": "true"},
			// SAST-018: insecure HTTP in REST operation
			{"requires_acl_authorization": "true", "active": "true", "operation_script": `var r = new GlideHTTPRequest("http://old.api.com")`},
			// Good
			{"requires_acl_authorization": "true", "active": "true", "operation_script": "valid"},
		},
	})

	// sys_user_has_role
	snapshot.AddTableData(&collector.TableData{
		Table: "sys_user_has_role",
		Records: []collector.Record{
			// ROLE-001 only
			{"role": "admin", "state": "active"},
			// ROLE-001 & ROLE-006
			{"role": "security_admin", "state": "active"},
			// ROLE-007
			{"role": "impersonator", "state": "active"},
			// ROLE-001 & ROLE-008
			{"role": "oauth_admin", "state": "active"},
			// ROLE-009
			{"role": "mid_server", "state": "active"},
			// ROLE-001 & ROLE-010
			{"role": "discovery_admin", "state": "active"},
			// Good
			{"role": "user", "state": "active"},
		},
	})

	// sys_user
	snapshot.AddTableData(&collector.TableData{
		Table: "sys_user",
		Records: []collector.Record{
			// ROLE-002
			{"web_service_access_only": "true", "active": "false"},
			// USER-001
			{"active": "true", "last_login_time": "", "locked_out": "false", "source": "", "internal_integration_user": "false", "web_service_access_only": "false"},
			// USER-002
			{"active": "true", "locked_out": "true", "last_login_time": "2024-01-01", "source": "", "internal_integration_user": "false", "web_service_access_only": "false"},
			// USER-003
			{"active": "true", "source": "ldap", "last_login_time": "2024-01-01", "locked_out": "false", "internal_integration_user": "false", "web_service_access_only": "false"},
			// USER-004
			{"active": "true", "internal_integration_user": "true", "web_service_access_only": "true", "last_login_time": "2024-01-01", "locked_out": "false", "source": ""},
			// USER-004 & USER-005
			{"active": "true", "internal_integration_user": "true", "web_service_access_only": "false", "last_login_time": "2024-01-01", "locked_out": "false", "source": ""},
			// Good
			{"active": "true", "last_login_time": "2024-01-01", "locked_out": "false", "source": "", "internal_integration_user": "false", "web_service_access_only": "false"},
		},
	})

	// sys_user_role
	snapshot.AddTableData(&collector.TableData{
		Table: "sys_user_role",
		Records: []collector.Record{
			// ROLE-003 & ROLE-004
			{"elevated_privilege": "true", "assignable_by": "", "includes_roles": ""},
			// ROLE-003 only
			{"elevated_privilege": "true", "assignable_by": "admin", "includes_roles": ""},
			// ROLE-005
			{"includes_roles": "admin,user", "elevated_privilege": "false", "assignable_by": "admin"},
			// Good
			{"elevated_privilege": "false", "assignable_by": "admin", "includes_roles": ""},
		},
	})

	// sys_script
	snapshot.AddTableData(&collector.TableData{
		Table: "sys_script",
		Records: []collector.Record{
			// SCRIPT-001
			{"script": "var x = eval(data)", "active": "true", "description": "desc", "when": "after"},
			// SCRIPT-004 & SCRIPT-005
			{"script": "normal", "active": "true", "description": "", "when": "before"},
			// SCRIPT-005 only
			{"script": "normal", "active": "true", "description": "desc", "when": "before"},
			// Good
			{"script": "normal", "active": "true", "description": "desc", "when": "after"},
			// SAST-007: AWS access key
			{"script": "var key = 'AKIAIOSFODNN7EXAMPLE'", "active": "true", "description": "desc", "when": "after"},
			// SAST-008: private key
			{"script": "var cert = '-----BEGIN RSA PRIVATE KEY-----\nMIIE...'", "active": "true", "description": "desc", "when": "after"},
			// SAST-016: insecure HTTP
			{"script": `var r = new GlideHTTPRequest("http://api.example.com/data")`, "active": "true", "description": "desc", "when": "after"},
			// SAST-019: SQL injection
			{"script": `gr.addEncodedQuery("category=" + userInput)`, "active": "true", "description": "desc", "when": "after"},
			// SAST-021: workflow bypass
			{"script": "current.setWorkflow( false )", "active": "true", "description": "desc", "when": "after"},
		},
	})

	// sys_script_include
	snapshot.AddTableData(&collector.TableData{
		Table: "sys_script_include",
		Records: []collector.Record{
			// SCRIPT-002
			{"script": "safe code", "client_callable": "true", "active": "true", "description": "desc"},
			// SCRIPT-006
			{"script": "safe code", "client_callable": "false", "active": "true", "description": ""},
			// Good
			{"script": "safe code", "client_callable": "false", "active": "true", "description": "desc"},
			// SAST-009: private key
			{"script": "var pk = '-----BEGIN PRIVATE KEY-----\nMIIE...'", "client_callable": "false", "active": "true", "description": "desc"},
			// SAST-010: GlideEvaluator
			{"script": "var ge = new GlideEvaluator(); ge.evaluateString(code)", "client_callable": "false", "active": "true", "description": "desc"},
			// SAST-012: eval()
			{"script": "var result = eval(userInput)", "client_callable": "false", "active": "true", "description": "desc"},
			// SAST-017: insecure HTTP
			{"script": `var r = new GlideHTTPRequest("http://legacy.internal.com")`, "client_callable": "false", "active": "true", "description": "desc"},
			// SAST-020: SQL injection
			{"script": `gr.addEncodedQuery("name=" + param)`, "client_callable": "false", "active": "true", "description": "desc"},
		},
	})

	// sys_ui_script
	snapshot.AddTableData(&collector.TableData{
		Table: "sys_ui_script",
		Records: []collector.Record{
			// SCRIPT-003
			{"script": "safe code", "active": "true", "global": "true"},
			// Good
			{"script": "safe code", "active": "true", "global": "false"},
			// SAST-013: eval()
			{"script": "var x = eval(data)", "active": "true", "global": "false"},
			// SAST-022: innerHTML XSS
			{"script": "el.innerHTML = userInput", "active": "true", "global": "false"},
			// SAST-023: document.write XSS
			{"script": "document.write(htmlContent)", "active": "true", "global": "false"},
		},
	})

	// ecc_agent_script_file (MID Server scripts)
	snapshot.AddTableData(&collector.TableData{
		Table: "ecc_agent_script_file",
		Records: []collector.Record{
			// SAST-011: GlideEvaluator in MID script
			{"script": "var ge = new GlideEvaluator()", "name": "evaluator_mid"},
			// SAST-014: eval() in MID script
			{"script": "var result = eval(code)", "name": "eval_mid"},
			// Good
			{"script": "var x = gs.getProperty('safe')", "name": "safe_mid_script"},
		},
	})

	evaluator := NewEvaluator(policies)
	findings, err := evaluator.Evaluate(snapshot)
	if err != nil {
		t.Fatalf("failed to evaluate policies: %v", err)
	}

	expectedCounts := map[string]int{
		"SNOW-ACL-001":    1,
		"SNOW-ACL-002":    1,
		"SNOW-ACL-003":    1,
		"SNOW-ACL-004":    1,
		"SNOW-ACL-005":    1,
		"SNOW-ACL-006":    1,
		"SNOW-ACL-007":    1,
		"SNOW-ACL-008":    1,
		"SNOW-ACL-009":    1,
		"SNOW-CFG-001":    1,
		"SNOW-CFG-002":    1,
		"SNOW-CFG-003":    1,
		"SNOW-CFG-004":    1,
		"SNOW-CFG-005":    1,
		"SNOW-CFG-006":    1,
		"SNOW-CFG-007":    1,
		"SNOW-CFG-008":    1,
		"SNOW-CFG-009":    1,
		"SNOW-CFG-010":    1,
		"SNOW-CFG-011":    1,
		"SNOW-CFG-012":    1,
		"SNOW-CFG-013":    1,
		"SNOW-CFG-014":    1,
		"SNOW-CFG-015":    1,
		"SNOW-CFG-016":    1,
		"SNOW-CFG-017":    1,
		"SNOW-CFG-018":    1,
		"SNOW-CFG-019":    1,
		"SNOW-CFG-020":    1,
		"SNOW-CFG-021":    1,
		"SNOW-CFG-022":    1,
		"SNOW-CFG-023":    1,
		"SNOW-CFG-024":    1,
		"SNOW-CFG-025":    1,
		"SNOW-CFG-026":    1,
		"SNOW-CFG-027":    1,
		"SNOW-CFG-028":    1,
		"SNOW-CFG-029":    1,
		"SNOW-CFG-030":    1,
		"SNOW-CFG-031":    1,
		"SNOW-CFG-032":    1,
		"SNOW-INT-001":    1,
		"SNOW-INT-002":    1,
		"SNOW-INT-003":    1,
		"SNOW-INT-004":    1,
		"SNOW-INT-005":    1,
		"SNOW-INT-006":    1,
		"SNOW-INT-007":    1,
		"SNOW-ROLE-001":   4, // admin, security_admin, oauth_admin, discovery_admin
		"SNOW-ROLE-002":   2,
		"SNOW-ROLE-003":   2, // 2 with elevated_privilege=true
		"SNOW-ROLE-004":   1,
		"SNOW-ROLE-005":   1,
		"SNOW-ROLE-006":   1,
		"SNOW-ROLE-007":   1,
		"SNOW-ROLE-008":   1,
		"SNOW-ROLE-009":   1,
		"SNOW-ROLE-010":   1,
		"SNOW-USER-001":   1,
		"SNOW-USER-002":   1,
		"SNOW-USER-003":   1,
		"SNOW-USER-004":   2, // 2 with internal_integration_user=true
		"SNOW-USER-005":   1,
		"SNOW-SCRIPT-001": 1,
		"SNOW-SCRIPT-002": 1,
		"SNOW-SCRIPT-003": 1,
		"SNOW-SCRIPT-004": 1,
		"SNOW-SCRIPT-005": 2, // 2 with when=before
		"SNOW-SCRIPT-006": 1,
		// SAST rules
		"SNOW-SAST-007": 1, // AWS access key in business rule
		"SNOW-SAST-008": 1, // private key in business rule
		"SNOW-SAST-009": 1, // private key in script include
		"SNOW-SAST-010": 1, // GlideEvaluator in script include
		"SNOW-SAST-011": 1, // GlideEvaluator in MID script
		"SNOW-SAST-012": 1, // eval() in script include
		"SNOW-SAST-013": 1, // eval() in UI script
		"SNOW-SAST-014": 1, // eval() in MID script
		"SNOW-SAST-015": 1, // eval() in ACL script
		"SNOW-SAST-016": 1, // insecure HTTP in business rule
		"SNOW-SAST-017": 1, // insecure HTTP in script include
		"SNOW-SAST-018": 1, // insecure HTTP in REST operation
		"SNOW-SAST-019": 1, // SQL injection in business rule
		"SNOW-SAST-020": 1, // SQL injection in script include
		"SNOW-SAST-021": 1, // workflow bypass in business rule
		"SNOW-SAST-022": 1, // innerHTML XSS in UI script
		"SNOW-SAST-023": 1, // document.write XSS in UI script
	}

	actualCounts := make(map[string]int)
	for _, f := range findings {
		actualCounts[f.PolicyID]++
	}

	for id, expected := range expectedCounts {
		if actual := actualCounts[id]; actual != expected {
			t.Errorf("Policy %s: expected %d findings, got %d", id, expected, actual)
		}
	}

	for id, actual := range actualCounts {
		if expectedCounts[id] == 0 {
			t.Errorf("Unexpected finding for policy %s: %d findings", id, actual)
		}
	}
}
