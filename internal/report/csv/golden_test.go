package csv

import (
	"bytes"
	"flag"
	"os"
	"path/filepath"
	"testing"

	"github.com/PiotrMackowski/ClosedSSPM/internal/finding"
	"github.com/PiotrMackowski/ClosedSSPM/internal/testutil"
)

var update = flag.Bool("update", false, "update golden files")

// goldenFindings returns a deterministic, representative set of findings
// covering multiple severities, platforms, evidence shapes, and CSV-injection
// edge-cases. The set MUST be kept stable — any change requires running
// `go test -run TestGolden -update` to regenerate the golden file.
func goldenFindings() []finding.Finding {
	return []finding.Finding{
		testutil.SampleFinding(
			testutil.WithID("SNOW-ACL-001-aaa"),
			testutil.WithPolicyID("SNOW-ACL-001"),
			testutil.WithTitle("Missing ACL for Table"),
			testutil.WithDescription("Default ACL grants read access to all authenticated users"),
			testutil.WithSeverity(finding.Critical),
			testutil.WithCategory("ACL"),
			testutil.WithPlatform("servicenow"),
			testutil.WithResource("sys_security_acl:aaa"),
			testutil.WithRemediation("Restrict ACL to appropriate roles"),
			testutil.WithEvidence(testutil.SampleEvidence(
				testutil.WithResourceType("sys_security_acl"),
				testutil.WithResourceID("aaa"),
				testutil.WithDisplayName("Default ACL"),
				testutil.WithEvidenceDescription("Read access for all users"),
				testutil.WithFields(map[string]string{"operation": "read", "active": "true"}),
			)),
		),
		testutil.SampleFinding(
			testutil.WithID("ENTRA-APP-002-bbb"),
			testutil.WithPolicyID("ENTRA-APP-002"),
			testutil.WithTitle("=cmd injection attempt"),
			testutil.WithDescription("+formula prefix"),
			testutil.WithSeverity(finding.High),
			testutil.WithCategory("Application"),
			testutil.WithPlatform("entra"),
			testutil.WithResource("app_registration:bbb"),
			testutil.WithRemediation("-remove dangerous permissions"),
			testutil.WithEvidence(testutil.SampleEvidence(
				testutil.WithResourceType("app_registration"),
				testutil.WithResourceID("bbb"),
				testutil.WithDisplayName("Test App"),
				testutil.WithEvidenceDescription("Over-permissioned app"),
			)),
		),
		testutil.SampleFinding(
			testutil.WithID("GW-SHARE-003-ccc"),
			testutil.WithPolicyID("GW-SHARE-003"),
			testutil.WithTitle("External Sharing Enabled"),
			testutil.WithDescription("Domain-wide sharing allows external access"),
			testutil.WithSeverity(finding.Medium),
			testutil.WithCategory("Sharing"),
			testutil.WithPlatform("googleworkspace"),
			testutil.WithResource("org_unit:ccc"),
			testutil.WithRemediation("Disable external sharing for sensitive OUs"),
			testutil.WithEvidence(),
		),
		testutil.SampleFinding(
			testutil.WithID("SNOW-ROLE-004-ddd"),
			testutil.WithPolicyID("SNOW-ROLE-004"),
			testutil.WithTitle("Admin Role Assigned to Service Account"),
			testutil.WithDescription("Service account has admin role"),
			testutil.WithSeverity(finding.Low),
			testutil.WithCategory("Roles"),
			testutil.WithPlatform("servicenow"),
			testutil.WithResource("sys_user_has_role:ddd"),
			testutil.WithRemediation("Remove admin role from service accounts"),
			testutil.WithEvidence(testutil.SampleEvidence(
				testutil.WithResourceType("sys_user_has_role"),
				testutil.WithResourceID("ddd"),
				testutil.WithDisplayName("svc_integration"),
				testutil.WithEvidenceDescription("Admin role assignment"),
			)),
		),
	}
}

func TestGoldenBasic(t *testing.T) {
	golden := filepath.Join("testdata", "basic.csv")

	var buf bytes.Buffer
	reporter := &Reporter{}
	if err := reporter.Generate(&buf, goldenFindings(), testutil.SampleSnapshot("multi")); err != nil {
		t.Fatalf("Generate() error: %v", err)
	}

	got := buf.Bytes()

	if *update {
		if err := os.MkdirAll("testdata", 0o755); err != nil {
			t.Fatalf("mkdir testdata: %v", err)
		}
		if err := os.WriteFile(golden, got, 0o644); err != nil {
			t.Fatalf("update golden file: %v", err)
		}
		t.Log("golden file updated")
		return
	}

	want, err := os.ReadFile(golden)
	if err != nil {
		t.Fatalf("reading golden file (run with -update to create): %v", err)
	}

	if !bytes.Equal(got, want) {
		t.Errorf("output differs from golden file %s\n--- got ---\n%s\n--- want ---\n%s",
			golden, string(got), string(want))
	}
}
