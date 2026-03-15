package sarif

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
// for the SARIF golden-file test. Must be kept stable — any change requires
// `go test -run TestGolden -update` to regenerate.
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
			testutil.WithReferences("https://docs.servicenow.com/acl-best-practices"),
			testutil.WithEvidence(testutil.SampleEvidence(
				testutil.WithResourceType("sys_security_acl"),
				testutil.WithResourceID("aaa"),
				testutil.WithDisplayName("Default ACL"),
			)),
		),
		testutil.SampleFinding(
			testutil.WithID("SNOW-ACL-001-bbb"),
			testutil.WithPolicyID("SNOW-ACL-001"),
			testutil.WithTitle("Missing ACL for Table"),
			testutil.WithDescription("Default ACL grants read access to all authenticated users"),
			testutil.WithSeverity(finding.Critical),
			testutil.WithCategory("ACL"),
			testutil.WithPlatform("servicenow"),
			testutil.WithResource("sys_security_acl:bbb"),
			testutil.WithRemediation("Restrict ACL to appropriate roles"),
			testutil.WithReferences("https://docs.servicenow.com/acl-best-practices"),
		),
		testutil.SampleFinding(
			testutil.WithID("ENTRA-APP-002-ccc"),
			testutil.WithPolicyID("ENTRA-APP-002"),
			testutil.WithTitle("Excessive API Permissions"),
			testutil.WithDescription("Application has Directory.ReadWrite.All permission"),
			testutil.WithSeverity(finding.High),
			testutil.WithCategory("Application"),
			testutil.WithPlatform("entra"),
			testutil.WithResource("app_registration:ccc"),
			testutil.WithRemediation("Apply least-privilege permissions"),
		),
		testutil.SampleFinding(
			testutil.WithID("GW-SHARE-003-ddd"),
			testutil.WithPolicyID("GW-SHARE-003"),
			testutil.WithTitle("External Sharing Enabled"),
			testutil.WithDescription("Domain-wide sharing allows external access"),
			testutil.WithSeverity(finding.Medium),
			testutil.WithCategory("Sharing"),
			testutil.WithPlatform("googleworkspace"),
			testutil.WithResource(""),
			testutil.WithRemediation("Disable external sharing for sensitive OUs"),
		),
		testutil.SampleFinding(
			testutil.WithID("SNOW-ROLE-004-eee"),
			testutil.WithPolicyID("SNOW-ROLE-004"),
			testutil.WithTitle("Admin Role Assigned to Service Account"),
			testutil.WithSeverity(finding.Low),
			testutil.WithCategory("Roles"),
			testutil.WithPlatform("servicenow"),
			testutil.WithResource("sys_user_has_role:eee"),
			testutil.WithRemediation("Remove admin role from service accounts"),
		),
	}
}

func TestGoldenBasic(t *testing.T) {
	golden := filepath.Join("testdata", "basic.sarif.json")

	snapshot := testutil.SampleSnapshot("servicenow")

	var buf bytes.Buffer
	reporter := &Reporter{}
	if err := reporter.Generate(&buf, goldenFindings(), snapshot); err != nil {
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
		t.Errorf("output differs from golden file %s\n--- got (first 500 bytes) ---\n%s\n--- want (first 500 bytes) ---\n%s",
			golden, truncate(got, 500), truncate(want, 500))
	}
}

func truncate(b []byte, n int) string {
	if len(b) <= n {
		return string(b)
	}
	return string(b[:n]) + "...(truncated)"
}
