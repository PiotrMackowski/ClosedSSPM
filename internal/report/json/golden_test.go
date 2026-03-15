package json

import (
	"bytes"
	"encoding/json"
	"flag"
	"os"
	"path/filepath"
	"testing"

	"github.com/PiotrMackowski/ClosedSSPM/internal/finding"
	"github.com/PiotrMackowski/ClosedSSPM/internal/testutil"
)

var update = flag.Bool("update", false, "update golden files")

// goldenFindings returns a deterministic set of findings for the JSON
// golden-file test. Must be kept stable.
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
			)),
		),
		testutil.SampleFinding(
			testutil.WithID("ENTRA-APP-002-bbb"),
			testutil.WithPolicyID("ENTRA-APP-002"),
			testutil.WithTitle("Excessive API Permissions"),
			testutil.WithSeverity(finding.High),
			testutil.WithCategory("Application"),
			testutil.WithPlatform("entra"),
			testutil.WithResource("app_registration:bbb"),
			testutil.WithRemediation("Apply least-privilege permissions"),
			testutil.WithEvidence(),
		),
		testutil.SampleFinding(
			testutil.WithID("GW-SHARE-003-ccc"),
			testutil.WithPolicyID("GW-SHARE-003"),
			testutil.WithTitle("External Sharing Enabled"),
			testutil.WithSeverity(finding.Medium),
			testutil.WithCategory("Sharing"),
			testutil.WithPlatform("googleworkspace"),
			testutil.WithResource("org_unit:ccc"),
			testutil.WithRemediation("Disable external sharing for sensitive OUs"),
		),
	}
}

// TestGoldenStructure verifies that the JSON reporter produces structurally
// identical output across runs. Because the JSON reporter embeds time.Now()
// in generated_at (both top-level and summary), we normalise those fields
// before comparison.
func TestGoldenStructure(t *testing.T) {
	golden := filepath.Join("testdata", "basic.json")

	snapshot := testutil.SampleSnapshot("servicenow")

	var buf bytes.Buffer
	reporter := &Reporter{}
	if err := reporter.Generate(&buf, goldenFindings(), snapshot); err != nil {
		t.Fatalf("Generate() error: %v", err)
	}

	got := normaliseTimestamps(t, buf.Bytes())

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
		t.Errorf("normalised output differs from golden file %s\n--- got (first 500 bytes) ---\n%s\n--- want (first 500 bytes) ---\n%s",
			golden, truncate(got, 500), truncate(want, 500))
	}
}

const placeholder = "TIMESTAMP_PLACEHOLDER"

// normaliseTimestamps replaces volatile timestamp fields with a fixed
// placeholder so that golden-file comparisons are deterministic.
func normaliseTimestamps(t *testing.T, data []byte) []byte {
	t.Helper()

	var raw map[string]interface{}
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatalf("unmarshal for normalisation: %v", err)
	}

	// Top-level generated_at.
	if _, ok := raw["generated_at"]; ok {
		raw["generated_at"] = placeholder
	}

	// Summary.generated_at.
	if summary, ok := raw["summary"].(map[string]interface{}); ok {
		if _, ok := summary["generated_at"]; ok {
			summary["generated_at"] = placeholder
		}
	}

	// Finding timestamps.
	if findings, ok := raw["findings"].([]interface{}); ok {
		for _, f := range findings {
			if fm, ok := f.(map[string]interface{}); ok {
				if _, ok := fm["timestamp"]; ok {
					fm["timestamp"] = placeholder
				}
			}
		}
	}

	out, err := json.MarshalIndent(raw, "", "  ")
	if err != nil {
		t.Fatalf("re-marshal normalised JSON: %v", err)
	}
	// json.Encoder adds a trailing newline; MarshalIndent does not.
	out = append(out, '\n')
	return out
}

func truncate(b []byte, n int) string {
	if len(b) <= n {
		return string(b)
	}
	return string(b[:n]) + "...(truncated)"
}
