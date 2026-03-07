package testutil

import (
	"time"

	"github.com/PiotrMackowski/ClosedSSPM/internal/collector"
	"github.com/PiotrMackowski/ClosedSSPM/internal/finding"
)

func SampleFinding(opts ...FindingOption) finding.Finding {
	f := finding.Finding{
		ID:          "TEST-001-abc",
		PolicyID:    "TEST-001",
		Title:       "Test Finding",
		Description: "A test finding",
		Severity:    finding.High,
		Category:    "Test",
		Resource:    "test_table:abc",
		Evidence:    []finding.Evidence{SampleEvidence()},
		Remediation: "Fix the thing",
	}

	for _, opt := range opts {
		opt(&f)
	}

	return f
}

type FindingOption func(*finding.Finding)

func WithID(id string) FindingOption {
	return func(f *finding.Finding) {
		f.ID = id
	}
}

func WithPolicyID(id string) FindingOption {
	return func(f *finding.Finding) {
		f.PolicyID = id
	}
}

func WithTitle(t string) FindingOption {
	return func(f *finding.Finding) {
		f.Title = t
	}
}

func WithSeverity(s finding.Severity) FindingOption {
	return func(f *finding.Finding) {
		f.Severity = s
	}
}

func WithCategory(c string) FindingOption {
	return func(f *finding.Finding) {
		f.Category = c
	}
}

func WithResource(r string) FindingOption {
	return func(f *finding.Finding) {
		f.Resource = r
	}
}

func WithEvidence(ev ...finding.Evidence) FindingOption {
	return func(f *finding.Finding) {
		f.Evidence = ev
	}
}

func WithRemediation(r string) FindingOption {
	return func(f *finding.Finding) {
		f.Remediation = r
	}
}

func WithReferences(refs ...string) FindingOption {
	return func(f *finding.Finding) {
		f.References = refs
	}
}

func WithDescription(d string) FindingOption {
	return func(f *finding.Finding) {
		f.Description = d
	}
}

func WithPlatform(p string) FindingOption {
	return func(f *finding.Finding) {
		f.Platform = p
	}
}

func SampleEvidence(opts ...EvidenceOption) finding.Evidence {
	ev := finding.Evidence{
		ResourceType: "test_table",
		ResourceID:   "abc",
		DisplayName:  "test_record",
		Fields:       map[string]string{"field1": "val1"},
	}

	for _, opt := range opts {
		opt(&ev)
	}

	return ev
}

type EvidenceOption func(*finding.Evidence)

func WithResourceType(rt string) EvidenceOption {
	return func(ev *finding.Evidence) {
		ev.ResourceType = rt
	}
}

func WithResourceID(rid string) EvidenceOption {
	return func(ev *finding.Evidence) {
		ev.ResourceID = rid
	}
}

func WithDisplayName(dn string) EvidenceOption {
	return func(ev *finding.Evidence) {
		ev.DisplayName = dn
	}
}

func WithFields(f map[string]string) EvidenceOption {
	return func(ev *finding.Evidence) {
		ev.Fields = f
	}
}

func WithEvidenceDescription(d string) EvidenceOption {
	return func(ev *finding.Evidence) {
		ev.Description = d
	}
}

func SampleSnapshot(platform string, tables ...*collector.TableData) *collector.Snapshot {
	snapshot := collector.NewSnapshot(platform, "https://test.example.com")
	for _, table := range tables {
		if table != nil {
			snapshot.AddTableData(table)
		}
	}
	return snapshot
}

func SampleTableData(table string, records ...collector.Record) *collector.TableData {
	return &collector.TableData{
		Table:       table,
		Records:     records,
		Count:       len(records),
		CollectedAt: time.Now().UTC(),
	}
}
