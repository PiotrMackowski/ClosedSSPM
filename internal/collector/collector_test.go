package collector

import (
	"testing"
	"time"
)

func TestNewSnapshot(t *testing.T) {
	s := NewSnapshot("servicenow", "https://example.service-now.com")

	if s.Platform != "servicenow" {
		t.Errorf("Platform = %q, want %q", s.Platform, "servicenow")
	}
	if s.InstanceURL != "https://example.service-now.com" {
		t.Errorf("InstanceURL = %q, want %q", s.InstanceURL, "https://example.service-now.com")
	}
	if s.CollectedBy != "closedsspm" {
		t.Errorf("CollectedBy = %q, want %q", s.CollectedBy, "closedsspm")
	}
	if s.Tables == nil {
		t.Error("Tables should be initialized")
	}
	if s.Metadata == nil {
		t.Error("Metadata should be initialized")
	}
	if s.CollectedAt.IsZero() {
		t.Error("CollectedAt should not be zero")
	}
}

func TestSnapshotAddTableData(t *testing.T) {
	s := NewSnapshot("servicenow", "https://example.service-now.com")

	td := &TableData{
		Table: "sys_security_acl",
		Records: []Record{
			{"sys_id": "abc123", "name": "test_acl"},
		},
		Count:       1,
		CollectedAt: time.Now().UTC(),
	}

	s.AddTableData(td)

	if len(s.Tables) != 1 {
		t.Fatalf("Tables count = %d, want 1", len(s.Tables))
	}
	if s.Tables["sys_security_acl"] != td {
		t.Error("Table data not stored correctly")
	}
}

func TestSnapshotGetRecords(t *testing.T) {
	s := NewSnapshot("servicenow", "https://example.service-now.com")

	records := []Record{
		{"sys_id": "abc123", "name": "acl1"},
		{"sys_id": "def456", "name": "acl2"},
	}

	s.AddTableData(&TableData{
		Table:       "sys_security_acl",
		Records:     records,
		Count:       2,
		CollectedAt: time.Now().UTC(),
	})

	got := s.GetRecords("sys_security_acl")
	if len(got) != 2 {
		t.Fatalf("GetRecords returned %d records, want 2", len(got))
	}
	if got[0]["sys_id"] != "abc123" {
		t.Errorf("First record sys_id = %v, want %q", got[0]["sys_id"], "abc123")
	}
}

func TestSnapshotGetRecordsNil(t *testing.T) {
	s := NewSnapshot("servicenow", "https://example.service-now.com")

	got := s.GetRecords("nonexistent_table")
	if got != nil {
		t.Errorf("GetRecords for nonexistent table should return nil, got %v", got)
	}
}

func TestSnapshotAddMultipleTables(t *testing.T) {
	s := NewSnapshot("servicenow", "https://example.service-now.com")

	tables := []string{"sys_security_acl", "sys_user", "sys_user_role"}
	for _, table := range tables {
		s.AddTableData(&TableData{
			Table:       table,
			Records:     []Record{{"sys_id": "id1"}},
			Count:       1,
			CollectedAt: time.Now().UTC(),
		})
	}

	if len(s.Tables) != 3 {
		t.Errorf("Tables count = %d, want 3", len(s.Tables))
	}

	for _, table := range tables {
		records := s.GetRecords(table)
		if records == nil {
			t.Errorf("GetRecords(%q) returned nil", table)
		}
	}
}

func TestSnapshotOverwriteTable(t *testing.T) {
	s := NewSnapshot("servicenow", "https://example.service-now.com")

	s.AddTableData(&TableData{
		Table:       "sys_user",
		Records:     []Record{{"sys_id": "old"}},
		Count:       1,
		CollectedAt: time.Now().UTC(),
	})

	// Overwrite with new data.
	s.AddTableData(&TableData{
		Table:       "sys_user",
		Records:     []Record{{"sys_id": "new1"}, {"sys_id": "new2"}},
		Count:       2,
		CollectedAt: time.Now().UTC(),
	})

	records := s.GetRecords("sys_user")
	if len(records) != 2 {
		t.Errorf("After overwrite, record count = %d, want 2", len(records))
	}
	if records[0]["sys_id"] != "new1" {
		t.Errorf("First record should be %q, got %v", "new1", records[0]["sys_id"])
	}
}
