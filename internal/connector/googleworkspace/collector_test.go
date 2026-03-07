package googleworkspace

import (
	"testing"
)

func TestGoogleWorkspaceCollectorName(t *testing.T) {
	c := &GoogleWorkspaceCollector{}
	if got := c.Name(); got != "googleworkspace" {
		t.Errorf("Name() = %q, want %q", got, "googleworkspace")
	}
}

func TestGoogleWorkspaceCollectorTables(t *testing.T) {
	c := &GoogleWorkspaceCollector{}
	tables := c.Tables()

	want := []string{"users", "oauth_tokens", "token_activity"}
	if len(tables) != len(want) {
		t.Fatalf("Tables() returned %d tables, want %d", len(tables), len(want))
	}
	for i, w := range want {
		if tables[i] != w {
			t.Errorf("Tables()[%d] = %q, want %q", i, tables[i], w)
		}
	}
}

func TestGoogleWorkspaceCollectorTables_NoDuplicates(t *testing.T) {
	c := &GoogleWorkspaceCollector{}
	tables := c.Tables()

	seen := make(map[string]bool)
	for _, table := range tables {
		if seen[table] {
			t.Errorf("Tables() contains duplicate: %q", table)
		}
		seen[table] = true
	}
}

func TestGoogleWorkspaceCollectorTables_ReturnsNewSlice(t *testing.T) {
	c := &GoogleWorkspaceCollector{}
	tables1 := c.Tables()
	tables2 := c.Tables()

	// Modifying one slice should not affect the other.
	if len(tables1) > 0 {
		tables1[0] = "modified"
		if tables2[0] == "modified" {
			t.Error("Tables() should return a new slice each call, not a shared reference")
		}
	}
}
