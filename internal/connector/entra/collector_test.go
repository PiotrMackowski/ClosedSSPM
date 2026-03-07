package entra

import "testing"

func TestEntraCollectorName(t *testing.T) {
	c := &EntraCollector{}
	if c.Name() != "entra" {
		t.Errorf("Name() = %q, want %q", c.Name(), "entra")
	}
}

func TestEntraCollectorTables(t *testing.T) {
	c := &EntraCollector{}
	tables := c.Tables()

	if len(tables) != 5 {
		t.Fatalf("Tables() returned %d tables, want %d", len(tables), 5)
	}

	expected := []string{
		"app_registrations",
		"service_principals",
		"oauth2_permission_grants",
		"app_role_assignments",
		"app_credentials",
	}

	for i, name := range expected {
		if tables[i] != name {
			t.Errorf("tables[%d] = %q, want %q", i, tables[i], name)
		}
	}
}
