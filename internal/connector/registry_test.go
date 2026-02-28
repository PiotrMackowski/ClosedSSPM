package connector

import (
	"testing"

	"github.com/PiotrMackowski/ClosedSSPM/internal/collector"
	"github.com/spf13/cobra"
)

// reset clears the global registry between tests.
func reset() {
	mu.Lock()
	defer mu.Unlock()
	platforms = make(map[string]platformEntry)
}

func dummyFactory() collector.Collector { return nil }

func dummyConfigBuilder(_ *cobra.Command) collector.ConnectorConfig {
	return collector.ConnectorConfig{}
}

func TestRegisterAndGet(t *testing.T) {
	reset()

	Register("testplatform", dummyFactory, dummyConfigBuilder, "TEST_VAR required")

	factory, configBuilder, err := Get("testplatform")
	if err != nil {
		t.Fatalf("Get(\"testplatform\") returned error: %v", err)
	}
	if factory == nil {
		t.Error("factory should not be nil")
	}
	if configBuilder == nil {
		t.Error("configBuilder should not be nil")
	}
}

func TestGetUnknownPlatform(t *testing.T) {
	reset()

	_, _, err := Get("nonexistent")
	if err == nil {
		t.Fatal("Get(\"nonexistent\") should return an error")
	}
}

func TestRegisterDuplicatePanics(t *testing.T) {
	reset()

	Register("dup", dummyFactory, dummyConfigBuilder, "")

	defer func() {
		r := recover()
		if r == nil {
			t.Fatal("Register duplicate should panic")
		}
	}()

	Register("dup", dummyFactory, dummyConfigBuilder, "")
}

func TestList(t *testing.T) {
	reset()

	Register("zebra", dummyFactory, dummyConfigBuilder, "")
	Register("alpha", dummyFactory, dummyConfigBuilder, "")
	Register("middle", dummyFactory, dummyConfigBuilder, "")

	names := List()
	if len(names) != 3 {
		t.Fatalf("List() returned %d names, want 3", len(names))
	}
	want := []string{"alpha", "middle", "zebra"}
	for i, name := range names {
		if name != want[i] {
			t.Errorf("List()[%d] = %q, want %q", i, name, want[i])
		}
	}
}

func TestListEmpty(t *testing.T) {
	reset()

	names := List()
	if len(names) != 0 {
		t.Errorf("List() on empty registry returned %d names, want 0", len(names))
	}
}

func TestEnvHelp(t *testing.T) {
	reset()

	Register("myplatform", dummyFactory, dummyConfigBuilder, "MY_TOKEN required")

	help := EnvHelp("myplatform")
	if help != "MY_TOKEN required" {
		t.Errorf("EnvHelp(\"myplatform\") = %q, want %q", help, "MY_TOKEN required")
	}
}

func TestEnvHelpUnknown(t *testing.T) {
	reset()

	help := EnvHelp("unknown")
	if help != "" {
		t.Errorf("EnvHelp(\"unknown\") = %q, want empty string", help)
	}
}
