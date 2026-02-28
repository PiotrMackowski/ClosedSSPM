// Package connector provides a registry for SaaS platform connectors.
//
// Each platform (e.g. ServiceNow, Jira, Okta) registers a factory function
// that creates a collector.Collector. The CLI uses this registry to look up
// the correct connector at runtime based on the --platform flag.
//
// To add a new platform:
//  1. Create internal/connector/<platform>/ with a Collector implementation.
//  2. Call connector.Register("<platform>", factory) in an init() function.
//  3. Add policies under policies/<platform>/.
//  4. Import the package (blank import) in cmd/closedsspm/platforms.go.
package connector

import (
	"fmt"
	"sort"
	"sync"

	"github.com/PiotrMackowski/ClosedSSPM/internal/collector"
	"github.com/spf13/cobra"
)

// Factory creates a new Collector for a specific platform.
type Factory func() collector.Collector

// ConfigBuilder builds a ConnectorConfig from CLI flags and environment
// variables. Each platform provides its own implementation to read
// platform-specific credentials (e.g. SNOW_* for ServiceNow, JIRA_* for Jira).
type ConfigBuilder func(cmd *cobra.Command) collector.ConnectorConfig

// platformEntry holds the factory and config builder for a registered platform.
type platformEntry struct {
	factory       Factory
	configBuilder ConfigBuilder
	envHelp       string // help text describing required environment variables
}

var (
	mu        sync.RWMutex
	platforms = make(map[string]platformEntry)
)

// Register adds a platform connector to the global registry.
// name is the platform identifier (e.g. "servicenow").
// factory creates new Collector instances.
// configBuilder builds ConnectorConfig from flags/env vars.
// envHelp is a human-readable description of required env vars for --help output.
//
// Panics if a platform with the same name is already registered.
func Register(name string, factory Factory, configBuilder ConfigBuilder, envHelp string) {
	mu.Lock()
	defer mu.Unlock()

	if _, exists := platforms[name]; exists {
		panic(fmt.Sprintf("connector: platform %q already registered", name))
	}

	platforms[name] = platformEntry{
		factory:       factory,
		configBuilder: configBuilder,
		envHelp:       envHelp,
	}
}

// Get returns the factory and config builder for a registered platform.
// Returns an error if the platform is not registered.
func Get(name string) (Factory, ConfigBuilder, error) {
	mu.RLock()
	defer mu.RUnlock()

	entry, ok := platforms[name]
	if !ok {
		return nil, nil, fmt.Errorf("unknown platform %q; available: %s", name, listNamesLocked())
	}
	return entry.factory, entry.configBuilder, nil
}

// List returns the names of all registered platforms in sorted order.
func List() []string {
	mu.RLock()
	defer mu.RUnlock()
	return listNamesLocked()
}

// EnvHelp returns the environment variable help text for a registered platform.
func EnvHelp(name string) string {
	mu.RLock()
	defer mu.RUnlock()

	if entry, ok := platforms[name]; ok {
		return entry.envHelp
	}
	return ""
}

// listNamesLocked returns sorted platform names. Caller must hold mu.
func listNamesLocked() []string {
	names := make([]string, 0, len(platforms))
	for name := range platforms {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}
