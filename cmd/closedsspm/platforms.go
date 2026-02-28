// Package main - platform registrations.
//
// Blank-import each connector package to trigger its init() function,
// which registers the platform with the connector registry.
//
// To add a new platform, add a blank import here:
//
//	_ "github.com/PiotrMackowski/ClosedSSPM/internal/connector/jira"
package main

import (
	// Register all supported platform connectors.
	_ "github.com/PiotrMackowski/ClosedSSPM/internal/connector/servicenow"
)
