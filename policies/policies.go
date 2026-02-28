// Package policies embeds the built-in policy YAML files into the binary.
package policies

import "embed"

// Embedded contains all built-in policy YAML files.
// Each platform's policies live in a subdirectory (e.g. servicenow/*.yaml).
// To add a new platform, create policies/<platform>/*.yaml and add an embed
// directive below.
//
//go:embed servicenow/*.yaml
var Embedded embed.FS
