// Package policies embeds the built-in policy YAML files into the binary.
package policies

import "embed"

// Embedded contains all built-in policy YAML files.
//
//go:embed servicenow/*.yaml
var Embedded embed.FS
