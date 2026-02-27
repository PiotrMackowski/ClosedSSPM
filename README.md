# ClosedSSPM

Open Source SaaS Security Posture Management (SSPM) tool. Audits SaaS platforms for security misconfigurations, starting with deep ServiceNow coverage.

## Features

- **ServiceNow security auditing** - 10 built-in checks covering ACLs, roles, scripts, and more
- **Policy-as-code** - Audit checks defined in YAML, easily extensible with custom policies
- **HTML reports** - Self-contained, dark-themed HTML reports with posture scoring (A-F)
- **JSON output** - Machine-readable output for pipeline integration
- **MCP server** - AI-assisted audit analysis via Model Context Protocol (works with Claude, OpenCode, etc.)
- **Offline analysis** - Collect data once, analyze many times with snapshot persistence
- **Parallel collection** - Concurrent API requests with configurable rate limiting

## Quick Start

### Build

```bash
make all
```

### Run an Audit

```bash
# Set credentials (never store these in config files)
export SNOW_INSTANCE=https://mycompany.service-now.com
export SNOW_USERNAME=audit_user
export SNOW_PASSWORD=secret

# Full audit: collect + evaluate + report
./bin/closedsspm audit --output report.html

# Or step by step:
./bin/closedsspm collect --output snapshot.json
./bin/closedsspm evaluate --snapshot snapshot.json --output report.html
```

### List Available Checks

```bash
./bin/closedsspm checks list
```

### MCP Server (AI-Assisted Analysis)

```bash
# Start MCP server with a snapshot
./bin/closedsspm mcp --snapshot snapshot.json
```

Add to your MCP client configuration (e.g. Claude Desktop):
```json
{
  "mcpServers": {
    "closedsspm": {
      "command": "/path/to/closedsspm",
      "args": ["mcp", "--snapshot", "/path/to/snapshot.json"]
    }
  }
}
```

## Architecture

```
closedsspm/
├── cmd/
│   ├── closedsspm/        # Main CLI
│   └── mcp/               # Standalone MCP server
├── internal/
│   ├── collector/          # Collector interface & snapshot model
│   ├── connector/
│   │   └── servicenow/    # ServiceNow API client & collector
│   ├── finding/            # Finding model & severity
│   ├── mcpserver/          # MCP server implementation
│   ├── policy/             # Policy engine (YAML loading & evaluation)
│   └── report/
│       ├── html/           # HTML report generator
│       └── json/           # JSON report generator
└── policies/
    └── servicenow/         # ServiceNow policy definitions (YAML)
```

## Security Checks (v0.1)

| ID | Severity | Category | Description |
|----|----------|----------|-------------|
| SNOW-ACL-001 | CRITICAL | ACL | ACL with no condition, no script, and no role requirement |
| SNOW-ACL-002 | HIGH | ACL | ACL with wildcard role assignment |
| SNOW-ACL-003 | MEDIUM | ACL | Inactive ACL that was previously active |
| SNOW-ACL-004 | INFO | ACL | ACL with admin overrides enabled |
| SNOW-ACL-005 | HIGH | ACL | ACL on sensitive table with weak protection |
| SNOW-ACL-006 | MEDIUM | ACL | Script-based ACL using gs.hasRole admin check only |
| SNOW-ACL-007 | LOW | ACL | ACL rule with no description |
| SNOW-ACL-008 | HIGH | ACL | ACL allows unauthenticated access via public type |
| SNOW-ROLE-001 | HIGH | Roles | Users with admin role |
| SNOW-ROLE-002 | CRITICAL | Roles | Integration/service users with admin role |

## MCP Tools

| Tool | Description |
|------|-------------|
| `list_findings` | List findings with optional severity/category filters |
| `get_finding` | Get detailed finding by ID |
| `get_summary` | Audit summary with posture score |
| `query_snapshot` | Query raw ServiceNow data from the snapshot |
| `suggest_remediation` | Remediation steps for a finding |
| `list_tables` | List collected tables with record counts |

## Security Best Practices

- Credentials are **only** read from environment variables, never from config files
- Snapshots may contain sensitive data - treat them as confidential
- The MCP server uses **stdio transport only** (no network exposure)
- The tool is **read-only** - it never writes to your ServiceNow instance
- ServiceNow audit user should have **read-only** roles (minimum required permissions)

### Minimum ServiceNow Permissions

Create a dedicated audit user with these roles:
- `itil` (read access to most tables)
- `security_admin` (read access to ACLs and security config)
- Disable `web_service_access_only` is NOT recommended for this user; use OAuth where possible

## Writing Custom Policies

Policies are YAML files in the `policies/` directory:

```yaml
id: CUSTOM-001
title: "Custom check description"
description: "Detailed explanation of what this checks"
severity: HIGH    # CRITICAL, HIGH, MEDIUM, LOW, INFO
category: Custom
platform: servicenow
query:
  table: sys_security_acl
  field_conditions:
    - field: "active"
      operator: "equals"     # empty, not_empty, equals, not_equals, contains
      value: "true"
remediation: "How to fix the issue"
references:
  - "https://docs.example.com"
```

## License

Apache 2.0 - see [LICENSE](LICENSE)
