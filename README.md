# ClosedSSPM

[![CI](https://github.com/PiotrMackowski/ClosedSSPM/actions/workflows/ci.yml/badge.svg)](https://github.com/PiotrMackowski/ClosedSSPM/actions/workflows/ci.yml)
[![CodeQL](https://github.com/PiotrMackowski/ClosedSSPM/actions/workflows/codeql.yml/badge.svg)](https://github.com/PiotrMackowski/ClosedSSPM/actions/workflows/codeql.yml)
[![Go Report Card](https://goreportcard.com/badge/github.com/PiotrMackowski/ClosedSSPM)](https://goreportcard.com/report/github.com/PiotrMackowski/ClosedSSPM)
[![License](https://img.shields.io/github/license/PiotrMackowski/ClosedSSPM)](LICENSE)
[![Go Version](https://img.shields.io/github/go-mod/go-version/PiotrMackowski/ClosedSSPM)](go.mod)
[![Release](https://img.shields.io/github/v/release/PiotrMackowski/ClosedSSPM?include_prereleases)](https://github.com/PiotrMackowski/ClosedSSPM/releases)

Open Source SaaS Security Posture Management (SSPM) tool. Audits SaaS platforms for security misconfigurations, starting with deep ServiceNow coverage.

## Features

- **40 security checks** covering ACLs, roles, scripts, integrations, instance config, and users
- **Policy-as-code** — audit checks defined in YAML, easily extensible with custom policies
- **Embedded policies** — all checks are baked into the binary; no external files needed at runtime
- **HTML reports** — self-contained, dark-themed HTML reports with posture scoring (A–F)
- **JSON output** — machine-readable output for pipeline integration
- **MCP server** — AI-assisted audit analysis via Model Context Protocol (works with Claude, OpenCode, etc.)
- **Offline analysis** — collect data once, analyze many times with snapshot persistence
- **Parallel collection** — concurrent API requests with configurable rate limiting

## Installation

### Homebrew (macOS / Linux)

```bash
brew tap PiotrMackowski/closedsspm
brew install closedsspm
```

### Binary (GitHub Releases)

Download the latest release for your platform from the [Releases](https://github.com/PiotrMackowski/ClosedSSPM/releases) page.

```bash
# Linux amd64
curl -Lo closedsspm.tar.gz https://github.com/PiotrMackowski/ClosedSSPM/releases/latest/download/closedsspm_Linux_amd64.tar.gz
tar xzf closedsspm.tar.gz
sudo mv closedsspm closedsspm-mcp /usr/local/bin/
```

### Debian / Ubuntu (.deb)

```bash
# Download the .deb from the latest release
sudo dpkg -i closedsspm_*.deb
```

### Red Hat / Fedora (.rpm)

```bash
# Download the .rpm from the latest release
sudo rpm -i closedsspm_*.rpm
```

### Docker

```bash
docker pull ghcr.io/piotrmackowski/closedsspm:latest

# Run an audit
docker run --rm \
  -e SNOW_INSTANCE=https://mycompany.service-now.com \
  -e SNOW_USERNAME=audit_user \
  -e SNOW_PASSWORD=secret \
  -v "$(pwd):/out" \
  ghcr.io/piotrmackowski/closedsspm:latest audit --output /out/report.html
```

### Build from Source

```bash
git clone https://github.com/PiotrMackowski/ClosedSSPM.git
cd ClosedSSPM
make all
```

## Quick Start

### Run an Audit

```bash
# Set credentials (never store these in config files)
export SNOW_INSTANCE=https://mycompany.service-now.com
export SNOW_USERNAME=audit_user
export SNOW_PASSWORD=secret

# Full audit: collect + evaluate + report
closedsspm audit --output report.html

# Or step by step:
closedsspm collect --output snapshot.json
closedsspm evaluate --snapshot snapshot.json --output report.html
```

### List Available Checks

```bash
closedsspm checks list
```

### MCP Server (AI-Assisted Analysis)

```bash
# Start MCP server with a snapshot
closedsspm mcp --snapshot snapshot.json
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

### Custom Policies Directory

By default the binary uses its 40 embedded policies. To override with external policies:

```bash
closedsspm audit --policies /path/to/my/policies --output report.html
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
    └── servicenow/         # ServiceNow policy definitions (YAML, embedded at build)
```

## Security Checks

40 built-in checks across 6 categories:

| Category | Count | Examples |
|----------|-------|---------|
| **ACL** | 8 | Unprotected ACLs, wildcard roles, public access |
| **Roles** | 5 | Admin role assignments, elevated privileges, role includes |
| **Scripts** | 6 | eval() usage, client-callable script includes, global UI scripts |
| **Integrations** | 7 | Unauthenticated endpoints, basic auth, unvalidated MID servers |
| **Instance Config** | 10 | HTTPS enforcement, session timeout, password policy, SAML signing |
| **Users** | 4 | Never-logged-in accounts, locked-out active users |

<details>
<summary>Full check list</summary>

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
| SNOW-ROLE-003 | HIGH | Roles | Roles with elevated privilege flag enabled |
| SNOW-ROLE-004 | MEDIUM | Roles | Roles with no assignable_by restriction |
| SNOW-ROLE-005 | CRITICAL | Roles | Custom role that includes the admin role |
| SNOW-SCRIPT-001 | CRITICAL | Scripts | Business rule script uses eval() or GlideEvaluator |
| SNOW-SCRIPT-002 | HIGH | Scripts | Script include marked as client-callable |
| SNOW-SCRIPT-003 | HIGH | Scripts | Global UI script active and running for all users |
| SNOW-SCRIPT-004 | LOW | Scripts | Active business rule with no description |
| SNOW-SCRIPT-005 | MEDIUM | Scripts | Active before business rule modifying data on sensitive tables |
| SNOW-SCRIPT-006 | LOW | Scripts | Active script include with no description |
| SNOW-INT-001 | CRITICAL | Integrations | Web service endpoint with authentication disabled |
| SNOW-INT-002 | LOW | Integrations | Inactive web service endpoint still defined |
| SNOW-INT-003 | HIGH | Integrations | REST message using basic authentication |
| SNOW-INT-004 | INFO | Integrations | Active OAuth application registered |
| SNOW-INT-005 | HIGH | Integrations | MID Server not in validated status |
| SNOW-INT-006 | HIGH | Integrations | Scripted REST operation without ACL authorization |
| SNOW-INT-007 | MEDIUM | Integrations | Scripted REST operation contains eval() or GlideRecord in script |
| SNOW-CFG-001 | CRITICAL | Instance Config | Instance allows HTTP connections (HTTPS not enforced) |
| SNOW-CFG-002 | HIGH | Instance Config | Session timeout set too high or unlimited |
| SNOW-CFG-003 | HIGH | Instance Config | Password policy does not enforce complexity |
| SNOW-CFG-004 | MEDIUM | Instance Config | Debug mode or logging verbosity enabled in production |
| SNOW-CFG-005 | MEDIUM | Instance Config | High security plugin not activated |
| SNOW-CFG-006 | MEDIUM | Instance Config | IP address access control not configured |
| SNOW-CFG-007 | HIGH | Instance Config | SSL certificate approaching expiration or already expired |
| SNOW-CFG-008 | CRITICAL | Instance Config | LDAP server connection without SSL/TLS encryption |
| SNOW-CFG-009 | CRITICAL | Instance Config | SAML identity provider with unsigned assertions |
| SNOW-CFG-010 | HIGH | Instance Config | SAML identity provider using weak signing algorithm |
| SNOW-USER-001 | MEDIUM | Users | Active user account that has never logged in |
| SNOW-USER-002 | HIGH | Users | Locked out user account still active |
| SNOW-USER-003 | MEDIUM | Users | User account sourced from external directory but active |
| SNOW-USER-004 | INFO | Users | Internal integration user account is active |

</details>

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
- Snapshots may contain sensitive data — treat them as confidential
- The MCP server uses **stdio transport only** (no network exposure)
- The tool is **read-only** — it never writes to your ServiceNow instance
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

Apache 2.0 — see [LICENSE](LICENSE)
