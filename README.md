# ClosedSSPM

[![CI](https://github.com/PiotrMackowski/ClosedSSPM/actions/workflows/ci.yml/badge.svg)](https://github.com/PiotrMackowski/ClosedSSPM/actions/workflows/ci.yml)
[![CodeQL](https://github.com/PiotrMackowski/ClosedSSPM/actions/workflows/codeql.yml/badge.svg)](https://github.com/PiotrMackowski/ClosedSSPM/actions/workflows/codeql.yml)
[![Go Report Card](https://goreportcard.com/badge/github.com/PiotrMackowski/ClosedSSPM)](https://goreportcard.com/report/github.com/PiotrMackowski/ClosedSSPM)
[![License](https://img.shields.io/github/license/PiotrMackowski/ClosedSSPM)](LICENSE)
[![Go Version](https://img.shields.io/github/go-mod/go-version/PiotrMackowski/ClosedSSPM)](go.mod)
[![Release](https://img.shields.io/github/v/release/PiotrMackowski/ClosedSSPM?include_prereleases)](https://github.com/PiotrMackowski/ClosedSSPM/releases)
[![OpenSSF Baseline](https://www.bestpractices.dev/projects/12061/baseline)](https://www.bestpractices.dev/projects/12061)
[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/PiotrMackowski/ClosedSSPM/badge)](https://scorecard.dev/viewer/?uri=github.com/PiotrMackowski/ClosedSSPM)

Open Source SaaS Security Posture Management (SSPM) tool. Audits SaaS platforms for security misconfigurations, with deep coverage for ServiceNow and Snowflake.

![ClosedSSPM HTML Report](docs/screenshots/report.jpg)

## Features

- **Multi-platform architecture** — pluggable connector registry; add new SaaS platforms without touching core code
- **141 security checks** across two platforms covering identity, access control, configuration, network, scripts, integrations, SAST scanning, and more
- **Policy-as-code** — audit checks defined in YAML, easily extensible with custom policies
- **Embedded policies** — all checks are baked into the binary; no external files needed at runtime
- **HTML reports** — self-contained, dark-themed HTML reports with posture scoring (A–F)
- **JSON output** — machine-readable output for pipeline integration
- **CSV export** — spreadsheet-friendly output for compliance workflows
- **MCP server** — AI-assisted audit analysis via Model Context Protocol (works with Claude, OpenCode, etc.)
- **Offline analysis** — collect data once, analyze many times with snapshot persistence
- **Parallel collection** — concurrent API requests with configurable rate limiting
- **SARIF output** — [SARIF 2.1.0](https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html) format for GitHub Code Scanning integration
- **GitHub Action** — run audits directly in CI/CD pipelines with `PiotrMackowski/ClosedSSPM`
- **`--fail-on` threshold** — exit with code 2 when findings meet or exceed a severity level

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
# --- Option 1: Basic auth ---
export SNOW_INSTANCE=https://mycompany.service-now.com
export SNOW_USERNAME=audit_user
export SNOW_PASSWORD=secret

# --- Option 2: OAuth (client credentials) ---
export SNOW_INSTANCE=https://mycompany.service-now.com
export SNOW_CLIENT_ID=your_client_id
export SNOW_CLIENT_SECRET=your_client_secret

# --- Option 3: Key pair (JWT bearer) ---
export SNOW_INSTANCE=https://mycompany.service-now.com
export SNOW_CLIENT_ID=your_client_id
export SNOW_CLIENT_SECRET=your_client_secret
export SNOW_PRIVATE_KEY_PATH=/path/to/private-key.pem
export SNOW_KEY_ID=your_key_id
export SNOW_JWT_USER=svc_audit_user

# --- Option 4: API Key ---
export SNOW_INSTANCE=https://mycompany.service-now.com
export SNOW_API_KEY=your_api_key

# Full audit: collect + evaluate + report (ServiceNow is the default platform)
closedsspm audit --output report.html

# Explicitly specify a platform
closedsspm audit --platform servicenow --output report.html

# Or step by step:
closedsspm collect --output snapshot.json
closedsspm evaluate --snapshot snapshot.json --output report.html
```

### Snowflake Audit

```bash
# --- Option 1: Basic auth ---
export SNOWFLAKE_ACCOUNT=xy12345.us-east-1
export SNOWFLAKE_USER=audit_user
export SNOWFLAKE_PASSWORD=secret

# --- Option 2: Key pair (JWT) ---
export SNOWFLAKE_ACCOUNT=xy12345.us-east-1
export SNOWFLAKE_USER=audit_user
export SNOWFLAKE_PRIVATE_KEY_PATH=/path/to/rsa_key.p8

# --- Option 3: OAuth ---
export SNOWFLAKE_ACCOUNT=xy12345.us-east-1
export SNOWFLAKE_TOKEN=your_oauth_access_token

# --- Option 4: Programmatic Access Token (PAT) ---
export SNOWFLAKE_ACCOUNT=xy12345.us-east-1
export SNOWFLAKE_USER=audit_user
export SNOWFLAKE_PAT=your_programmatic_access_token
# Optional: override defaults
export SNOWFLAKE_ROLE=SECURITYADMIN       # default: SECURITYADMIN
export SNOWFLAKE_WAREHOUSE=COMPUTE_WH     # default: COMPUTE_WH

# Run the audit
closedsspm audit --platform snowflake --output report.html
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

By default the binary uses its 141 embedded policies. To override with external policies:

```bash
closedsspm audit --policies /path/to/my/policies --output report.html
```

## CLI Reference

### `closedsspm audit`

Run a full security audit: connect to a SaaS platform, collect data, evaluate policies, and generate a report.

```
Flags:
  --platform string       SaaS platform to audit (default "servicenow")
  --instance string       Platform instance URL (or set via env var)
  --output string         Output file path (default "report.html")
  --format string         Report format: html, json, csv, or sarif (default "html")
  --policies string       Path to custom policies directory (default: embedded)
  --save-snapshot string  Also save the raw snapshot to this file
  --concurrency int       Max parallel API requests (default 5)
  --rate-limit float      Max API requests per second (default 10)
  --fail-on string        Exit with code 2 if findings at or above this severity (CRITICAL, HIGH, MEDIUM, LOW, INFO)
```

### `closedsspm collect`

Collect data from a SaaS platform and save a snapshot for offline analysis.

```
Flags:
  --platform string    SaaS platform to collect from (default "servicenow")
  --instance string    Platform instance URL (or set via env var)
  --output string      Output snapshot file path (default "snapshot.json")
  --concurrency int    Max parallel API requests (default 5)
  --rate-limit float   Max API requests per second (default 10)
```

### `closedsspm evaluate`

Evaluate policies against a previously saved snapshot.

```
Flags:
  --snapshot string   Path to snapshot file (default "snapshot.json")
  --output string     Output file path (default "report.html")
  --format string   Report format: html, json, csv, or sarif (default "html")
  --policies string   Path to custom policies directory (default: embedded)
  --fail-on string  Exit with code 2 if findings at or above this severity (CRITICAL, HIGH, MEDIUM, LOW, INFO)
```

### `closedsspm mcp`

Start a Model Context Protocol server over stdio for AI-assisted audit analysis.

```
Flags:
  --snapshot string   Path to snapshot file (default "snapshot.json")
  --policies string   Path to custom policies directory (default: embedded)
```

### `closedsspm checks list`

List all available security checks.

```
Flags:
  --policies string   Path to custom policies directory (default: embedded)
```

### Environment Variables

All credentials are read from environment variables. **Never store credentials in config files.**

Each platform uses its own set of environment variables. The `--platform` flag (default: `servicenow`) determines which variables are read.

#### ServiceNow (`--platform servicenow`)

| Variable | Description | Required |
|----------|-------------|----------|
| `SNOW_INSTANCE` | ServiceNow instance URL (e.g. `https://mycompany.service-now.com`) | Yes |
| `SNOW_USERNAME` | Username for basic authentication | For basic auth |
| `SNOW_PASSWORD` | Password for basic authentication | For basic auth |
| `SNOW_CLIENT_ID` | OAuth 2.0 client ID | For OAuth / key pair |
| `SNOW_CLIENT_SECRET` | OAuth 2.0 client secret | For OAuth / key pair |
| `SNOW_PRIVATE_KEY_PATH` | Path to RSA private key PEM file | For key pair |
| `SNOW_KEY_ID` | Key ID from ServiceNow JWT Verifier Map | For key pair |
| `SNOW_JWT_USER` | ServiceNow username for JWT `sub` claim (cannot be admin) | For key pair |
| `SNOW_API_KEY` | API key token (from REST API Key table) | For API key auth |

**Authentication method is auto-detected** based on which variables are set:

| Priority | Method | Required Variables |
|----------|--------|--------------------|
| 1 | API key | `SNOW_API_KEY` |
| 2 | Key pair (JWT bearer) | `SNOW_CLIENT_ID` + `SNOW_CLIENT_SECRET` + `SNOW_PRIVATE_KEY_PATH` |
| 3 | OAuth (client credentials) | `SNOW_CLIENT_ID` + `SNOW_CLIENT_SECRET` |
| 4 | Basic | `SNOW_USERNAME` + `SNOW_PASSWORD` |

> **New to API key auth?** Run [`docs/setup_apikey_auth.py`](docs/setup_apikey_auth.py) — it configures everything via REST API (idempotent, well-commented).

#### Snowflake (`--platform snowflake`)

| Variable | Description | Required |
|----------|-------------|----------|
| `SNOWFLAKE_ACCOUNT` | Account identifier (e.g. `xy12345.us-east-1`) | Yes |
| `SNOWFLAKE_USER` | Username | For basic / key pair auth |
| `SNOWFLAKE_PASSWORD` | Password | For basic auth |
| `SNOWFLAKE_PRIVATE_KEY_PATH` | Path to RSA private key PEM file | For key pair (JWT) |
| `SNOWFLAKE_TOKEN` | OAuth access token | For OAuth |
| `SNOWFLAKE_PAT` | Programmatic access token | For PAT auth |
| `SNOWFLAKE_ROLE` | Role to assume (default: `SECURITYADMIN`) | No |
| `SNOWFLAKE_WAREHOUSE` | Warehouse for queries (default: `COMPUTE_WH`) | No |
| `SNOWFLAKE_DATABASE` | Database (default: `SNOWFLAKE` for ACCOUNT_USAGE views) | No |

**Authentication method is auto-detected** based on which variables are set:

| Priority | Method | Required Variables |
|----------|--------|--------------------|
| 1 | Key pair (JWT) | `SNOWFLAKE_USER` + `SNOWFLAKE_PRIVATE_KEY_PATH` |
| 2 | PAT | `SNOWFLAKE_USER` + `SNOWFLAKE_PAT` |
| 3 | OAuth | `SNOWFLAKE_TOKEN` |
| 4 | Basic | `SNOWFLAKE_USER` + `SNOWFLAKE_PASSWORD` |

## Architecture

```
closedsspm/
├── cmd/
│   ├── closedsspm/
│   │   ├── main.go          # CLI commands (platform-agnostic)
│   │   ├── main_test.go     # CLI helper tests
│   │   └── platforms.go     # Blank imports to register platform connectors
│   └── mcp/                 # Standalone MCP server
├── internal/
│   ├── collector/            # Collector interface & snapshot model
│   ├── connector/
│   │   ├── registry.go       # Platform connector registry
│   │   ├── servicenow/       # ServiceNow API client & collector
│   │   └── snowflake/        # Snowflake SQL client & collector
│   ├── finding/              # Finding model & severity
│   ├── mcpserver/            # MCP server implementation
│   ├── policy/               # Policy engine (YAML loading & evaluation)
│   └── report/
│       ├── csv/             # CSV report generator
│       ├── html/            # HTML report generator
│       └── json/            # JSON report generator
│       ├── sarif/           # SARIF 2.1.0 report generator
└── policies/
    ├── servicenow/           # ServiceNow policy definitions (YAML, embedded at build)
    └── snowflake/            # Snowflake policy definitions (YAML, embedded at build)
```

## Subprojects

| Repository | Purpose | Status |
|------------|---------|--------|
| [homebrew-closedsspm](https://github.com/PiotrMackowski/homebrew-closedsspm) | Homebrew tap — hosts the formula for `brew install closedsspm` | Active — automatically updated by goreleaser on each release |

## Security Checks

141 built-in checks across two platforms.

### ServiceNow (86 checks)

| Category | Count | Examples |
|----------|-------|---------|
| **ACL** | 9 | Unprotected ACLs, wildcard roles, public access, deny-unless audit |
| **Roles** | 10 | Admin role assignments, elevated privileges, role includes, security_admin, impersonator, oauth_admin |
| **Scripts** | 6 | eval() usage, client-callable script includes, global UI scripts |
| **Integrations** | 7 | Unauthenticated endpoints, basic auth, unvalidated MID servers |
| **Instance Config** | 32 | HTTPS enforcement, session timeout, password policy, CSRF, XSS prevention, TLS, sandbox, SAML signing, SSO bypass |
| **Users** | 5 | Never-logged-in accounts, locked-out active users, service account hygiene |
| **SAST** | 17 | Hardcoded credentials, eval(), GlideEvaluator, insecure HTTP, query injection, XSS sinks, workflow bypass |

### Snowflake (55 checks)

| Category | Count | Examples |
|----------|-------|---------|
| **IAM** | 8 | MFA not enabled, ACCOUNTADMIN/SYSADMIN default role, password-only auth, disabled users with roles, missing email/owner, MFA enrollment prompt |
| **ACL** | 8 | ACCOUNTADMIN/SECURITYADMIN/SYSADMIN grants, MANAGE GRANTS privilege, GRANT OPTION, role ownership, ACCOUNT ownership |
| **Network** | 3 | Missing network policies, no blocked IP list, network policy IP restrictions summary |
| **Config** | 22 | Unencrypted copy, storage integration, data exfiltration controls, encryption rekeying, session/password policies, warehouse monitors, MFA caching, session keep-alive, OAuth role blocking, network policy enforcement |
| **Data Sharing** | 1 | Outbound share review |
| **Audit** | 3 | Failed logins, logins without MFA, password-only logins |
| **SAST** | 10 | AWS keys in procedures/UDFs, private keys, eval(), new Function(), SQL injection, subprocess/os.system |

Run `closedsspm checks list` to see all individual rules.

## MCP Server Interface

The MCP server exposes 6 tools and 2 resources over **stdio transport** for AI-assisted security audit analysis.

### Tools

| Tool | Parameters | Description |
|------|-----------|-------------|
| `list_findings` | `severity?` `category?` | List findings, optionally filtered by severity (CRITICAL/HIGH/MEDIUM/LOW/INFO) or category |
| `get_finding` | `finding_id` (required) | Get detailed information about a specific finding |
| `get_summary` | _(none)_ | Overall audit summary with posture score and finding counts by severity/category |
| `query_snapshot` | `table` (required) `field?` `value?` `limit?` | Query raw ServiceNow records from the snapshot (default limit: 50, max: 500) |
| `suggest_remediation` | `finding_id` (required) | Get remediation steps and context for a specific finding |
| `list_tables` | _(none)_ | List all collected tables with record counts |

### Resources

| URI | Description |
|-----|-------------|
| `closedsspm://summary` | Audit posture summary (JSON) |
| `closedsspm://snapshot/meta` | Snapshot metadata: platform, instance URL, collection time, table count (JSON) |


## GitHub Action

Run ClosedSSPM audits directly in your CI/CD pipeline:

```yaml
- name: Run ClosedSSPM audit
  id: audit
  uses: PiotrMackowski/ClosedSSPM@v0  # or pin to a specific release tag
  with:
    instance: ${{ secrets.SNOW_INSTANCE }}
    # --- Basic auth ---
    username: ${{ secrets.SNOW_USERNAME }}
    password: ${{ secrets.SNOW_PASSWORD }}
    # --- OR OAuth (client credentials) ---
    # client-id: ${{ secrets.SNOW_CLIENT_ID }}
    # client-secret: ${{ secrets.SNOW_CLIENT_SECRET }}
    # --- OR Key pair (JWT bearer) ---
    # client-id: ${{ secrets.SNOW_CLIENT_ID }}
    # client-secret: ${{ secrets.SNOW_CLIENT_SECRET }}
    # private-key: ${{ secrets.SNOW_PRIVATE_KEY }}
    # key-id: ${{ secrets.SNOW_KEY_ID }}
    # jwt-user: ${{ secrets.SNOW_JWT_USER }}
    # --- OR API Key ---
    # api-key: ${{ secrets.SNOW_API_KEY }}
    format: sarif
    fail-on: HIGH

- name: Upload SARIF to GitHub Code Scanning
  if: always()
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: ${{ steps.audit.outputs.sarif-path }}
```

### Action Inputs

| Input | Required | Default | Description |
|-------|----------|---------|-------------|
| `instance` | Yes | — | Platform instance URL |
| `platform` | No | `servicenow` | SaaS platform to audit |
| `username` | No | — | Username for basic auth |
| `password` | No | — | Password for basic auth |
| `client-id` | No | — | OAuth 2.0 client ID |
| `client-secret` | No | — | OAuth 2.0 client secret |
| `private-key` | No | — | RSA private key PEM content for JWT key pair auth |
| `key-id` | No | — | Key ID from ServiceNow JWT Verifier Map |
| `jwt-user` | No | — | ServiceNow username for JWT `sub` claim (cannot be admin) |
| `api-key` | No | — | ServiceNow API key token |
| `format` | No | `sarif` | Report format: html, json, csv, or sarif |
| `fail-on` | No | `none` | Fail if findings at/above severity: CRITICAL, HIGH, MEDIUM, LOW, INFO |

All credential inputs should be passed via [GitHub encrypted secrets](https://docs.github.com/en/actions/security-for-github-actions/security-guides/using-secrets-in-github-actions). Authentication method is auto-detected based on which inputs are provided (same priority as the CLI).

### Action Outputs

| Output | Description |
|--------|-------------|
| `report-path` | Path to the generated report file |
| `finding-count` | Total number of findings |
| `posture-score` | Posture score grade (A–F) |
| `sarif-path` | Path to SARIF file (only when format=sarif) |
## Security Best Practices

- Credentials are **only** read from environment variables, never from config files
- Snapshots may contain sensitive data — treat them as confidential
- The MCP server uses **stdio transport only** (no network exposure)
- The tool is **read-only** — it never writes to your SaaS platform
- ServiceNow audit user should have **read-only** roles (minimum required permissions)

### Minimum ServiceNow Permissions

Create a dedicated audit user with these roles:
- `itil` (read access to most tables)
- `security_admin` (read access to ACLs and security config)
- Disable `web_service_access_only` is NOT recommended for this user; use OAuth where possible

## Writing Custom Policies

Policies are YAML files organized by platform in the `policies/` directory (e.g. `policies/servicenow/`):

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

## Testing

Run the full test suite:

```bash
make test
# or directly:
go test ./...
```

Run static analysis:

```bash
make vet
go vet ./...
```

All pull requests must pass CI (tests + `go vet`) before merging.

## Contributing

Contributions are welcome. Please follow these guidelines:

1. **Open an issue first** — describe the bug or feature before starting work
2. **Fork and branch** — create a feature branch from `main`
3. **Follow existing patterns** — match the project's code style and structure
4. **Add tests** — new features and bug fixes should include tests
5. **All CI checks must pass** — tests, `go vet`, CodeQL, and Trivy scans
6. **One PR per change** — keep pull requests focused and reviewable

See [SECURITY.md](SECURITY.md) for reporting vulnerabilities (do **not** use public issues for security bugs).

## Reporting Issues

Found a bug or have a feature request? Open an issue on the [GitHub Issues](https://github.com/PiotrMackowski/ClosedSSPM/issues) page.

When reporting a bug, please include:
- ClosedSSPM version (`closedsspm --version`)
- Operating system and architecture
- Steps to reproduce the issue
- Expected vs actual behavior
- Any relevant error output (sanitize credentials before sharing)

## Reporting Vulnerabilities

**Do not report security vulnerabilities through public issues.**

Please use [GitHub Security Advisories](https://github.com/PiotrMackowski/ClosedSSPM/security/advisories/new) to report vulnerabilities privately. See [SECURITY.md](SECURITY.md) for full details including response timelines and scope.


## Development

This project is developed with AI-assisted coding using [OpenCode](https://github.com/anomalyco/opencode).

## License

Apache 2.0 — see [LICENSE](LICENSE)
