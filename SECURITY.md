# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 0.x.x   | :white_check_mark: |

Security updates are applied to the latest release only. We recommend always running the most recent version.

## Reporting a Vulnerability

**Please do NOT report security vulnerabilities through public GitHub issues.**

Instead, use [GitHub Security Advisories](https://github.com/PiotrMackowski/ClosedSSPM/security/advisories/new) to report vulnerabilities privately.

You should receive an initial response within **72 hours**. If the issue is confirmed, a fix will be released as soon as possible, typically within **7 days** depending on complexity.

### What to Include

- Description of the vulnerability
- Steps to reproduce
- Affected version(s)
- Potential impact assessment

### What to Expect

- Acknowledgment within 72 hours
- Regular updates on remediation progress
- Credit in the release notes (unless you prefer anonymity)
- CVE assignment for confirmed vulnerabilities where appropriate

## Security Design

ClosedSSPM is designed with security as a core principle:

- **Read-only by design** — the tool never writes to audited SaaS instances
- **No credential storage** — credentials are only read from environment variables, never persisted to disk or config files
- **Stdio-only MCP transport** — the MCP server uses stdio transport exclusively, with no network exposure
- **Input validation** — all MCP inputs are validated against strict patterns (length limits, regex allowlists)
- **No eval or dynamic code execution** — policies are declarative YAML, never executed as code
- **Dependency minimalism** — minimal third-party dependencies to reduce supply chain risk
- **SBOM generation** — every release includes a Software Bill of Materials
- **SHA-pinned CI** — all GitHub Actions are pinned to full commit SHAs

## Dependency Management

Dependencies are monitored by:

- **Dependabot** — automated version update PRs for Go modules and GitHub Actions
- **CodeQL** — weekly static analysis scanning
- **Go vulnerability database** — checked via `govulncheck` (planned)

## Snapshot Data Handling

Snapshots collected by ClosedSSPM may contain sensitive configuration data from your SaaS instance. Treat snapshot files as confidential:

- Do not commit snapshots to version control
- Do not share snapshots in public channels
- Delete snapshots after analysis is complete
- Store snapshots with appropriate filesystem permissions
