# Security

How to report vulnerabilities and the security principles behind ClosedSSPM.

## Reporting Vulnerabilities

If you discover a security vulnerability in ClosedSSPM, report it through GitHub Security Advisories rather than opening a public issue. This keeps disclosure coordinated and protects users.

- **Response Time**: We aim to respond to all security reports within 72 hours.
- **What to Include**:
    - A detailed description of the vulnerability.
    - Step-by-step instructions to reproduce the issue.
    - The versions of ClosedSSPM affected.
    - An assessment of the potential impact.

## Security Design Principles

ClosedSSPM is built with several core security principles:

- **Read-only by Design**: The tool only collects configuration data. It never attempts to modify, update, or delete settings on the target platform.
- **No Credential Storage**: ClosedSSPM does not store credentials. Authentication is handled via environment variables or command-line flags and is only held in memory during the audit process.
- **Local-only MCP**: The Model Context Protocol (MCP) server communicates over `stdio` and does not expose any network services.
- **Input Validation**: All user inputs, including policy definitions and command-line flags, are strictly validated before use.
- **No Eval**: The tool does not use dynamic code execution or `eval` functions, reducing the risk of injection attacks.
- **Dependency Minimalism**: We keep external dependencies to a minimum and use SBOM (Software Bill of Materials) tracking to manage supply chain risks.
- **SHA-pinned CI**: All GitHub Actions used in our continuous integration pipelines are pinned to specific SHAs to prevent supply chain compromise.

## Dependency Management

- **Dependabot**: We use Dependabot to automatically identify and update vulnerable dependencies.
- **CodeQL**: Our codebase is scanned with CodeQL to identify potential security flaws during the development cycle.

## Snapshot Data Handling

Audit snapshots contain sensitive configuration information about your cloud and SaaS environments.

!!! warning
    Treat snapshot files as highly confidential data. Do not commit them to version control systems (VCS) or share them over unencrypted channels.
