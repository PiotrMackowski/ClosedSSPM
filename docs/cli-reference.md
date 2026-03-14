# CLI Reference

ClosedSSPM provides a unified command line interface to manage the entire audit lifecycle, from data collection to reporting.

## closedsspm audit

The `audit` command performs a full audit cycle. It connects to the target platform, collects relevant configuration data, evaluates the data against security policies, and generates a final report.

### Flags

| Flag | Default | Description |
|------|---------|-------------|
| `--platform` | "servicenow" | The target platform to audit (e.g., servicenow, entra, snowflake, googleworkspace). |
| `--instance` | | The instance URL or identifier for the target platform. |
| `--output` | "report.html" | Path where the final report will be saved. |
| `--format` | "html" | The output format of the report. Supported: html, json, csv, sarif. |
| `--policies` | | Path to a directory containing custom policy files. |
| `--save-snapshot` | | If set, the raw collected data will be saved as a JSON snapshot. |
| `--concurrency` | 5 | Number of concurrent requests to the platform API. |
| `--rate-limit` | 10 | Maximum number of requests per second. |
| `--fail-on` | | Exit with a non-zero code if findings of this severity or higher are found (CRITICAL, HIGH, MEDIUM, LOW, INFO). |

### Examples

Run a standard ServiceNow audit:
```bash
closedsspm audit --instance https://dev12345.service-now.com --output results.html
```

Run an Entra audit and fail if any HIGH severity issues are found:
```bash
closedsspm audit --platform entra --instance my-tenant-id --fail-on HIGH
```

## closedsspm collect

The `collect` command focuses exclusively on retrieving configuration data from the target platform. It produces a snapshot file that can be used for offline evaluation later.

### Flags

| Flag | Default | Description |
|------|---------|-------------|
| `--platform` | "servicenow" | The target platform to collect data from. |
| `--instance` | | The instance URL or identifier. |
| `--output` | "snapshot.json" | Path where the collected data snapshot will be saved. |
| `--concurrency` | 5 | Number of concurrent requests to the platform API. |
| `--rate-limit` | 10 | Maximum number of requests per second. |

### Examples

Create a snapshot of a Snowflake environment:
```bash
closedsspm collect --platform snowflake --instance account.region --output snow_snap.json
```

## closedsspm evaluate

The `evaluate` command performs security analysis on a previously collected snapshot file. This allows for auditing environments without needing direct network access to the platform during the evaluation phase.

### Flags

| Flag | Default | Description |
|------|---------|-------------|
| `--snapshot` | "snapshot.json" | Path to the snapshot file to analyze. |
| `--output` | "report.html" | Path where the evaluation report will be saved. |
| `--format` | "html" | The output format of the report (html, json, csv, sarif). |
| `--policies` | | Path to custom policy files. |
| `--fail-on` | | Exit with a non-zero code if findings of this severity or higher are found. |

### Examples

Analyze a local snapshot file:
```bash
closedsspm evaluate --snapshot snapshot.json --format json --output report.json
```

## closedsspm mcp

The `mcp` command starts a Model Context Protocol (MCP) server. This enables AI assistants like Claude to interact with audit findings and snapshot data directly.

### Flags

| Flag | Default | Description |
|------|---------|-------------|
| `--snapshot` | "snapshot.json" | Path to the snapshot file the server should expose. |
| `--policies` | | Path to custom policies used for findings. |

### Examples

Start the MCP server for an interactive session:
```bash
closedsspm mcp --snapshot my_audit_snapshot.json
```

## closedsspm checks list

The `checks list` command provides a listing of all security checks available in the current version of ClosedSSPM.

### Flags

| Flag | Default | Description |
|------|---------|-------------|
| `--policies` | | Include custom policies from the specified path in the list. |

### Examples

List all available checks:
```bash
closedsspm checks list
```
