# GitHub Action

ClosedSSPM provides a GitHub Action to automate security audits as part of your CI/CD pipelines. This action can perform audits, generate reports, and upload SARIF results to GitHub Code Scanning.

## Example Workflow

The following example shows how to run a ServiceNow audit and upload the results to GitHub's Security tab:

```yaml
name: "ClosedSSPM Audit"

on:
  schedule:
    - cron: '0 0 * * *'
  workflow_dispatch:

jobs:
  audit:
    runs-on: ubuntu-latest
    steps:
      - name: Run ClosedSSPM Audit
        id: audit
        uses: PiotrMackowski/ClosedSSPM@v0
        with:
          platform: 'servicenow'
          instance: ${{ secrets.SNOW_INSTANCE }}
          username: ${{ secrets.SNOW_USERNAME }}
          password: ${{ secrets.SNOW_PASSWORD }}
          format: 'sarif'
          fail-on: 'HIGH'

      - name: Upload SARIF to GitHub
        uses: github/codeql-action/upload-sarif@v3
        if: always()
        with:
          sarif_file: ${{ steps.audit.outputs.sarif-path }}
```

## Action Inputs

| Input | Required | Default | Description |
|-------|----------|---------|-------------|
| `platform` | No | "servicenow" | Target platform (servicenow, entra, snowflake, googleworkspace). |
| `instance` | Yes | | Instance URL or identifier. |
| `username` | No | | Authentication username. |
| `password` | No | | Authentication password. |
| `client-id` | No | | OAuth Client ID. |
| `client-secret` | No | | OAuth Client Secret. |
| `private-key` | No | | Private key for JWT/Key-pair auth. |
| `key-id` | No | | Key ID for authentication. |
| `jwt-user` | No | | User for JWT authentication. |
| `api-key` | No | | Platform API Key. |
| `format` | No | "sarif" | Output format (html, json, csv, sarif). |
| `fail-on` | No | | Exit with failure on findings of this severity or higher. |

!!! warning
    Never hardcode credentials in your workflow YAML files. Always use GitHub Encrypted Secrets to store sensitive information like passwords and API keys.

## Action Outputs

| Output | Description |
|--------|-------------|
| `report-path` | Path to the generated report file. |
| `finding-count` | The total number of security findings identified. |
| `posture-score` | The overall security posture grade (A-F). |
| `sarif-path` | Path to the generated SARIF file, if applicable. |

## Authentication Auto-detection

The GitHub Action follows the same authentication priority as the CLI. It will automatically detect and use credentials provided through the action inputs. If multiple authentication methods are available, it will select the most appropriate one based on the platform's configuration.
