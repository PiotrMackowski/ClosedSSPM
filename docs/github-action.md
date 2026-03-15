# GitHub Action

ClosedSSPM provides a GitHub Action to automate security audits as part of your CI/CD pipelines. This action can perform audits, generate reports, and upload SARIF results to GitHub Code Scanning.

## Quick Start

The following example runs a ServiceNow audit on a daily schedule and uploads the results to GitHub's Security tab:

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

## Platform Examples

### ServiceNow

ServiceNow supports four authentication methods: basic auth, OAuth 2.0, JWT key-pair, and API key.

=== "Basic Auth"

    ```yaml
    - name: Audit ServiceNow
      id: audit
      uses: PiotrMackowski/ClosedSSPM@v0
      with:
        platform: 'servicenow'
        instance: ${{ secrets.SNOW_INSTANCE }}
        username: ${{ secrets.SNOW_USERNAME }}
        password: ${{ secrets.SNOW_PASSWORD }}
        format: 'sarif'
    ```

=== "OAuth 2.0"

    ```yaml
    - name: Audit ServiceNow
      id: audit
      uses: PiotrMackowski/ClosedSSPM@v0
      with:
        platform: 'servicenow'
        instance: ${{ secrets.SNOW_INSTANCE }}
        username: ${{ secrets.SNOW_USERNAME }}
        password: ${{ secrets.SNOW_PASSWORD }}
        client-id: ${{ secrets.SNOW_CLIENT_ID }}
        client-secret: ${{ secrets.SNOW_CLIENT_SECRET }}
        format: 'sarif'
    ```

=== "JWT Key-Pair"

    ```yaml
    - name: Audit ServiceNow
      id: audit
      uses: PiotrMackowski/ClosedSSPM@v0
      with:
        platform: 'servicenow'
        instance: ${{ secrets.SNOW_INSTANCE }}
        private-key: ${{ secrets.SNOW_PRIVATE_KEY }}
        key-id: ${{ secrets.SNOW_KEY_ID }}
        jwt-user: ${{ secrets.SNOW_JWT_USER }}
        format: 'sarif'
    ```

### Snowflake

Snowflake supports basic auth, JWT key-pair, OAuth, and programmatic access tokens.

=== "Basic Auth"

    ```yaml
    - name: Audit Snowflake
      id: audit
      uses: PiotrMackowski/ClosedSSPM@v0
      with:
        platform: 'snowflake'
        snowflake-account: ${{ secrets.SNOWFLAKE_ACCOUNT }}
        snowflake-user: ${{ secrets.SNOWFLAKE_USER }}
        snowflake-password: ${{ secrets.SNOWFLAKE_PASSWORD }}
        format: 'sarif'
    ```

=== "Key-Pair Auth"

    ```yaml
    - name: Audit Snowflake
      id: audit
      uses: PiotrMackowski/ClosedSSPM@v0
      with:
        platform: 'snowflake'
        snowflake-account: ${{ secrets.SNOWFLAKE_ACCOUNT }}
        snowflake-user: ${{ secrets.SNOWFLAKE_USER }}
        snowflake-private-key: ${{ secrets.SNOWFLAKE_PRIVATE_KEY }}
        format: 'sarif'
    ```

=== "OAuth Token"

    ```yaml
    - name: Audit Snowflake
      id: audit
      uses: PiotrMackowski/ClosedSSPM@v0
      with:
        platform: 'snowflake'
        snowflake-account: ${{ secrets.SNOWFLAKE_ACCOUNT }}
        snowflake-user: ${{ secrets.SNOWFLAKE_USER }}
        snowflake-token: ${{ secrets.SNOWFLAKE_TOKEN }}
        format: 'sarif'
    ```

=== "PAT"

    ```yaml
    - name: Audit Snowflake
      id: audit
      uses: PiotrMackowski/ClosedSSPM@v0
      with:
        platform: 'snowflake'
        snowflake-account: ${{ secrets.SNOWFLAKE_ACCOUNT }}
        snowflake-user: ${{ secrets.SNOWFLAKE_USER }}
        snowflake-pat: ${{ secrets.SNOWFLAKE_PAT }}
        format: 'sarif'
    ```

### Entra ID

Entra ID supports OAuth client credentials (client secret or certificate-based assertion).

=== "Client Secret"

    ```yaml
    - name: Audit Entra ID
      id: audit
      uses: PiotrMackowski/ClosedSSPM@v0
      with:
        platform: 'entra'
        entra-tenant-id: ${{ secrets.ENTRA_TENANT_ID }}
        entra-client-id: ${{ secrets.ENTRA_CLIENT_ID }}
        entra-client-secret: ${{ secrets.ENTRA_CLIENT_SECRET }}
        format: 'sarif'
    ```

=== "Certificate Auth"

    ```yaml
    - name: Audit Entra ID
      id: audit
      uses: PiotrMackowski/ClosedSSPM@v0
      with:
        platform: 'entra'
        entra-tenant-id: ${{ secrets.ENTRA_TENANT_ID }}
        entra-client-id: ${{ secrets.ENTRA_CLIENT_ID }}
        entra-certificate: ${{ secrets.ENTRA_CERTIFICATE_PEM }}
        format: 'sarif'
    ```

    Store the PEM certificate (including private key) as a GitHub secret. The action writes it to a temporary file that is removed after the audit completes.

### Google Workspace

Google Workspace supports OAuth bearer tokens, service account JSON keys, and Application Default Credentials (ADC).

=== "Access Token"

    ```yaml
    - name: Audit Google Workspace
      id: audit
      uses: PiotrMackowski/ClosedSSPM@v0
      with:
        platform: 'googleworkspace'
        gw-access-token: ${{ secrets.GW_ACCESS_TOKEN }}
        gw-delegated-user: ${{ secrets.GW_DELEGATED_USER }}
        format: 'sarif'
    ```

=== "Service Account"

    ```yaml
    - name: Audit Google Workspace
      id: audit
      uses: PiotrMackowski/ClosedSSPM@v0
      with:
        platform: 'googleworkspace'
        gw-credentials-json: ${{ secrets.GW_CREDENTIALS_JSON }}
        gw-delegated-user: ${{ secrets.GW_DELEGATED_USER }}
        format: 'sarif'
    ```

    Store the full service account JSON key as a GitHub secret. The action writes it to a temporary file that is removed after the audit completes.

=== "ADC (GCP Workload Identity)"

    ```yaml
    - name: Authenticate to GCP
      uses: google-github-actions/auth@v2
      with:
        workload_identity_provider: ${{ secrets.GCP_WORKLOAD_IDENTITY_PROVIDER }}
        service_account: ${{ secrets.GCP_SERVICE_ACCOUNT }}

    - name: Audit Google Workspace
      id: audit
      uses: PiotrMackowski/ClosedSSPM@v0
      with:
        platform: 'googleworkspace'
        gw-use-adc: 'true'
        gw-delegated-user: ${{ secrets.GW_DELEGATED_USER }}
        format: 'sarif'
    ```

    Use [Workload Identity Federation](https://cloud.google.com/iam/docs/workload-identity-federation) for keyless authentication from GitHub Actions to GCP.

## Uploading Results to GitHub Code Scanning

All platform examples above can be paired with the SARIF upload step to surface findings in GitHub's Security tab:

```yaml
      - name: Upload SARIF to GitHub
        uses: github/codeql-action/upload-sarif@v3
        if: always()
        with:
          sarif_file: ${{ steps.audit.outputs.sarif-path }}
```

!!! note
    The `if: always()` condition ensures results are uploaded even when findings exceed the `fail-on` threshold (exit code 2).

## Action Inputs

### Common Inputs

| Input | Required | Default | Description |
|-------|----------|---------|-------------|
| `platform` | No | `servicenow` | Target platform: `servicenow`, `snowflake`, `entra`, or `googleworkspace`. |
| `format` | No | `sarif` | Report format: `html`, `json`, `csv`, or `sarif`. |
| `fail-on` | No | `none` | Fail if findings at or above this severity: `CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `INFO`. |

### ServiceNow Inputs

| Input | Description |
|-------|-------------|
| `instance` | Instance URL (e.g. `https://mycompany.service-now.com`). |
| `username` | Username for basic auth or OAuth. |
| `password` | Password for basic auth or OAuth. |
| `client-id` | OAuth 2.0 client ID. |
| `client-secret` | OAuth 2.0 client secret. |
| `private-key` | RSA private key PEM content for JWT key-pair auth. |
| `key-id` | Key ID from JWT Verifier Map. |
| `jwt-user` | Username for JWT sub claim. |

### Snowflake Inputs

| Input | Description |
|-------|-------------|
| `snowflake-account` | Account identifier (e.g. `xy12345.us-east-1`). |
| `snowflake-user` | Username. |
| `snowflake-password` | Password for basic auth. |
| `snowflake-private-key` | RSA private key PEM content for key-pair auth. |
| `snowflake-pat` | Programmatic access token. |
| `snowflake-token` | OAuth access token. |
| `snowflake-role` | Role to assume (default: `SECURITYADMIN`). |
| `snowflake-warehouse` | Warehouse for queries (default: `COMPUTE_WH`). |
| `snowflake-database` | Database (default: `SNOWFLAKE`). |

### Entra ID Inputs

| Input | Description |
|-------|-------------|
| `entra-tenant-id` | Azure AD / Entra ID tenant ID. |
| `entra-client-id` | App registration client ID. |
| `entra-client-secret` | Client secret for OAuth client credentials. |
| `entra-certificate` | PEM certificate content for client assertion auth. |

### Google Workspace Inputs

| Input | Description |
|-------|-------------|
| `gw-access-token` | OAuth2 bearer token. |
| `gw-credentials-json` | Service account JSON key content. |
| `gw-delegated-user` | Super admin email for domain-wide delegation. |
| `gw-use-adc` | Use Application Default Credentials (`true`/`false`). |

!!! warning
    Never hardcode credentials in your workflow YAML files. Always use [GitHub Encrypted Secrets](https://docs.github.com/en/actions/security-for-github-actions/security-guides/using-secrets-in-github-actions) to store sensitive information.

## Action Outputs

| Output | Description |
|--------|-------------|
| `report-path` | Path to the generated report file. |
| `finding-count` | The total number of security findings identified. |
| `posture-score` | The overall security posture grade (A–F). |
| `sarif-path` | Path to the generated SARIF file (only when `format=sarif`). |

## Authentication Auto-detection

The GitHub Action follows the same authentication priority as the CLI. It will automatically detect and use credentials provided through the action inputs. If multiple authentication methods are available, it will select the most appropriate one based on the platform's configuration.
