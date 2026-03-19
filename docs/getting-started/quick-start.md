# Quick Start

Run your first security audit.

Each platform requires specific environment variables for authentication. These are the simplest authentication methods for a quick test.

=== "ServiceNow"

    The default platform for ClosedSSPM is ServiceNow.

    ```bash
    export SNOW_INSTANCE=https://mycompany.service-now.com
    export SNOW_USERNAME=audit_user
    export SNOW_PASSWORD=secret
    closedsspm audit --output report.html
    ```

=== "Snowflake"

    To audit a Snowflake account, use the `--platform snowflake` flag.

    ```bash
    export SNOWFLAKE_ACCOUNT=xy12345.us-east-1
    export SNOWFLAKE_USER=audit_user
    export SNOWFLAKE_PASSWORD=secret
    closedsspm audit --platform snowflake --output report.html
    ```

=== "Google Workspace"

    Auditing Google Workspace requires a Service Account with domain-wide delegation.

    ```bash
    export GW_CREDENTIALS_FILE=/path/to/service-account.json
    export GW_DELEGATED_USER=admin@yourdomain.com
    closedsspm audit --platform googleworkspace --output report.html
    ```

=== "Entra ID"

    To audit Entra ID (Azure AD), use a Service Principal (App Registration).

    ```bash
    export ENTRA_TENANT_ID=your-tenant-id
    export ENTRA_CLIENT_ID=your-client-id
    export ENTRA_CLIENT_SECRET=your-client-secret
    closedsspm audit --platform entra --output report.html
    ```

!!! warning
    For production use, avoid leaving credentials in your shell history. Consider using secret managers or CI/CD secrets for credential injection.

## Review the Audit Results

After the command completes, you can view the report.

- **HTML Report**: Open `report.html` in your web browser for a detailed view of all checks and remediation steps.
- **Other Formats**: You can change the output format using the `--format` flag. Available options include `html`, `json`, `csv`, and `sarif`.
- **List All Checks**: Run `closedsspm checks list` to see all available security checks for your platform.

## What's Next?

After your first audit:

- **Platform-specific Guides**: Check individual platform documentation for other authentication methods.
- **CLI Reference**: See the full list of commands and flags available in the CLI documentation.
- **Custom Policies**: Write YAML policies for project-specific checks.
