# Google Workspace

Google Workspace audits focus on application governance, OAuth risk assessment, and user account status across the organization.

## Authentication

Google Workspace uses Service Account authentication to perform organization-wide audits.

=== "Service Account"
    Domain-wide delegation is required for the service account to access user data.

    ```bash
    export GW_CREDENTIALS_FILE="/path/to/credentials.json"
    export GW_DELEGATED_USER="admin@yourdomain.com"
    ```

## Environment Variables

| Variable | Description |
| :--- | :--- |
| GW_CREDENTIALS_FILE | The path to your Google Cloud Service Account JSON file |
| GW_DELEGATED_USER | The email address of a user with domain-wide delegated access |

## Prerequisites

Before running the scan, ensure the following are configured in your Google Cloud and Workspace environment:

*   Create a Google Cloud Project and Service Account.
*   Enable Domain-Wide Delegation for the Service Account.
*   The Service Account requires the following OAuth scopes:
    *   `https://www.googleapis.com/auth/admin.directory.user.readonly`
    *   `https://www.googleapis.com/auth/admin.directory.user.security`
    *   `https://www.googleapis.com/auth/admin.reports.audit.readonly`

## Security Checks

Google Workspace scanning focuses on third-party application risk and identity posture.

| Category | Count | Examples |
| :--- | :--- | :--- |
| OAuth | 10 | Full Gmail/Drive/Admin SDK access tokens, Gmail send permission, contacts/calendar access, anonymous app tokens, native app tokens, OAuth authorization events, suspended user accounts |
