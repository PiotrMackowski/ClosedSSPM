# Entra ID

Entra ID audits evaluate application permissions, credential hygiene, and identity governance within your Microsoft 365 tenant.

## Authentication

Entra ID uses App Registration with client secret credentials for Microsoft Graph API access.

=== "App Registration"
    A dedicated application registration in the Azure portal.

    ```bash
    export ENTRA_TENANT_ID="your-tenant-id"
    export ENTRA_CLIENT_ID="your-client-id"
    export ENTRA_CLIENT_SECRET="your-client-secret"
    ```

## Environment Variables

| Variable | Description |
| :--- | :--- |
| ENTRA_TENANT_ID | Your Azure AD (Entra) tenant ID |
| ENTRA_CLIENT_ID | The client (application) ID for your app registration |
| ENTRA_CLIENT_SECRET | The client secret associated with the app registration |

## Prerequisites

To perform an audit, you must configure an app registration with specific Microsoft Graph API permissions.

*   Register an application in the Azure portal.
*   Assign the following Microsoft Graph **Application** permissions:
    *   `Application.Read.All`
    *   `Directory.Read.All`
    *   `AuditLog.Read.All`
*   Grant Admin Consent for these permissions.

## Security Checks

The Entra ID scanner performs 15 checks focused on application and credential governance.

| Category | Count | Examples |
| :--- | :--- | :--- |
| OAuth Permissions | 8 | Mail.ReadWrite, Mail.Send, Directory.ReadWrite.All |
| Credential Hygiene | 2 | Expired credentials, password credentials |
| OAuth Governance | 1 | Tenant-wide admin consent grants |
| Application Registration | 1 | Multi-tenant app registrations |
| Application Governance | 1 | App registrations without owners |
| Access Control | 1 | Service principals not requiring user assignment |
| Asset Hygiene | 1 | Disabled service principals |
