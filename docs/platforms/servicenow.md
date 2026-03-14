# ServiceNow

ClosedSSPM supports auditing ServiceNow instances for security misconfigurations, insecure script usage, and identity risks. The scanner identifies platform-level vulnerabilities and static analysis issues in custom scripts.

## Authentication

ServiceNow supports multiple authentication methods. Configure your environment using one of the following tabs.

=== "Basic Auth"
    Standard username and password authentication.

    ```bash
    export SNOW_INSTANCE=https://mycompany.service-now.com
    export SNOW_USERNAME="audit-user"
    export SNOW_PASSWORD="your-password"
    ```

=== "OAuth (Client Credentials)"
    Service-to-service authentication using OAuth 2.0.

    ```bash
    export SNOW_INSTANCE=https://mycompany.service-now.com
    export SNOW_CLIENT_ID="your-client-id"
    export SNOW_CLIENT_SECRET="your-client-secret"
    ```

=== "Key Pair (JWT Bearer)"
    JWT-based authentication using a private key and key ID.

    ```bash
    export SNOW_INSTANCE=https://mycompany.service-now.com
    export SNOW_CLIENT_ID=your_client_id
    export SNOW_CLIENT_SECRET=your_client_secret
    export SNOW_PRIVATE_KEY_PATH=/path/to/private-key.pem
    export SNOW_KEY_ID=your_key_id
    export SNOW_JWT_USER=svc_audit_user
    ```

=== "API Key"
    Token-based authentication for specific integrations.

    ```bash
    export SNOW_INSTANCE=https://mycompany.service-now.com
    export SNOW_API_KEY="your-api-key"
    ```

    Refer to `docs/setup_apikey_auth.py` for instructions on setting up API key authentication in your instance.

### Auth Priority

The scanner attempts to detect authentication credentials in the following order:

| Priority | Method | Required Variables |
| :--- | :--- | :--- |
| 1 | API Key | SNOW_API_KEY |
| 2 | Key Pair (JWT Bearer) | `SNOW_CLIENT_ID` + `SNOW_CLIENT_SECRET` + `SNOW_PRIVATE_KEY_PATH` |
| 3 | OAuth | SNOW_CLIENT_ID, SNOW_CLIENT_SECRET |
| 4 | Basic Auth | SNOW_USERNAME, SNOW_PASSWORD |

## Environment Variables

| Variable | Description |
| :--- | :--- |
| `SNOW_INSTANCE` | ServiceNow instance URL (e.g., `https://mycompany.service-now.com`) |
| SNOW_USERNAME | Username for basic authentication |
| SNOW_PASSWORD | Password for basic authentication |
| SNOW_CLIENT_ID | OAuth client ID |
| SNOW_CLIENT_SECRET | OAuth client secret |
| `SNOW_PRIVATE_KEY_PATH` | Path to RSA private key PEM file |
| `SNOW_KEY_ID` | Key ID from ServiceNow JWT Verifier Map |
| `SNOW_JWT_USER` | ServiceNow username for JWT `sub` claim (cannot be admin) |
| `SNOW_API_KEY` | API key token (from REST API Key table) |

## Security Checks

ServiceNow audits include 86 unique checks across several categories.

| Category | Count | Examples |
| :--- | :--- | :--- |
| ACL | 9 | Unprotected ACLs, wildcard roles, public access, deny-unless audit |
| Roles | 10 | Admin role assignments, elevated privileges, role includes, security_admin, impersonator, oauth_admin |
| Scripts | 6 | eval() usage, client-callable script includes, global UI scripts |
| Integrations | 7 | Unauthenticated endpoints, basic auth, unvalidated MID servers |
| Instance Config | 32 | HTTPS enforcement, session timeout, password policy, CSRF, XSS prevention, TLS, sandbox, SAML signing, SSO bypass |
| Users | 5 | Never-logged-in accounts, locked-out active users, service account hygiene |
| SAST | 17 | Hardcoded credentials, eval(), GlideEvaluator, insecure HTTP, query injection, XSS sinks, workflow bypass |

## Prerequisites

The authentication user requires the following roles to perform a full audit:

* itil
* security_admin
