# ServiceNow API Key Authentication Setup

This guide walks through configuring API Key authentication on a ServiceNow instance so that ClosedSSPM can audit it using the `x-sn-apikey` header instead of basic auth.

All steps use the ServiceNow Table REST API with basic auth (admin credentials). Once configured, you can switch to API key auth for all subsequent ClosedSSPM operations.

> **Automated setup**: A Python script (`docs/setup_apikey_auth.py`) automates all of these steps. See [Automated Setup](#automated-setup) at the bottom.

## Prerequisites

- ServiceNow instance with admin access
- The **API Key and HMAC Authentication** plugin (`com.glide.tokenbased_auth`) must be active
- `curl` (or the Python script) available on your machine

### Set your instance URL

All commands below use `$SNOW_INSTANCE`. Set it once:

```bash
export SNOW_INSTANCE=https://mycompany.service-now.com
```
### Verify the plugin is active

```bash
curl -s -u 'admin:PASSWORD' \
  -H 'Accept: application/json' \
  "$SNOW_INSTANCE/api/now/table/sys_plugins?sysparm_query=id=com.glide.tokenbased_auth&sysparm_fields=id,name,active" \
  | python3 -m json.tool
```

You should see `"active": "active"`. If not, activate it via **System Definition > Plugins** in the ServiceNow UI.

---

## Step 1: Activate the Table GET API Access Policy

ServiceNow ships with a built-in "Table GET API Access Policy" that governs GET requests to `/api/now/table/{tableName}`. By default it is **inactive**. Activating it with `apply_all_tables=true` allows API key auth for all table reads.

### Find the policy

```bash
curl -s -u 'admin:PASSWORD' \
  -H 'Accept: application/json' \
  "$SNOW_INSTANCE/api/now/table/sys_api_access_policy?sysparm_query=name=Table%20GET%20API%20Access%20Policy&sysparm_fields=sys_id,name,active,apply_all_tables" \
  | python3 -m json.tool
```

Note the `sys_id` from the response (e.g. `010e53d3671210101e2becccb585efb4`).

### Activate it

```bash
curl -s -u 'admin:PASSWORD' -X PATCH \
  -H 'Content-Type: application/json' \
  -H 'Accept: application/json' \
  -d '{"active": "true", "apply_all_tables": "true"}' \
  "$SNOW_INSTANCE/api/now/table/sys_api_access_policy/POLICY_SYS_ID" \
  | python3 -m json.tool
```

Confirm: `"active": "true"` and `"apply_all_tables": "true"` in the response.

---

## Step 2: Create an API Key Authentication Profile

An authentication profile tells ServiceNow which header/parameter carries the API key. ClosedSSPM uses the `x-sn-apikey` HTTP header, which is ServiceNow's default API key header.

### Find the auth parameter for `x-sn-apikey` (Auth Header type)

```bash
curl -s -u 'admin:PASSWORD' \
  -H 'Accept: application/json' \
  "$SNOW_INSTANCE/api/now/table/sys_token_auth_parameter?sysparm_query=parameter_name=x-sn-apikey^type=auth_header&sysparm_fields=sys_id,parameter_name,type" \
  | python3 -m json.tool
```

Note the `sys_id` (e.g. `2af926dca3303110f96f5f87f31e6155`).

### Create the auth profile

```bash
curl -s -u 'admin:PASSWORD' -X POST \
  -H 'Content-Type: application/json' \
  -H 'Accept: application/json' \
  -d '{
    "name": "ClosedSSPM API Key Auth",
    "auth_parameter": "AUTH_PARAMETER_SYS_ID",
    "active": "true",
    "sys_class_name": "http_key_auth"
  }' \
  "$SNOW_INSTANCE/api/now/table/http_key_auth" \
  | python3 -m json.tool
```

Note the `sys_id` of the created profile from the response.

---

## Step 3: Link the Auth Profile to the Access Policy

The profile must be mapped to the Table GET Access Policy so that incoming requests with the `x-sn-apikey` header are recognized.

```bash
curl -s -u 'admin:PASSWORD' -X POST \
  -H 'Content-Type: application/json' \
  -H 'Accept: application/json' \
  -d '{
    "api_access_policy": "POLICY_SYS_ID",
    "inbound_auth_profile": "AUTH_PROFILE_SYS_ID"
  }' \
  "$SNOW_INSTANCE/api/now/table/sys_auth_profile_mapping" \
  | python3 -m json.tool
```

---

## Step 4: Create an API Key

API keys are stored in the `api_key` table. Each key is associated with a user and has an expiration date.

### Find the admin user sys_id

```bash
curl -s -u 'admin:PASSWORD' \
  -H 'Accept: application/json' \
  "$SNOW_INSTANCE/api/now/table/sys_user?sysparm_query=user_name=admin&sysparm_fields=sys_id,user_name" \
  | python3 -m json.tool
```

### Create the key

```bash
curl -s -u 'admin:PASSWORD' -X POST \
  -H 'Content-Type: application/json' \
  -H 'Accept: application/json' \
  -d '{
    "name": "ClosedSSPM Audit Key",
    "user": "USER_SYS_ID",
    "active": "true",
    "expires": "2027-01-01 00:00:00"
  }' \
  "$SNOW_INSTANCE/api/now/table/api_key" \
  | python3 -m json.tool
```

> **Important**: The API key value (the `token` field) is only returned once at creation time. Copy it immediately — ServiceNow stores only the hash afterward.

If you already have a key that is expired, you can extend it:

```bash
curl -s -u 'admin:PASSWORD' -X PATCH \
  -H 'Content-Type: application/json' \
  -H 'Accept: application/json' \
  -d '{"expires": "2027-01-01 00:00:00"}' \
  "$SNOW_INSTANCE/api/now/table/api_key/KEY_SYS_ID" \
  | python3 -m json.tool
```

---

## Step 5: Test the API Key

```bash
curl -s -w "\nHTTP %{http_code}\n" \
  -H 'Accept: application/json' \
  -H 'x-sn-apikey: YOUR_API_KEY_TOKEN' \
  "$SNOW_INSTANCE/api/now/table/sys_user?sysparm_limit=1&sysparm_fields=user_name"
```

Expected: HTTP 200 with a JSON response containing a user record.

---

## Step 6: Run ClosedSSPM with API Key Auth

```bash
# SNOW_INSTANCE should already be set from the Prerequisites section
export SNOW_API_KEY=YOUR_API_KEY_TOKEN

closedsspm audit --output report.html
```

Authentication method is auto-detected: when `SNOW_API_KEY` is set, ClosedSSPM sends the `x-sn-apikey` header on every request.

---

## Reference: ServiceNow Tables Used

| Table | Purpose |
|-------|---------|
| `sys_plugins` | Verify plugin activation status |
| `sys_api_access_policy` | API access policies (controls which auth methods are accepted) |
| `sys_token_auth_parameter` | Defines accepted auth parameters (header names, query params) |
| `http_key_auth` | API Key authentication profiles (subclass of `inbound_auth_profile`) |
| `sys_auth_profile_mapping` | Links auth profiles to access policies |
| `api_key` | REST API keys (token, user, expiry) |
| `sys_user` | User records (needed to get user `sys_id` for key creation) |

---

## Automated Setup

The `docs/setup_apikey_auth.py` script automates all of the above steps.

### Usage

```bash
# Install dependency (only uses the Python standard library + requests)
pip install requests

# Run the setup
python docs/setup_apikey_auth.py \
  --instance $SNOW_INSTANCE \
  --username admin \
  --password 'YOUR_PASSWORD'

# Optional: specify a custom key name, user, or expiry
python docs/setup_apikey_auth.py \
  --instance $SNOW_INSTANCE \
  --username admin \
  --password 'YOUR_PASSWORD' \
  --key-name "CI Audit Key" \
  --key-user svc_audit \
  --key-expires "2027-06-01 00:00:00"
```

The script will:
1. Verify the API Key plugin is active
2. Find and activate the Table GET API Access Policy
3. Find the `x-sn-apikey` auth header parameter
4. Create an API Key auth profile (or find an existing one)
5. Link the auth profile to the access policy (if not already linked)
6. Create an API key for the specified user
7. Print the API key token and a ready-to-use export command

### Idempotent

The script is safe to run multiple times. It checks for existing resources before creating new ones.
