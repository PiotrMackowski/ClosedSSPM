#!/usr/bin/env python3
"""
ServiceNow API Key Authentication Setup

Automates the configuration of API key authentication on a ServiceNow instance
so that ClosedSSPM can audit using the x-sn-apikey header.

Steps performed:
  1. Verify the API Key plugin (com.glide.tokenbased_auth) is active
  2. Activate the Table GET API Access Policy
  3. Create an API Key authentication profile
  4. Link the auth profile to the access policy
  5. Create an API key for the specified user

Usage:
  python setup_apikey_auth.py \\
    --instance https://mycompany.service-now.com \
    --username admin \\
    --password 'secret'

Requirements:
  pip install requests
"""

import argparse
import sys
from datetime import datetime, timedelta, timezone

try:
    import requests
except ImportError:
    print("Error: 'requests' package is required. Install with: pip install requests", file=sys.stderr)
    sys.exit(1)

# ServiceNow table/field constants
PLUGIN_ID = "com.glide.tokenbased_auth"
TABLE_GET_POLICY_NAME = "Table GET API Access Policy"
AUTH_PARAM_NAME = "x-sn-apikey"
AUTH_PARAM_TYPE = "auth_header"
AUTH_PROFILE_NAME = "ClosedSSPM API Key Auth"
DEFAULT_KEY_NAME = "ClosedSSPM Audit Key"


class ServiceNowClient:
    """Thin wrapper around the ServiceNow Table REST API."""

    def __init__(self, instance: str, username: str, password: str):
        self.base_url = instance.rstrip("/")
        self.auth = (username, password)
        self.session = requests.Session()
        self.session.auth = self.auth
        self.session.headers.update({
            "Accept": "application/json",
            "Content-Type": "application/json",
        })

    def get(self, table: str, query: str = "", fields: str = "", limit: int = 10) -> list:
        params = {"sysparm_limit": limit}
        if query:
            params["sysparm_query"] = query
        if fields:
            params["sysparm_fields"] = fields
        resp = self.session.get(f"{self.base_url}/api/now/table/{table}", params=params)
        resp.raise_for_status()
        return resp.json().get("result", [])

    def get_one(self, table: str, sys_id: str, fields: str = "") -> dict:
        params = {}
        if fields:
            params["sysparm_fields"] = fields
        resp = self.session.get(f"{self.base_url}/api/now/table/{table}/{sys_id}", params=params)
        resp.raise_for_status()
        return resp.json().get("result", {})

    def create(self, table: str, data: dict) -> dict:
        resp = self.session.post(f"{self.base_url}/api/now/table/{table}", json=data)
        resp.raise_for_status()
        return resp.json().get("result", {})

    def update(self, table: str, sys_id: str, data: dict) -> dict:
        resp = self.session.patch(f"{self.base_url}/api/now/table/{table}/{sys_id}", json=data)
        resp.raise_for_status()
        return resp.json().get("result", {})


def step(num: int, msg: str):
    print(f"\n{'='*60}")
    print(f"  Step {num}: {msg}")
    print(f"{'='*60}")


def ok(msg: str):
    print(f"  [OK] {msg}")


def warn(msg: str):
    print(f"  [!!] {msg}")


def fail(msg: str):
    print(f"  [FAIL] {msg}", file=sys.stderr)
    sys.exit(1)


def verify_plugin(client: ServiceNowClient):
    """Step 1: Verify the API Key and HMAC Authentication plugin is active."""
    step(1, "Verify API Key plugin is active")

    try:
        results = client.get(
            "sys_plugins",
            query=f"id={PLUGIN_ID}",
            fields="id,name,active",
        )
    except requests.exceptions.HTTPError as e:
        if e.response is not None and e.response.status_code == 403:
            warn("Cannot query sys_plugins (403). Assuming plugin is active — proceeding.")
            return
        raise

    if not results:
        fail(
            f"Plugin '{PLUGIN_ID}' not found. "
            "Activate it via System Definition > Plugins in the ServiceNow UI."
        )

    plugin = results[0]
    if plugin.get("active") != "active":
        fail(
            f"Plugin '{PLUGIN_ID}' is installed but not active (status: {plugin.get('active')}). "
            "Activate it via System Definition > Plugins."
        )

    ok(f"Plugin '{plugin.get('name', PLUGIN_ID)}' is active")


def activate_policy(client: ServiceNowClient) -> str:
    """Step 2: Find and activate the Table GET API Access Policy. Returns sys_id."""
    step(2, "Activate Table GET API Access Policy")

    results = client.get(
        "sys_api_access_policy",
        query=f"name={TABLE_GET_POLICY_NAME}",
        fields="sys_id,name,active,apply_all_tables",
    )

    if not results:
        fail(
            f"Policy '{TABLE_GET_POLICY_NAME}' not found. "
            "This policy is shipped with ServiceNow — check your instance version."
        )

    policy = results[0]
    sys_id = policy["sys_id"]

    if policy.get("active") == "true" and policy.get("apply_all_tables") == "true":
        ok(f"Policy already active with apply_all_tables=true (sys_id: {sys_id})")
        return sys_id

    updated = client.update("sys_api_access_policy", sys_id, {
        "active": "true",
        "apply_all_tables": "true",
    })

    ok(f"Policy activated: active={updated.get('active')}, apply_all_tables={updated.get('apply_all_tables')}")
    return sys_id


def find_auth_parameter(client: ServiceNowClient) -> str:
    """Find the x-sn-apikey auth header parameter. Returns sys_id."""
    results = client.get(
        "sys_token_auth_parameter",
        query=f"parameter_name={AUTH_PARAM_NAME}^type={AUTH_PARAM_TYPE}",
        fields="sys_id,parameter_name,type",
    )

    if not results:
        fail(
            f"Auth parameter '{AUTH_PARAM_NAME}' (type={AUTH_PARAM_TYPE}) not found. "
            "The API Key plugin may not be properly activated."
        )

    return results[0]["sys_id"]


def create_auth_profile(client: ServiceNowClient, auth_param_id: str) -> str:
    """Step 3: Create or find the API Key auth profile. Returns sys_id."""
    step(3, "Create API Key authentication profile")

    # Check if profile already exists
    results = client.get(
        "http_key_auth",
        query=f"name={AUTH_PROFILE_NAME}",
        fields="sys_id,name,active",
    )

    if results:
        sys_id = results[0]["sys_id"]
        ok(f"Profile '{AUTH_PROFILE_NAME}' already exists (sys_id: {sys_id})")
        return sys_id

    # Find the auth parameter
    ok(f"Found auth parameter for '{AUTH_PARAM_NAME}' (sys_id: {auth_param_id})")

    # Create the profile
    profile = client.create("http_key_auth", {
        "name": AUTH_PROFILE_NAME,
        "auth_parameter": auth_param_id,
        "active": "true",
        "sys_class_name": "http_key_auth",
    })

    sys_id = profile["sys_id"]
    ok(f"Created auth profile '{AUTH_PROFILE_NAME}' (sys_id: {sys_id})")
    return sys_id


def link_profile_to_policy(client: ServiceNowClient, policy_id: str, profile_id: str):
    """Step 4: Link the auth profile to the access policy (if not already linked)."""
    step(4, "Link auth profile to access policy")

    # Check for existing mapping
    results = client.get(
        "sys_auth_profile_mapping",
        query=f"api_access_policy={policy_id}^inbound_auth_profile={profile_id}",
        fields="sys_id",
    )

    if results:
        ok(f"Mapping already exists (sys_id: {results[0]['sys_id']})")
        return

    mapping = client.create("sys_auth_profile_mapping", {
        "api_access_policy": policy_id,
        "inbound_auth_profile": profile_id,
    })

    ok(f"Created mapping (sys_id: {mapping['sys_id']})")


def find_user(client: ServiceNowClient, username: str) -> str:
    """Find a user by username. Returns sys_id."""
    results = client.get(
        "sys_user",
        query=f"user_name={username}",
        fields="sys_id,user_name",
    )

    if not results:
        fail(f"User '{username}' not found")

    return results[0]["sys_id"]


def create_api_key(client: ServiceNowClient, key_name: str, user_id: str, expires: str) -> dict:
    """Step 5: Create an API key. Returns the full response including the token."""
    step(5, "Create API key")

    # Check for existing key with same name
    results = client.get(
        "api_key",
        query=f"name={key_name}",
        fields="sys_id,name,active,expires",
    )

    if results:
        existing = results[0]
        warn(f"Key '{key_name}' already exists (sys_id: {existing['sys_id']}, expires: {existing.get('expires', 'N/A')})")
        warn("The token value cannot be retrieved after creation.")
        warn("If you need a new token, use a different --key-name or delete the existing key first.")

        # Extend expiry if requested
        client.update("api_key", existing["sys_id"], {"expires": expires, "active": "true"})
        ok(f"Updated expiry to {expires}")
        return existing

    key = client.create("api_key", {
        "name": key_name,
        "user": user_id,
        "active": "true",
        "expires": expires,
    })

    ok(f"Created API key '{key_name}' (sys_id: {key['sys_id']}, expires: {expires})")
    return key


def main():
    parser = argparse.ArgumentParser(
        description="Set up ServiceNow API Key authentication for ClosedSSPM",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s --instance https://mycompany.service-now.com --username admin --password secret

  %(prog)s --instance https://mycompany.service-now.com --username admin --password secret \
    --key-name "CI Audit Key" --key-user svc_audit --key-expires "2027-06-01 00:00:00"
""",
    )
    parser.add_argument("--instance", required=True, help="ServiceNow instance URL")
    parser.add_argument("--username", required=True, help="Admin username for setup (basic auth)")
    parser.add_argument("--password", required=True, help="Admin password for setup (basic auth)")
    parser.add_argument("--key-name", default=DEFAULT_KEY_NAME, help=f"Name for the API key (default: {DEFAULT_KEY_NAME})")
    parser.add_argument("--key-user", default=None, help="Username to associate the key with (default: same as --username)")
    parser.add_argument("--key-expires", default=None, help="Key expiry datetime, UTC (default: 1 year from now)")

    args = parser.parse_args()

    key_user = args.key_user or args.username
    if args.key_expires:
        key_expires = args.key_expires
    else:
        key_expires = (datetime.now(timezone.utc) + timedelta(days=365)).strftime("%Y-%m-%d %H:%M:%S")

    print(f"ServiceNow API Key Auth Setup")
    print(f"Instance:  {args.instance}")
    print(f"Key user:  {key_user}")
    print(f"Key name:  {args.key_name}")
    print(f"Expires:   {key_expires}")

    client = ServiceNowClient(args.instance, args.username, args.password)

    # Step 1: Verify plugin
    verify_plugin(client)

    # Step 2: Activate policy
    policy_id = activate_policy(client)

    # Step 3: Create auth profile
    auth_param_id = find_auth_parameter(client)
    profile_id = create_auth_profile(client, auth_param_id)

    # Step 4: Link profile to policy
    link_profile_to_policy(client, policy_id, profile_id)

    # Step 5: Create API key
    user_id = find_user(client, key_user)
    key = create_api_key(client, args.key_name, user_id, key_expires)

    # Summary
    print(f"\n{'='*60}")
    print(f"  Setup Complete")
    print(f"{'='*60}")

    token = key.get("token", "")
    if token and not token.startswith("\ufdd"):
        # Token is available (only on first creation)
        print(f"\n  API Key Token (save this — it won't be shown again):\n")
        print(f"    {token}\n")
        print(f"  Use with ClosedSSPM:\n")
        print(f"    export SNOW_INSTANCE={args.instance}")
        print(f"    export SNOW_API_KEY='{token}'")
        print(f"    closedsspm audit --output report.html\n")
    else:
        print(f"\n  Key '{args.key_name}' is configured (expiry updated to {key_expires}).")
        print(f"  The token value is only available at creation time.")
        print(f"  If you need a new token, delete the existing key and rerun this script.\n")
        print(f"  Use with ClosedSSPM:\n")
        print(f"    export SNOW_INSTANCE={args.instance}")
        print(f"    export SNOW_API_KEY='<your-api-key-token>'")
        print(f"    closedsspm audit --output report.html\n")

    # Test the connection (if token available)
    if token and not token.startswith("\ufdd"):
        print("  Testing API key authentication...")
        try:
            test_resp = requests.get(
                f"{args.instance.rstrip('/')}/api/now/table/sys_user",
                headers={"Accept": "application/json", "x-sn-apikey": token},
                params={"sysparm_limit": "1", "sysparm_fields": "user_name"},
            )
            if test_resp.status_code == 200:
                ok("API key authentication works!")
            else:
                warn(f"API key test returned HTTP {test_resp.status_code}. Check the configuration.")
        except Exception as e:
            warn(f"API key test failed: {e}")


if __name__ == "__main__":
    main()
