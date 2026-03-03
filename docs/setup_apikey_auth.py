#!/usr/bin/env python3
"""
ServiceNow API Key Auth Setup for ClosedSSPM.

Configures x-sn-apikey header authentication so ClosedSSPM can audit
without basic auth. Both basic and API key auth work after setup.
Idempotent — safe to run repeatedly.

Required env vars:
    SNOW_INSTANCE   https://mycompany.service-now.com
    SNOW_USERNAME   admin account for setup
    SNOW_PASSWORD   admin password

Requires: pip install requests

IMPORTANT: After running, open the API key record in the browser to copy
the token — the REST API returns an encrypted blob, not the usable
`now_...` token. The script prints the URL to visit.
"""

import os
import sys
from datetime import datetime, timedelta, timezone

try:
    import requests
except ImportError:
    sys.exit("pip install requests")

# ---------------------------------------------------------------------------
# Config — ServiceNow table names and well-known values
# ---------------------------------------------------------------------------

# Plugin that ships the x-sn-apikey header support
PLUGIN = "com.glide.tokenbased_auth"

# Built-in policy that gates GET /api/now/table/*
# Must be active with apply_all_tables=true for API key reads to work
POLICY_NAME = "Table GET API Access Policy"

# The header parameter the plugin registers for API key auth
AUTH_PARAM = ("x-sn-apikey", "auth_header")

# Built-in basic auth profile — must also be mapped to the policy so
# adding the API key profile doesn't lock out basic auth
BASIC_AUTH_NAME = "BasicAuth for none public processors"

# What we create
PROFILE_NAME = "ClosedSSPM API Key Auth"
KEY_NAME = "ClosedSSPM Audit Key"
KEY_EXPIRY_DAYS = 365

# ---------------------------------------------------------------------------
# ServiceNow REST client — thin wrapper, one method per HTTP verb
# ---------------------------------------------------------------------------

class Snow:
    def __init__(self, base: str, user: str, pwd: str):
        self.base = base.rstrip("/")
        self.s = requests.Session()
        self.s.auth = (user, pwd)
        self.s.headers.update({"Accept": "application/json", "Content-Type": "application/json"})

    def _url(self, table: str, sys_id: str = "") -> str:
        return f"{self.base}/api/now/table/{table}" + (f"/{sys_id}" if sys_id else "")

    def get(self, table: str, query: str = "", fields: str = "") -> list:
        r = self.s.get(self._url(table), params={
            "sysparm_query": query, "sysparm_fields": fields, "sysparm_limit": 10,
        })
        r.raise_for_status()
        return r.json().get("result", [])

    def create(self, table: str, data: dict) -> dict:
        r = self.s.post(self._url(table), json=data)
        r.raise_for_status()
        return r.json().get("result", {})

    def update(self, table: str, sys_id: str, data: dict) -> dict:
        r = self.s.patch(self._url(table, sys_id), json=data)
        r.raise_for_status()
        return r.json().get("result", {})

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def env(name: str) -> str:
    """Read required env var or die."""
    val = os.environ.get(name, "").strip()
    if not val:
        sys.exit(f"Missing env var: {name}")
    return val

def find_one(client: Snow, table: str, query: str, fields: str, label: str) -> dict:
    """Query a table expecting exactly one result. Exits on miss."""
    rows = client.get(table, query, fields)
    if not rows:
        sys.exit(f"Not found: {label}")
    return rows[0]

def find_or_create(client: Snow, table: str, query: str, fields: str, data: dict, label: str) -> tuple[dict, bool]:
    """Return (record, created). Creates only if missing."""
    rows = client.get(table, query, fields)
    if rows:
        print(f"  exists: {label} ({rows[0]['sys_id']})")
        return rows[0], False
    rec = client.create(table, data)
    print(f"  created: {label} ({rec['sys_id']})")
    return rec, True

def heading(n: int, msg: str):
    print(f"\n[{n}] {msg}")

# ---------------------------------------------------------------------------
# Steps — each one is idempotent
# ---------------------------------------------------------------------------

def verify_plugin(c: Snow):
    """The tokenbased_auth plugin must be active — it registers the
    x-sn-apikey header parameter and the api_key table."""
    heading(1, "Verify API Key plugin")
    try:
        p = find_one(c, "sys_plugins", f"id={PLUGIN}", "id,name,active", PLUGIN)
    except (SystemExit, requests.HTTPError):
        # Some instances restrict sys_plugins (403) — assume active
        print("  (sys_plugins not queryable, assuming active)")
        return
    if p.get("active") != "active":
        sys.exit(f"Plugin {PLUGIN} is installed but inactive. Activate via System Definition > Plugins.")
    print(f"  active: {p.get('name', PLUGIN)}")


def activate_policy(c: Snow) -> str:
    """The Table GET policy controls which auth methods are accepted on
    GET /api/now/table/*. It ships inactive — we need it active with
    apply_all_tables=true so API key auth works on every table."""
    heading(2, "Activate Table GET Access Policy")
    pol = find_one(c, "sys_api_access_policy", f"name={POLICY_NAME}",
                   "sys_id,active,apply_all_tables", POLICY_NAME)
    sid = pol["sys_id"]
    if pol.get("active") == "true" and pol.get("apply_all_tables") == "true":
        print(f"  already active ({sid})")
        return sid
    c.update("sys_api_access_policy", sid, {"active": "true", "apply_all_tables": "true"})
    print(f"  activated ({sid})")
    return sid


def create_auth_profile(c: Snow) -> str:
    """An auth profile tells ServiceNow which header carries the key.
    We point it at the x-sn-apikey auth_header parameter that the plugin
    registered in sys_token_auth_parameter.

    auth_processor=true scopes the profile to specific processors only,
    preventing it from globally blocking basic auth on all endpoints."""
    heading(3, "Create auth profile")

    # The plugin pre-registers this parameter — we just need its sys_id
    param = find_one(c, "sys_token_auth_parameter",
                     f"parameter_name={AUTH_PARAM[0]}^type={AUTH_PARAM[1]}",
                     "sys_id", f"auth param {AUTH_PARAM[0]}")

    profile, created = find_or_create(
        c, "http_key_auth", f"name={PROFILE_NAME}", "sys_id,name,auth_processor",
        {"name": PROFILE_NAME, "auth_parameter": param["sys_id"],
         "active": "true", "auth_processor": "true",
         "sys_class_name": "http_key_auth"},
        PROFILE_NAME,
    )

    # Ensure auth_processor=true even on existing profiles
    if not created and profile.get("auth_processor") != "true":
        c.update("http_key_auth", profile["sys_id"], {"auth_processor": "true"})
        print(f"  fixed: set auth_processor=true")

    return profile["sys_id"]


def link_profiles(c: Snow, policy_id: str, apikey_profile_id: str):
    """Map BOTH the API key profile AND basic auth profile to the policy.

    CRITICAL: once an access policy has *any* auth profile mapping, ONLY
    those mapped methods are accepted — unmapped methods get 401. So we
    must explicitly map basic auth too, or it gets locked out."""
    heading(4, "Link auth profiles → policy")

    # Map API key profile
    find_or_create(
        c, "sys_auth_profile_mapping",
        f"api_access_policy={policy_id}^inbound_auth_profile={apikey_profile_id}", "sys_id",
        {"api_access_policy": policy_id, "inbound_auth_profile": apikey_profile_id},
        "API key ↔ policy mapping",
    )

    # Map basic auth profile — find by name with trailing space (ServiceNow default)
    basic_profiles = c.get("std_http_auth", f"nameLIKE{BASIC_AUTH_NAME}", "sys_id,name")
    if not basic_profiles:
        print("  WARNING: basic auth profile not found — basic auth may be locked out!")
        print(f"  Looked for: {BASIC_AUTH_NAME}")
        return

    basic_id = basic_profiles[0]["sys_id"]
    find_or_create(
        c, "sys_auth_profile_mapping",
        f"api_access_policy={policy_id}^inbound_auth_profile={basic_id}", "sys_id",
        {"api_access_policy": policy_id, "inbound_auth_profile": basic_id},
        "basic auth ↔ policy mapping",
    )


def create_key(c: Snow, username: str) -> dict:
    """Create an API key bound to the given user.

    NOTE: The REST API returns an encrypted token blob, not the usable
    `now_...` value. You MUST open the key record in the browser to copy
    the real token — it's shown only at creation time."""
    heading(5, "Create API key")
    expires = (datetime.now(timezone.utc) + timedelta(days=KEY_EXPIRY_DAYS)).strftime("%Y-%m-%d %H:%M:%S")

    user = find_one(c, "sys_user", f"user_name={username}", "sys_id", f"user {username}")

    # Check if key already exists — if so, just extend expiry
    existing = c.get("api_key", f"name={KEY_NAME}", "sys_id,name,active,expires")
    if existing:
        c.update("api_key", existing[0]["sys_id"], {"expires": expires, "active": "true"})
        print(f"  exists: {KEY_NAME} — extended to {expires}")
        print("  (token only available at creation; delete + rerun if you need a new one)")
        return existing[0]

    key = c.create("api_key", {
        "name": KEY_NAME, "user": user["sys_id"], "active": "true", "expires": expires,
    })
    key_id = key.get("sys_id", "")
    print(f"  created: {KEY_NAME} (expires {expires})")
    print(f"\n  ┌─ COPY TOKEN FROM BROWSER ─────────────────────────────")
    print(f"  │ The REST API returns an encrypted token.")
    print(f"  │ Open this URL to copy the real now_... token:")
    print(f"  │")
    print(f"  │   {c.base}/nav_to.do?uri=api_key.do?sys_id={key_id}")
    print(f"  │")
    print(f"  │ Then: export SNOW_API_KEY='now_...'")
    print(f"  └────────────────────────────────────────────────────────")
    return key

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    instance = env("SNOW_INSTANCE")
    username = env("SNOW_USERNAME")
    password = env("SNOW_PASSWORD")

    print(f"ServiceNow API Key Setup — {instance}")
    c = Snow(instance, username, password)

    verify_plugin(c)
    policy_id = activate_policy(c)
    profile_id = create_auth_profile(c)
    link_profiles(c, policy_id, profile_id)
    create_key(c, username)

    print(f"\nDone. Both basic auth and API key auth are now enabled.")
    print(f"  export SNOW_INSTANCE={instance}")
    print(f"  export SNOW_API_KEY='<token from browser>'")
    print(f"  closedsspm audit --output report.html")


if __name__ == "__main__":
    main()
