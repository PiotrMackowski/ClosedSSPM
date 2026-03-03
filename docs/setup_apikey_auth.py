#!/usr/bin/env python3
"""
ServiceNow API Key Auth Setup for ClosedSSPM.

Configures x-sn-apikey header authentication so ClosedSSPM can audit
without basic auth. Idempotent — safe to run repeatedly.

Required env vars:
    SNOW_INSTANCE   https://mycompany.service-now.com
    SNOW_USERNAME   admin account for setup
    SNOW_PASSWORD   admin password

Requires: pip install requests
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
    except SystemExit:
        # Some instances restrict sys_plugins — assume active
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
    registered in sys_token_auth_parameter."""
    heading(3, "Create auth profile")

    # The plugin pre-registers this parameter — we just need its sys_id
    param = find_one(c, "sys_token_auth_parameter",
                     f"parameter_name={AUTH_PARAM[0]}^type={AUTH_PARAM[1]}",
                     "sys_id", f"auth param {AUTH_PARAM[0]}")

    profile, _ = find_or_create(
        c, "http_key_auth", f"name={PROFILE_NAME}", "sys_id,name",
        {"name": PROFILE_NAME, "auth_parameter": param["sys_id"],
         "active": "true", "sys_class_name": "http_key_auth"},
        PROFILE_NAME,
    )
    return profile["sys_id"]


def link_profile(c: Snow, policy_id: str, profile_id: str):
    """The mapping tells the access policy to accept our auth profile.
    WARNING: once a policy has *any* mapping, only those mapped auth
    methods work — everything else is rejected."""
    heading(4, "Link profile → policy")
    find_or_create(
        c, "sys_auth_profile_mapping",
        f"api_access_policy={policy_id}^inbound_auth_profile={profile_id}", "sys_id",
        {"api_access_policy": policy_id, "inbound_auth_profile": profile_id},
        "profile ↔ policy mapping",
    )


def create_key(c: Snow, username: str) -> dict:
    """Create an API key bound to the given user. The token value is only
    returned once — ServiceNow stores only the hash afterward."""
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
    print(f"  created: {KEY_NAME} (expires {expires})")
    token = key.get("token", "")
    if token:
        print(f"\n  ┌─ SAVE THIS — shown only once ──────────────────────────")
        print(f"  │ export SNOW_API_KEY='{token}'")
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
    link_profile(c, policy_id, profile_id)
    create_key(c, username)

    print(f"\nDone. Run ClosedSSPM:")
    print(f"  export SNOW_INSTANCE={instance}")
    print(f"  export SNOW_API_KEY='<token>'")
    print(f"  closedsspm audit --output report.html")


if __name__ == "__main__":
    main()
