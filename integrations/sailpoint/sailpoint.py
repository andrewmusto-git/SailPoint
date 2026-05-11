#!/usr/bin/env python3
"""
SailPoint Identity Security Cloud → Veza OAA Integration Script

Collects identity, role, and access-profile data from SailPoint ISC (v3 API)
and pushes it into Veza's Access Graph via the Open Authorization API (OAA).

Entity model:
  SailPoint Identity      → OAA Local User
  SailPoint Role          → OAA Local Role
  SailPoint Access Profile → OAA Application Resource
  Identity-Role assignment → user.add_role()
  Role-Access Profile link → resource.add_permission("member", local_roles=[...])
  Access Profile owner     → resource.add_permission("owner", identities=[...])
"""

import argparse
import json
import logging
import os
import sys
from datetime import datetime
from logging.handlers import TimedRotatingFileHandler

import requests
from dotenv import load_dotenv
from oaaclient.client import OAAClient, OAAClientError
from oaaclient.templates import CustomApplication, OAAPermission

log = logging.getLogger(__name__)

# ─── Banner ──────────────────────────────────────────────────────────────────
BANNER = """
╔══════════════════════════════════════════════════════════════╗
║     SailPoint ISC → Veza OAA Integration  (v1.0)            ║
╚══════════════════════════════════════════════════════════════╝
"""


# ─── Logging ─────────────────────────────────────────────────────────────────
def _setup_logging(log_level: str = "INFO") -> None:
    """Configure file-only logging with hourly rotation to the logs/ folder."""
    script_dir = os.path.dirname(os.path.abspath(__file__))
    log_dir = os.path.join(script_dir, "logs")
    os.makedirs(log_dir, exist_ok=True)

    timestamp = datetime.now().strftime("%d%m%Y-%H%M")
    script_name = os.path.splitext(os.path.basename(__file__))[0]
    log_file = os.path.join(log_dir, f"{script_name}_{timestamp}.log")

    handler = TimedRotatingFileHandler(
        log_file,
        when="h",
        interval=1,
        backupCount=24,
        encoding="utf-8",
    )
    handler.setFormatter(logging.Formatter(
        fmt="%(asctime)s %(levelname)-8s %(message)s",
        datefmt="%Y-%m-%dT%H:%M:%S",
    ))

    root = logging.getLogger()
    root.setLevel(getattr(logging, log_level.upper(), logging.INFO))
    root.addHandler(handler)


# ─── Configuration ────────────────────────────────────────────────────────────
def load_config(args: argparse.Namespace) -> dict:
    """
    Load configuration; precedence: CLI arg → environment variable → .env file.
    Exits with a clear error message if required values are missing.
    """
    env_file = getattr(args, "env_file", ".env")
    if env_file and os.path.exists(env_file):
        load_dotenv(env_file)

    # SailPoint tenant / base URL
    tenant = getattr(args, "sailpoint_tenant", None) or os.getenv("SAILPOINT_TENANT", "")
    sailpoint_url = getattr(args, "sailpoint_url", None) or os.getenv("SAILPOINT_URL", "")

    if not tenant and not sailpoint_url:
        log.error(
            "SailPoint tenant is required. Set --sailpoint-tenant (e.g. 'mycompany') "
            "or SAILPOINT_TENANT env var, or provide --sailpoint-url."
        )
        sys.exit(1)

    # Derive base URL from tenant name if an explicit URL is not provided
    base_url = (sailpoint_url or f"https://{tenant}.api.identitynow.com").rstrip("/")

    # If tenant was not given but URL was, extract tenant from URL for labelling
    if not tenant and base_url:
        # e.g. https://mycompany.api.identitynow.com  →  mycompany
        host = base_url.replace("https://", "").replace("http://", "").split(".")[0]
        tenant = host

    client_id = (
        getattr(args, "sailpoint_client_id", None)
        or os.getenv("SAILPOINT_CLIENT_ID", "")
    )
    client_secret = (
        getattr(args, "sailpoint_client_secret", None)
        or os.getenv("SAILPOINT_CLIENT_SECRET", "")
    )
    if not client_id or not client_secret:
        log.error(
            "SailPoint OAuth2 credentials are required. "
            "Set SAILPOINT_CLIENT_ID and SAILPOINT_CLIENT_SECRET, "
            "or use --sailpoint-client-id / --sailpoint-client-secret."
        )
        sys.exit(1)

    veza_url = (
        getattr(args, "veza_url", None) or os.getenv("VEZA_URL", "")
    ).rstrip("/")
    veza_api_key = (
        getattr(args, "veza_api_key", None) or os.getenv("VEZA_API_KEY", "")
    )

    dry_run = getattr(args, "dry_run", False)
    if not dry_run and (not veza_url or not veza_api_key):
        log.error(
            "VEZA_URL and VEZA_API_KEY are required unless --dry-run is set."
        )
        sys.exit(1)

    provider_name = (
        getattr(args, "provider_name", None)
        or os.getenv("PROVIDER_NAME", "SailPoint")
    )
    datasource_name = (
        getattr(args, "datasource_name", None)
        or os.getenv("DATASOURCE_NAME", tenant)
    )

    return {
        "tenant": tenant,
        "base_url": base_url,
        "client_id": client_id,
        "client_secret": client_secret,
        "veza_url": veza_url,
        "veza_api_key": veza_api_key,
        "provider_name": provider_name,
        "datasource_name": datasource_name,
    }


# ─── SailPoint API helpers ────────────────────────────────────────────────────
def get_access_token(base_url: str, client_id: str, client_secret: str) -> str:
    """
    Obtain a short-lived JWT access_token from SailPoint via the
    OAuth 2.0 Client Credentials grant flow (PAT-based).

    Token URL: POST https://{tenant}.api.identitynow.com/oauth/token
    """
    token_url = f"{base_url}/oauth/token"
    log.debug("Requesting OAuth2 access token from %s", token_url)
    try:
        resp = requests.post(
            token_url,
            data={
                "grant_type": "client_credentials",
                "client_id": client_id,
                "client_secret": client_secret,
            },
            timeout=30,
        )
        resp.raise_for_status()
    except requests.exceptions.HTTPError as exc:
        log.error(
            "Failed to obtain SailPoint access token: HTTP %s — %s",
            exc.response.status_code,
            exc.response.text[:200],
        )
        sys.exit(1)
    except requests.exceptions.RequestException as exc:
        log.error("Network error obtaining SailPoint access token: %s", exc)
        sys.exit(1)

    token = resp.json().get("access_token")
    if not token:
        log.error("SailPoint token response did not contain access_token")
        sys.exit(1)

    log.debug("Access token obtained successfully")
    return token


def make_session(access_token: str) -> requests.Session:
    """
    Build a requests.Session with the Bearer token header and an
    exponential-backoff retry policy for transient errors.
    """
    from requests.adapters import HTTPAdapter
    from urllib3.util.retry import Retry

    session = requests.Session()
    session.headers.update({
        "Authorization": f"Bearer {access_token}",
        "Accept": "application/json",
    })

    retry = Retry(
        total=3,
        backoff_factor=1.0,
        status_forcelist=[429, 500, 502, 503, 504],
        allowed_methods=["GET"],
        raise_on_status=False,
    )
    adapter = HTTPAdapter(max_retries=retry)
    session.mount("https://", adapter)
    session.mount("http://", adapter)
    return session


def paginate(session: requests.Session, url: str, params: dict = None, limit: int = 250) -> list:
    """
    Collect all results from a paginated SailPoint v3 API endpoint.
    Uses the given limit (default 250; use 50 for /v3/roles which caps at 50)
    and increments offset until an empty page is returned.
    """
    if params is None:
        params = {}
    params = {**params, "limit": limit, "offset": 0}
    results = []

    while True:
        log.debug("GET %s  offset=%d", url, params["offset"])
        try:
            resp = session.get(url, params=params, timeout=60)
            resp.raise_for_status()
        except requests.exceptions.HTTPError as exc:
            log.error("HTTP error fetching %s: %s", url, exc)
            raise

        data = resp.json()
        if not isinstance(data, list) or not data:
            break

        results.extend(data)
        log.debug("  → page of %d; running total %d", len(data), len(results))

        if len(data) < limit:
            break
        params = {**params, "offset": params["offset"] + limit}

    return results


def paginate_search(
    session: requests.Session,
    url: str,
    index: str,
    query: str = "*",
    limit: int = 250,
) -> list:
    """
    Collect all results from the SailPoint Search API (POST /v3/search).
    Uses offset-based pagination with the given limit until an empty page
    is returned.
    """
    results = []
    offset = 0

    while True:
        payload = {
            "indices": [index],
            "query": {"query": query},
            "includeNested": True,
        }
        params = {"limit": limit, "offset": offset}
        log.debug("POST %s  index=%s  offset=%d", url, index, offset)
        try:
            resp = session.post(url, json=payload, params=params, timeout=60)
            resp.raise_for_status()
        except requests.exceptions.HTTPError as exc:
            log.error("HTTP error searching %s (index=%s): %s", url, index, exc)
            raise

        data = resp.json()
        if not isinstance(data, list) or not data:
            break

        results.extend(data)
        log.debug("  → page of %d; running total %d", len(data), len(results))

        if len(data) < limit:
            break
        offset += limit

    return results


# ─── Data collection ──────────────────────────────────────────────────────────
def collect_identities(session: requests.Session, api_base: str) -> list:
    """Fetch all identities via POST /v3/search (identities index, paginated).

    The GET /v3/identities endpoint was deprecated on newer ISC tenants; the
    Search API is the recommended replacement and returns the same fields.
    """
    search_url = f"{api_base}/search"
    log.info("Collecting identities from /v3/search (identities index) ...")
    identities = paginate_search(session, search_url, index="identities")
    log.info("Collected %d identities", len(identities))
    return identities


def collect_roles(session: requests.Session, api_base: str) -> list:
    """Fetch all roles from /v3/roles (paginated).

    Note: /v3/roles enforces a maximum page size of 50 per the API spec.
    """
    log.info("Collecting roles from /v3/roles ...")
    roles = paginate(session, f"{api_base}/roles", limit=50)
    log.info("Collected %d roles", len(roles))
    return roles


def collect_role_assignments(
    session: requests.Session, api_base: str, roles: list
) -> dict:
    """
    For each role, fetch the list of identities assigned to it.

    Calls GET /v3/roles/{roleId}/assigned-identities (paginated per role).
    Returns: {role_id: [identity_id, ...]}
    """
    log.info("Collecting role assignments for %d roles ...", len(roles))
    assignments: dict = {}

    for role in roles:
        role_id = role.get("id", "")
        role_name = role.get("name", role_id)
        if not role_id:
            continue

        url = f"{api_base}/roles/{role_id}/assigned-identities"
        try:
            assigned = paginate(session, url)
            assignments[role_id] = [
                i.get("id") for i in assigned if i.get("id")
            ]
            log.debug(
                "  Role '%s' → %d assigned identities",
                role_name,
                len(assignments[role_id]),
            )
        except requests.exceptions.HTTPError as exc:
            log.warning(
                "Could not fetch assigned identities for role '%s' (%s): %s",
                role_name,
                role_id,
                exc,
            )
            assignments[role_id] = []

    total_assignments = sum(len(v) for v in assignments.values())
    log.info(
        "Role assignment collection complete — %d total assignments across %d roles",
        total_assignments,
        len(assignments),
    )
    return assignments


def collect_access_profiles(session: requests.Session, api_base: str) -> list:
    """Fetch all access profiles from /v3/access-profiles (paginated)."""
    log.info("Collecting access profiles from /v3/access-profiles ...")
    profiles = paginate(session, f"{api_base}/access-profiles")
    log.info("Collected %d access profiles", len(profiles))
    return profiles


# ─── OAA payload assembly ─────────────────────────────────────────────────────
def build_oaa_payload(
    config: dict,
    identities: list,
    roles: list,
    role_assignments: dict,
    access_profiles: list,
) -> CustomApplication:
    """
    Construct the Veza OAA CustomApplication payload from SailPoint data.

    Mapping:
      Identity        → Local User     (unique_id = SailPoint identity id)
      Role            → Local Role     (unique_id = SailPoint role id)
      Identity→Role   → user.add_role(role_name)
      Access Profile  → Resource       (resource_type = "access_profile")
      Role→Profile    → resource.add_permission("member", local_roles=[...])
      Profile owner   → resource.add_permission("owner", identities=[...])
    """
    log.info("Building OAA payload ...")

    app = CustomApplication(
        name=config["datasource_name"],
        application_type=config["provider_name"],
        description=(
            "SailPoint Identity Security Cloud — identities, roles, and access profiles "
            f"for tenant '{config['tenant']}'"
        ),
    )

    # ── Custom permissions ──────────────────────────────────────────────────
    app.add_custom_permission(
        "member",
        [OAAPermission.DataRead],
    )
    app.add_custom_permission(
        "owner",
        [
            OAAPermission.DataRead,
            OAAPermission.DataWrite,
            OAAPermission.MetadataRead,
            OAAPermission.MetadataWrite,
        ],
    )

    # ── Custom property definitions — Local User ────────────────────────────
    app.property_definitions.define_local_user_property("sailpoint_id",    "string")
    app.property_definitions.define_local_user_property("alias",           "string")
    app.property_definitions.define_local_user_property("manager_name",    "string")
    app.property_definitions.define_local_user_property("lifecycle_state", "string")
    app.property_definitions.define_local_user_property("is_manager",      "boolean")

    # ── Custom property definitions — Local Role ────────────────────────────
    app.property_definitions.define_local_role_property("sailpoint_role_id", "string")
    app.property_definitions.define_local_role_property("enabled",           "boolean")
    app.property_definitions.define_local_role_property("requestable",       "boolean")
    app.property_definitions.define_local_role_property("owner_name",        "string")

    # ── Custom property definitions — Application Resource ──────────────────
    app.property_definitions.define_resource_property("sailpoint_profile_id", "string")
    app.property_definitions.define_resource_property("source_name",          "string")
    app.property_definitions.define_resource_property("enabled",              "boolean")
    app.property_definitions.define_resource_property("requestable",          "boolean")
    app.property_definitions.define_resource_property("entitlement_count",    "number")

    # ── Local Users from SailPoint Identities ───────────────────────────────
    identity_map: dict = {}  # sailpoint_id → OAA Local User object

    for identity in identities:
        uid = identity.get("id", "")
        if not uid:
            log.debug("Skipping identity with no id: %s", identity.get("name"))
            continue

        first = identity.get("firstName") or ""
        last = identity.get("lastName") or ""
        display_name = (
            identity.get("name")
            or f"{first} {last}".strip()
            or identity.get("alias")
            or uid
        )
        email = identity.get("emailAddress") or ""
        is_active = identity.get("status", "ACTIVE").upper() == "ACTIVE"

        user = app.add_local_user(
            name=display_name,
            unique_id=uid,
            identities=[email] if email else [],
        )
        user.is_active = is_active
        user.is_admin = False  # SailPoint admin access flows through roles

        user.set_property("sailpoint_id",    uid)
        user.set_property("alias",           identity.get("alias") or "")
        user.set_property("manager_name",    (identity.get("manager") or {}).get("name") or "")
        user.set_property("lifecycle_state", (identity.get("lifecycleState") or {}).get("stateName") or "")
        user.set_property("is_manager",      bool(identity.get("isManager", False)))

        identity_map[uid] = user

    log.info("Added %d local users to OAA payload", len(identity_map))

    # ── Local Roles from SailPoint Roles ────────────────────────────────────
    role_name_map: dict = {}  # sailpoint role_id → role display name

    for role in roles:
        role_id = role.get("id", "")
        role_name = role.get("name", "")
        if not role_id or not role_name:
            continue

        local_role = app.add_local_role(
            name=role_name,
            unique_id=role_id,
        )
        local_role.set_property("sailpoint_role_id", role_id)
        local_role.set_property("enabled",           bool(role.get("enabled", False)))
        local_role.set_property("requestable",       bool(role.get("requestable", False)))
        local_role.set_property("owner_name",        (role.get("owner") or {}).get("name") or "")

        role_name_map[role_id] = role_name

    log.info("Added %d local roles to OAA payload", len(role_name_map))

    # ── Identity → Role assignments ─────────────────────────────────────────
    assignment_count = 0
    for role_id, identity_ids in role_assignments.items():
        role_name = role_name_map.get(role_id)
        if not role_name:
            continue
        for identity_id in identity_ids:
            user = identity_map.get(identity_id)
            if user:
                user.add_role(role_name)
                assignment_count += 1

    log.info("Created %d identity-role assignments", assignment_count)

    # ── Build role → access-profile membership map ──────────────────────────
    # Each SailPoint role lists the access profiles it contains.
    profile_to_roles: dict = {}  # profile_id → [role_name, ...]
    for role in roles:
        role_name = role_name_map.get(role.get("id", ""), "")
        if not role_name:
            continue
        for ap in role.get("accessProfiles") or []:
            ap_id = ap.get("id", "")
            if ap_id:
                profile_to_roles.setdefault(ap_id, []).append(role_name)

    # ── Access Profiles as Application Resources ────────────────────────────
    resource_count = 0
    for profile in access_profiles:
        profile_id = profile.get("id", "")
        profile_name = profile.get("name", "")
        if not profile_id or not profile_name:
            continue

        resource = app.add_resource(
            name=profile_name,
            resource_type="access_profile",
        )

        resource.set_property("sailpoint_profile_id", profile_id)
        resource.set_property(
            "source_name",
            (profile.get("source") or {}).get("name") or "",
        )
        resource.set_property("enabled",          bool(profile.get("enabled", False)))
        resource.set_property("requestable",      bool(profile.get("requestable", True)))
        entitlements = profile.get("entitlements") or []
        resource.set_property("entitlement_count", len(entitlements))

        # Give 'member' permission to every role that contains this access profile
        linked_roles = profile_to_roles.get(profile_id, [])
        if linked_roles:
            resource.add_permission("member", local_roles=linked_roles)

        # Give 'owner' permission to the access profile's designated owner identity
        owner_id = (profile.get("owner") or {}).get("id", "")
        if owner_id and owner_id in identity_map:
            resource.add_permission("owner", identities=[owner_id])

        resource_count += 1

    log.info("Added %d access-profile resources to OAA payload", resource_count)
    log.info("OAA payload build complete")
    return app


# ─── Veza push ────────────────────────────────────────────────────────────────
def push_to_veza(
    config: dict,
    app: CustomApplication,
    dry_run: bool = False,
    save_json: bool = False,
) -> None:
    """Push the OAA payload to Veza, or perform a dry-run (no push)."""
    if save_json or dry_run:
        payload = app.get_payload()
        json_path = os.path.join(
            os.path.dirname(os.path.abspath(__file__)),
            f"sailpoint_oaa_payload_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json",
        )
        with open(json_path, "w", encoding="utf-8") as fh:
            json.dump(payload, fh, indent=2, default=str)
        log.info("OAA payload saved to %s", json_path)
        print(f"[INFO] Payload saved → {json_path}")

    if dry_run:
        log.info("[DRY RUN] Payload built successfully — skipping Veza push")
        print("[INFO] Dry-run complete. No data was pushed to Veza.")
        return

    log.info("Pushing OAA payload to Veza at %s ...", config["veza_url"])
    veza_con = OAAClient(url=config["veza_url"], token=config["veza_api_key"])
    try:
        response = veza_con.push_application(
            provider_name=config["provider_name"],
            data_source_name=config["datasource_name"],
            application_object=app,
            create_provider=True,
        )
        if response and response.get("warnings"):
            for warning in response["warnings"]:
                log.warning("Veza warning: %s", warning)
        log.info("Successfully pushed OAA payload to Veza")
    except OAAClientError as exc:
        log.error(
            "Veza push failed: %s — %s (HTTP %s)",
            exc.error,
            exc.message,
            exc.status_code,
        )
        if hasattr(exc, "details"):
            for detail in exc.details:
                log.error("  Detail: %s", detail)
        sys.exit(1)


# ─── Argument parsing ─────────────────────────────────────────────────────────
def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="SailPoint Identity Security Cloud → Veza OAA Integration",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )

    sp = parser.add_argument_group("SailPoint ISC")
    sp.add_argument(
        "--sailpoint-tenant",
        default=None,
        metavar="TENANT",
        help="SailPoint tenant name (e.g. 'mycompany'). "
             "Constructs base URL as https://<tenant>.api.identitynow.com",
    )
    sp.add_argument(
        "--sailpoint-url",
        default=None,
        metavar="URL",
        help="Full SailPoint API base URL (overrides --sailpoint-tenant). "
             "e.g. https://mycompany.api.identitynow.com",
    )
    sp.add_argument(
        "--sailpoint-client-id",
        default=None,
        metavar="CLIENT_ID",
        help="OAuth2 PAT Client ID (also read from SAILPOINT_CLIENT_ID)",
    )
    sp.add_argument(
        "--sailpoint-client-secret",
        default=None,
        metavar="CLIENT_SECRET",
        help="OAuth2 PAT Client Secret (also read from SAILPOINT_CLIENT_SECRET)",
    )

    vz = parser.add_argument_group("Veza")
    vz.add_argument(
        "--veza-url",
        default=None,
        metavar="URL",
        help="Veza tenant URL, e.g. https://myorg.veza.com (also read from VEZA_URL)",
    )
    vz.add_argument(
        "--veza-api-key",
        default=None,
        metavar="KEY",
        help="Veza API key (also read from VEZA_API_KEY)",
    )

    oaa = parser.add_argument_group("OAA Settings")
    oaa.add_argument(
        "--provider-name",
        default=None,
        metavar="NAME",
        help="Provider name as it appears in the Veza UI (default: SailPoint)",
    )
    oaa.add_argument(
        "--datasource-name",
        default=None,
        metavar="NAME",
        help="Datasource name in Veza UI (default: tenant name)",
    )

    rt = parser.add_argument_group("Runtime")
    rt.add_argument(
        "--env-file",
        default=".env",
        metavar="PATH",
        help="Path to .env file containing credentials",
    )
    rt.add_argument(
        "--dry-run",
        action="store_true",
        help="Build the OAA payload locally without pushing to Veza",
    )
    rt.add_argument(
        "--save-json",
        action="store_true",
        help="Save the OAA payload as a JSON file for inspection",
    )
    rt.add_argument(
        "--log-level",
        default="INFO",
        choices=["DEBUG", "INFO", "WARNING", "ERROR"],
        help="Logging verbosity",
    )

    return parser.parse_args()


# ─── Entry point ──────────────────────────────────────────────────────────────
def main() -> None:
    print(BANNER)
    args = parse_args()
    _setup_logging(args.log_level)
    log.info("SailPoint → Veza OAA integration starting")

    config = load_config(args)
    log.info(
        "Tenant: %s | Base URL: %s | Provider: %s | Datasource: %s",
        config["tenant"],
        config["base_url"],
        config["provider_name"],
        config["datasource_name"],
    )

    # Authenticate to SailPoint
    access_token = get_access_token(
        config["base_url"], config["client_id"], config["client_secret"]
    )
    session = make_session(access_token)
    api_base = f"{config['base_url']}/v3"

    # Collect all data
    identities = collect_identities(session, api_base)
    roles = collect_roles(session, api_base)
    role_assignments = collect_role_assignments(session, api_base, roles)
    access_profiles = collect_access_profiles(session, api_base)

    # Build OAA payload
    app = build_oaa_payload(
        config, identities, roles, role_assignments, access_profiles
    )

    log.info(
        "Payload summary — identities: %d  roles: %d  access_profiles: %d",
        len(identities),
        len(roles),
        len(access_profiles),
    )

    # Push to Veza (or dry-run)
    push_to_veza(config, app, dry_run=args.dry_run, save_json=args.save_json)
    log.info("Integration run complete")


if __name__ == "__main__":
    main()
