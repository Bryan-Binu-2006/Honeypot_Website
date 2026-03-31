"""Central fake values and response builders used across deception routes."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
import base64
import json
import random
import string
from typing import Dict, List


FAKE_COMPANY_NAME = "CyberShield Technologies Inc."
FAKE_DOMAIN = "cybershield.io"
FAKE_INTERNAL_DOMAIN = "internal.cybershield.io"
FAKE_HOSTNAME_PROD = "cybershield-prod-01"
FAKE_HOSTNAME_DB = "db-prod-01.internal.cybershield.io"
FAKE_HOSTNAME_CACHE = "cache-01.internal.cybershield.io"

FAKE_JWT_SECRET = "hs256-prod-secret-do-not-share-2026"
FAKE_ADMIN_API_KEY = "adminkey-7f3a9b2c-prod-f3a91"
FAKE_INTERNAL_API_KEY = "int-api-key-9k2m4n8p-x991"
FAKE_DB_PASSWORD = "Pr0d#Secur3!2026"
FAKE_DB_USER = "cs_app"
FAKE_DB_NAME = "cybershield_prod"
FAKE_REDIS_PASSWORD = "r3d1s_pr0d_k3y_2026"
FAKE_STAGING_DB_PASS = "Staging#Pass2026!"
FAKE_STRIPE_KEY = "stripe_live_sim_4eC39HqLyjWDarjtT1zdp7dc"
FAKE_SENDGRID_KEY = "sendgrid_prod_sim_aBcDeFgHiJkLmNoPqRsTuVwXyZ012345"
FAKE_AWS_ACCESS_KEY = "AWSAKI_SIM_IOSFODNN7EXAMPLE"
FAKE_AWS_SECRET_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
FAKE_AWS_REGION = "us-east-1"
FAKE_S3_BUCKET_PRIVATE = "cybershield-backups-private"
FAKE_S3_BUCKET_ASSETS = "cybershield-prod-assets"
FAKE_GITLAB_TOKEN = "gitlab_pat_sim_xXfAkEtOkEnXx_2026_prod"
FAKE_DEPLOY_KEY = "deploy-key-prod-7f3a9b2c"
FAKE_VAULT_ROOT_TOKEN = "vault_root_sim_CAESFAKE_2026"
FAKE_K8S_SERVICE_ACCOUNT = (
    "eyJhbGciOiJSUzI1NiJ9."
    "eyJzdWIiOiJzeXN0ZW06c2VydmljZWFjY291bnQ6ZGVmYXVsdDpjeWJlcnNoaWVsZC1hZG1pbiJ9."
    "FAKE"
)
FAKE_SLACK_WEBHOOK = "https://slack-webhook.cybershield.internal/services/T000/B000/FAKE"
FAKE_DATADOG_API_KEY = "dd-api-key-f9a1c3b2d4e5f6a7b8c9d0e1f2a3b4c5"

FAKE_SERVER_IP_PUBLIC = "34.205.17.82"
FAKE_SERVER_IP_INTERNAL = "10.0.1.42"
FAKE_DB_IP = "10.0.1.55"
FAKE_CACHE_IP = "10.0.1.67"
FAKE_VPC_CIDR = "10.0.0.0/16"

FAKE_EMPLOYEES = [
    {
        "name": "Sarah Chen",
        "role": "DevOps Lead",
        "email": "s.chen@cybershield.io",
        "slack": "@sarah.chen",
    },
    {
        "name": "Mike Torres",
        "role": "Backend Engineer",
        "email": "m.torres@cybershield.io",
        "slack": "@mike.t",
    },
    {
        "name": "Alice Novak",
        "role": "Security Engineer",
        "email": "a.novak@cybershield.io",
        "slack": "@alice.sec",
    },
    {
        "name": "James Okafor",
        "role": "CTO",
        "email": "j.okafor@cybershield.io",
        "slack": "@james.cto",
    },
    {
        "name": "Priya Sharma",
        "role": "DBA",
        "email": "p.sharma@cybershield.io",
        "slack": "@priya.db",
    },
]

CUSTOMER_ACCOUNTS = {
    "nina.r@northbridge.local": {
        "password": "ClientPortal!2026",
        "display_name": "Nina Rao",
        "company": "Northbridge Capital",
        "tier": "Enterprise Guard",
    },
    "liam.p@vectorgrid.io": {
        "password": "ClientPortal!2026",
        "display_name": "Liam Patel",
        "company": "VectorGrid Systems",
        "tier": "Business Shield",
    },
    "maya.k@solislogistics.com": {
        "password": "ClientPortal!2026",
        "display_name": "Maya Kim",
        "company": "Solis Logistics",
        "tier": "Enterprise Guard",
    },
}

ADMIN_USERNAME = "admin"
ADMIN_PASSWORD = "SuperSecureAdmin!2026"

RECON_ROBOTS = """User-agent: *
Disallow: /admin/
Disallow: /api/internal/
Disallow: /api/v2/
Disallow: /.git/
Disallow: /backup/
Disallow: /staging/
Disallow: /config/
Disallow: /uploads/private/
Disallow: /api/debug/
Disallow: /health/detailed
Disallow: /internal/

# Legacy paths - do not index
Disallow: /old-admin/
Disallow: /portal/
Disallow: /support/internal/

Sitemap: /sitemap.xml
"""


def build_fake_env_text() -> str:
    return f"""# CyberShield Production Environment
# Last updated: 2026-01-15 by DevOps

APP_ENV=production
APP_VERSION=2.4.1
SECRET_KEY=sk-prod-f9a1c3b2d4e5f6a7b8c9d0e1f2a3b4c5
SESSION_SECRET=sess-f9a1c3b2d4e5f6a7b8c9d0e1f2a3b4c5

DB_HOST={FAKE_HOSTNAME_DB}
DB_PORT=5432
DB_NAME={FAKE_DB_NAME}
DB_USER={FAKE_DB_USER}
DB_PASS={FAKE_DB_PASSWORD}
DB_POOL_SIZE=20
DB_SSL=require

REDIS_URL=redis://:{FAKE_REDIS_PASSWORD}@cache-01.internal:6379/0
REDIS_CLUSTER=false

AWS_ACCESS_KEY_ID={FAKE_AWS_ACCESS_KEY}
AWS_SECRET_ACCESS_KEY={FAKE_AWS_SECRET_KEY}
AWS_DEFAULT_REGION={FAKE_AWS_REGION}
S3_BUCKET_ASSETS={FAKE_S3_BUCKET_ASSETS}
S3_BUCKET_BACKUPS={FAKE_S3_BUCKET_PRIVATE}

STRIPE_SECRET_KEY={FAKE_STRIPE_KEY}
STRIPE_WEBHOOK_SECRET=webhooksec_sim_FakeWebhookSecret2026
SENDGRID_API_KEY={FAKE_SENDGRID_KEY}
SENDGRID_FROM=noreply@{FAKE_DOMAIN}

JWT_SECRET={FAKE_JWT_SECRET}
JWT_EXPIRY=3600
JWT_REFRESH_EXPIRY=86400

ADMIN_PANEL_KEY={FAKE_ADMIN_API_KEY}
INTERNAL_API_KEY={FAKE_INTERNAL_API_KEY}
DATADOG_API_KEY={FAKE_DATADOG_API_KEY}

# DO NOT COMMIT - rotate quarterly
# Last rotated: 2026-01-01 by Alice Novak
"""


def build_fake_git_config() -> str:
    return f"""[core]
    repositoryformatversion = 0
    filemode = true
    bare = false
    logallrefupdates = true
[remote "origin"]
    url = git@gitlab.internal.cybershield.io:platform/cybershield-webapp.git
    fetch = +refs/heads/*:refs/remotes/origin/*
[remote "staging"]
    url = git@gitlab.internal.cybershield.io:platform/cybershield-webapp-staging.git
    fetch = +refs/heads/*:refs/remotes/staging/*
[branch "main"]
    remote = origin
    merge = refs/heads/main
[branch "dev"]
    remote = origin
    merge = refs/heads/dev
[branch "feature/api-v3"]
    remote = origin
    merge = refs/heads/feature/api-v3
# CI deploy hook: https://{FAKE_DOMAIN}/api/deploy?token={FAKE_DEPLOY_KEY}
# Emergency unlock: https://{FAKE_DOMAIN}/admin/unlock?token=UNLOCK_DEV_2026
# Internal docs: http://wiki.internal.cybershield.io/ops/runbooks
"""


def build_swagger_spec() -> Dict[str, object]:
    return {
        "openapi": "3.0.0",
        "info": {"title": "CyberShield API", "version": "2.4.1"},
        "paths": {
            "/api/v1/users": {
                "get": {"deprecated": True, "summary": "Legacy users export"},
                "post": {"x-internal": True, "x-auth-bypass": "legacy-header"},
            },
            "/api/v2/internal/users": {
                "get": {"summary": "Internal user listing", "x-internal": True}
            },
            "/api/fetch": {"post": {"summary": "URL fetch helper", "deprecated": False}},
            "/admin/debug/eval": {"post": {"summary": "Template tester", "x-internal": True}},
        },
        "components": {"securitySchemes": {"bearerAuth": {"type": "http", "scheme": "bearer"}}},
    }


def build_package_manifest() -> Dict[str, object]:
    return {
        "name": "cybershield-webapp",
        "version": "2.4.1",
        "dependencies": {
            "express": "4.17.1",
            "jsonwebtoken": "8.5.1",
            "lodash": "4.17.4",
            "axios": "0.21.1",
            "multer": "1.4.2",
            "serialize-javascript": "3.1.0",
        },
    }


def build_server_status_html() -> str:
    rows = []
    for idx in range(1, 13):
        ip = f"10.0.1.{20 + idx}"
        uri = random.choice(
            [
                "/internal/db",
                "/api/v2/internal/users",
                "/admin/debug/eval",
                "/api/fetch",
                "/internal/vault/secrets",
            ]
        )
        rows.append(f"<tr><td>{idx}</td><td>{ip}</td><td>{uri}</td><td>W</td></tr>")
    return (
        "<html><body><h1>Apache Server Status for cybershield-prod-01</h1>"
        "<p>Server Uptime: 47 days 04:16:21</p>"
        "<p>Total accesses: 4381272 - Total Traffic: 912 GB</p>"
        "<table border='1'><tr><th>Slot</th><th>Client</th><th>Request</th><th>Status</th></tr>"
        + "".join(rows)
        + "</table></body></html>"
    )


def build_phpinfo_html() -> str:
    return (
        "<html><body><h1>phpinfo()</h1>"
        "<table border='1'>"
        "<tr><td>PHP Version</td><td>7.4.3</td></tr>"
        "<tr><td>System</td><td>Linux cybershield-prod-01</td></tr>"
        "<tr><td>Loaded Extensions</td><td>PDO, curl, OpenSSL, mbstring, json</td></tr>"
        "<tr><td>DOCUMENT_ROOT</td><td>/var/www/cybershield</td></tr>"
        f"<tr><td>SERVER_ADDR</td><td>{FAKE_SERVER_IP_INTERNAL}</td></tr>"
        f"<tr><td>SERVER_NAME</td><td>{FAKE_DOMAIN}</td></tr>"
        "</table></body></html>"
    )


def build_web_xml() -> str:
    return """<?xml version="1.0" encoding="UTF-8"?>
<web-app>
  <display-name>CyberShield Internal Portal</display-name>
  <servlet>
    <servlet-name>AdminServlet</servlet-name>
    <servlet-class>io.cybershield.AdminServlet</servlet-class>
  </servlet>
  <servlet-mapping>
    <servlet-name>AdminServlet</servlet-name>
    <url-pattern>/admin/*</url-pattern>
  </servlet-mapping>
</web-app>
"""


def build_backup_blob() -> bytes:
    prefix = (
        "-- CyberShield DB backup Jan 2026. Encrypted with AES-256. "
        "Key in vault at prod/backup/encryption_key\n"
    ).encode("ascii")
    random_bytes = bytes(random.getrandbits(8) for _ in range(2000))
    return prefix + random_bytes


def build_fake_changelog() -> str:
    return """# CHANGELOG

## v2.4.1
- Patched IDOR in /api/v1/users endpoint (see ticket SEC-291)

## v2.3.0
- Removed hardcoded staging credentials from config loader

## v2.2.8
- Fixed auth bypass via malformed JWT header (reported by HackerOne)

## v2.1.0
- Deprecated /api/v1/auth/token — use /api/v2/auth instead

## v2.0.5
- Disabled debug eval endpoint in production (ticket ENG-1847)
"""


def build_fake_sitemap() -> str:
    paths = [
        "/",
        "/login",
        "/admin/",
        "/api/internal/",
        "/api/v2/",
        "/.git/",
        "/backup/",
        "/staging/",
        "/config/",
        "/uploads/private/",
        "/api/debug/",
        "/health/detailed",
        "/internal/",
        "/old-admin/",
        "/portal/",
        "/support/internal/",
    ]
    parts = ['<?xml version="1.0" encoding="UTF-8"?><urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">']
    for p in paths:
        parts.append(f"<url><loc>https://{FAKE_DOMAIN}{p}</loc><lastmod>2026-03-15</lastmod></url>")
    parts.append("</urlset>")
    return "".join(parts)


def _rand_hex(n: int = 8) -> str:
    return "".join(random.choices(string.hexdigits.lower()[:16], k=n))


def fake_upload_path() -> str:
    return f"/uploads/{_rand_hex(8)}.php"


def fake_upload_url(path: str) -> str:
    return f"https://{FAKE_DOMAIN}{path}"


def fake_users(count: int = 50) -> List[Dict[str, object]]:
    users: List[Dict[str, object]] = [
        {
            "id": 1,
            "username": "j.okafor",
            "email": "j.okafor@cybershield.io",
            "role": "superadmin",
            "last_login": "2026-01-15 10:23:45",
            "note": "SSH key on file. 2FA disabled for legacy reasons. Contact j.okafor@cybershield.io to re-enable.",
        },
        {
            "id": 2,
            "username": "a.novak",
            "email": "a.novak@cybershield.io",
            "role": "superadmin",
            "last_login": "2026-01-14 18:01:12",
        },
        {
            "id": 3,
            "username": "s.chen",
            "email": "s.chen@cybershield.io",
            "role": "superadmin",
            "last_login": "2026-01-14 12:03:55",
        },
    ]
    roles = (
        ["admin"] * 8
        + ["auditor"] * 2
        + ["api_service_account"] * 4
        + ["user"] * (count - 3 - 8 - 2 - 4)
    )
    idx = 4
    for role in roles:
        name = f"user_{idx:02d}"
        row: Dict[str, object] = {
            "id": idx,
            "username": name,
            "email": f"{name}@cybershield.io",
            "role": role,
            "last_login": f"2026-01-{(idx % 28) + 1:02d} {8 + (idx % 10):02d}:12:00",
        }
        if role == "auditor":
            row["can_export_logs"] = True
        if role == "api_service_account":
            row["api_key"] = f"svc-key-{idx:02d}-{_rand_hex(12)}"
        users.append(row)
        idx += 1
    if len(users) >= 7:
        users[6]["role"] = "api_service_account"
        users[6]["api_key"] = FAKE_INTERNAL_API_KEY
    return users[:count]


def build_env_map() -> Dict[str, str]:
    return {
        "APP_ENV": "production",
        "APP_VERSION": "2.4.1",
        "DB_HOST": FAKE_HOSTNAME_DB,
        "DB_PORT": "5432",
        "DB_NAME": FAKE_DB_NAME,
        "DB_USER": FAKE_DB_USER,
        "DB_PASS": FAKE_DB_PASSWORD,
        "REDIS_URL": f"redis://:{FAKE_REDIS_PASSWORD}@cache-01.internal:6379/0",
        "AWS_ACCESS_KEY_ID": FAKE_AWS_ACCESS_KEY,
        "AWS_SECRET_ACCESS_KEY": FAKE_AWS_SECRET_KEY,
        "AWS_DEFAULT_REGION": FAKE_AWS_REGION,
        "S3_BUCKET_ASSETS": FAKE_S3_BUCKET_ASSETS,
        "S3_BUCKET_BACKUPS": FAKE_S3_BUCKET_PRIVATE,
        "STRIPE_SECRET_KEY": FAKE_STRIPE_KEY,
        "SENDGRID_API_KEY": FAKE_SENDGRID_KEY,
        "JWT_SECRET": FAKE_JWT_SECRET,
        "ADMIN_PANEL_KEY": FAKE_ADMIN_API_KEY,
        "INTERNAL_API_KEY": FAKE_INTERNAL_API_KEY,
        "DATADOG_API_KEY": FAKE_DATADOG_API_KEY,
    }


def build_env_kv_text() -> str:
    return "\n".join([f"{k}={v}" for k, v in build_env_map().items()])


def consulate_jwt_secret_b64() -> str:
    return base64.b64encode(FAKE_JWT_SECRET.encode("utf-8")).decode("ascii")


def rate_limit_reset_ts() -> str:
    return str(int((datetime.now(timezone.utc) + timedelta(hours=1)).timestamp()))


def fake_jwt_like_token(subject: str = "reset") -> str:
    header = base64.urlsafe_b64encode(json.dumps({"alg": "HS256", "typ": "JWT"}).encode()).decode().rstrip("=")
    payload = base64.urlsafe_b64encode(
        json.dumps({"sub": subject, "iat": int(datetime.now(timezone.utc).timestamp())}).encode()
    ).decode().rstrip("=")
    sig = _rand_hex(32)
    return f"{header}.{payload}.{sig}"

