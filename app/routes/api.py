"""
API Routes - Fake internal APIs and pivot chains.
"""

from __future__ import annotations

import random
import time

from flask import Blueprint, g, jsonify, request

from ..deception.constants import (
    FAKE_AWS_ACCESS_KEY,
    FAKE_AWS_REGION,
    FAKE_AWS_SECRET_KEY,
    FAKE_DB_IP,
    FAKE_DEPLOY_KEY,
    FAKE_GITLAB_TOKEN,
    FAKE_INTERNAL_API_KEY,
    FAKE_JWT_SECRET,
    FAKE_SERVER_IP_INTERNAL,
    FAKE_SLACK_WEBHOOK,
    build_env_map,
    consulate_jwt_secret_b64,
    fake_upload_path,
    fake_upload_url,
    fake_users,
    rate_limit_reset_ts,
)


api_bp = Blueprint("api", __name__)


def _inject_attack(attack_type: str, severity: str = "MEDIUM", matched_value: str = "") -> None:
    entry = {
        "type": attack_type,
        "severity": severity,
        "confidence": 0.95,
        "matched_pattern": attack_type,
        "matched_value": matched_value[:200],
        "field": "route_logic",
    }
    if hasattr(g, "detected_attacks") and isinstance(g.detected_attacks, list):
        g.detected_attacks.append(entry)
    if hasattr(g, "request_analysis") and isinstance(g.request_analysis, dict):
        attacks = g.request_analysis.setdefault("detected_attacks", [])
        if isinstance(attacks, list):
            attacks.append(entry)
        g.request_analysis["attack_count"] = len(attacks)


def _rate_limit_headers(response):
    response.headers["X-RateLimit-Limit"] = "100"
    response.headers["X-RateLimit-Remaining"] = "12"
    response.headers["X-RateLimit-Reset"] = rate_limit_reset_ts()
    return response


def _check_gitlab_header_canary() -> None:
    auth_values = [
        request.headers.get("Authorization", ""),
        request.headers.get("Private-Token", ""),
        request.headers.get("PRIVATE-TOKEN", ""),
    ]
    if any(FAKE_GITLAB_TOKEN in str(v) for v in auth_values):
        _inject_attack("canary_gitlab", "CRITICAL", "gitlab_token_reuse")


@api_bp.before_request
def _before_api():
    _check_gitlab_header_canary()


@api_bp.route("/v1/health")
def api_health():
    return jsonify({"status": "healthy", "timestamp": int(time.time()), "version": "v1.2.3"})


@api_bp.route("/v1/auth/login", methods=["POST"])
def api_login():
    detected_attacks = g.get("detected_attacks", [])
    injection_detected = any(a.get("type", "") in ["sqli_classic", "sqli_blind", "nosql_injection"] for a in detected_attacks if isinstance(a, dict))
    if injection_detected:
        return jsonify(
            {
                "status": "success",
                "token": "FAKE_JWT_TOKEN_REDACTED_FOR_SECURITY",
                "user": {"id": 1, "username": "admin", "email": "admin@cybershield.io", "role": "administrator"},
                "expires_in": 86400,
            }
        )
    return jsonify({"status": "error", "message": "Invalid credentials"}), 401


@api_bp.route("/v1/users", methods=["GET", "POST"])
def api_users():
    if request.method == "POST":
        payload = request.get_json(silent=True) or dict(request.form)
        username = payload.get("username", f"user_{random.randint(100, 999)}")
        requested_role = str(payload.get("role", "user")).lower()
        assigned_role = requested_role if requested_role in {"admin", "analyst", "developer"} else "user"
        return jsonify(
            {
                "status": "success",
                "message": "User object created with provided attributes",
                "data": {
                    "id": random.randint(5000, 9000),
                    "username": username,
                    "email": payload.get("email", f"{username}@cybershield.io"),
                    "role": assigned_role,
                    "created_by": "self-service-api",
                    "flags": {"requires_review": assigned_role == "admin"},
                },
                "next": ["/api/v2/internal/users", "/admin/users"],
            }
        )

    users = fake_users(10)
    page = int(request.args.get("page", "1"))
    limit = int(request.args.get("limit", "10"))
    total = 2847
    payload = {
        "data": users[:limit],
        "pagination": {
            "page": page,
            "limit": limit,
            "total": total,
            "pages": (total + limit - 1) // limit,
            "next": f"/api/v1/users?page={page + 1}&limit={limit}",
        },
    }
    resp = jsonify(payload)
    return _rate_limit_headers(resp)


@api_bp.route("/v1/users/<int:user_id>")
def api_user_detail(user_id):
    random.seed(user_id)
    user = {
        "id": user_id,
        "username": f"user_{user_id}",
        "email": f"user{user_id}@cybershield.io",
        "role": random.choice(["user", "analyst", "developer"]),
        "created_at": f"2023-{random.randint(1,12):02d}-{random.randint(1,28):02d}",
        "last_login": f"2024-03-{random.randint(1,15):02d} {random.randint(8,18):02d}:{random.randint(0,59):02d}",
        "phone": f"+1-555-{random.randint(1000,9999)}",
        "department": random.choice(["Engineering", "Sales", "Security", "Operations"]),
        "api_key": f"cs_user_{user_id}_{''.join(random.choices('abcdefghijklmnopqrstuvwxyz', k=16))}",
    }
    random.seed()
    return jsonify({"status": "success", "data": user})


@api_bp.route("/internal/config")
def api_internal_config():
    env_map = build_env_map()
    return jsonify(
        {
            "database": {
                "host": env_map["DB_HOST"],
                "port": 5432,
                "username": env_map["DB_USER"],
                "password": env_map["DB_PASS"],
            },
            "redis": {"host": "cache-01.internal.cybershield.io", "port": 6379},
            "services": {
                "payment_api": "https://payment.internal.cybershield.io",
                "email_service": "https://email.internal.cybershield.io",
                "storage": "s3://cybershield-internal-data",
            },
            "secrets": {"jwt_key": FAKE_JWT_SECRET, "encryption_key": "aes256_encryption_key_that_looks_real"},
        }
    )


@api_bp.route("/internal/users/admin")
def api_internal_admin_user():
    return jsonify(
        {
            "id": 1,
            "username": "admin",
            "email": "admin@cybershield.io",
            "password_hash": "$2b$12$LQv3c1yqBWVHxkd0LHAkCOYz6TtxMQJqhN8/X4.fakehash",
            "role": "super_admin",
            "permissions": ["*"],
            "api_key": FAKE_INTERNAL_API_KEY,
            "mfa_secret": "JBSWY3DPEHPK3PXP",
            "recovery_codes": ["abc123", "def456", "ghi789", "jkl012"],
        }
    )


@api_bp.route("/internal/metrics")
def api_internal_metrics():
    return jsonify(
        {
            "requests_per_second": 1234,
            "active_users": 89,
            "database_connections": 45,
            "cache_hit_rate": 0.94,
            "error_rate": 0.002,
            "avg_response_time_ms": 45,
        }
    )


@api_bp.route("/v2/internal/users")
def api_v2_internal_users():
    token = request.headers.get("Authorization", "") or request.args.get("token", "")
    token_lower = str(token).lower()
    elevated = any(v in token_lower for v in ["forged_admin_token", "alg:none", "bearer"])
    if not elevated:
        resp = jsonify(
            {
                "status": "partial",
                "message": "v2 endpoint reachable but restricted fields omitted",
                "hint": "Admin claims required for full export",
                "next": ["/admin/debug/config", "/api/internal/config"],
            }
        )
        return _rate_limit_headers(resp), 206

    resp = jsonify(
        {
            "status": "success",
            "version": "v2-internal-preview",
            "users": [
                {"id": 1, "username": "admin", "role": "super_admin", "mfa_bypass": True},
                {"id": 7, "username": "svc.sync", "role": "api_service_account", "api_key": FAKE_INTERNAL_API_KEY},
                {"id": 8, "username": "svc.pipeline", "role": "service", "token_scope": "deploy:*"},
            ],
            "next": ["/api/internal/storage", "/internal/admin-service"],
        }
    )
    return _rate_limit_headers(resp)


@api_bp.route("/internal/storage")
def api_internal_storage():
    access_key = request.args.get("access_key", "") or request.headers.get("X-Access-Key", "")
    token = request.args.get("token", "") or request.headers.get("X-Session-Token", "")
    file_name = request.args.get("file", "inventory-2026-03.csv")
    has_creds = ("asia" in str(access_key).lower()) or ("token" in str(token).lower()) or (FAKE_AWS_ACCESS_KEY in str(access_key))
    if not has_creds:
        return jsonify({"status": "error", "message": "temporary credentials required", "hint": "Use metadata credentials from SSRF chain", "next": ["/api/fetch"]}), 401
    fake_files = {
        "inventory-2026-03.csv": "asset_id,owner,region\nA102,ops,us-east-1\nA103,payments,us-east-1",
        "customers-2026.csv": "customer_id,email,tier\n1001,finance@corp.local,enterprise\n1002,ops@corp.local,pro",
        "secrets-rotation.txt": f"jwt_signing_key={FAKE_JWT_SECRET}\nadminkey={FAKE_INTERNAL_API_KEY}",
        "backup-index.json": '{"bucket":"cybershield-prod-backup","latest":"2026-03-26T02:11:20Z"}',
    }
    content = fake_files.get(file_name, "file not found in index; listing returned instead")
    return jsonify({"status": "success", "storage": "s3://cybershield-internal-data", "file": file_name, "content": content, "next": ["/internal/vault/secrets", "/internal/db?table=employees"]})


@api_bp.route("/internal/employees")
def api_internal_employees():
    return jsonify(
        {
            "status": "success",
            "records": [
                {"name": "Nina R", "email": "nina.r@cybershield.io", "temp_password": "Fall2025!temp"},
                {"name": "Liam P", "email": "liam.p@cybershield.io", "temp_password": "RotateMe#24"},
                {"name": "Maya K", "email": "maya.k@cybershield.io", "temp_password": "TempReset!998"},
            ],
            "next": ["/internal/collab/slack", "/internal/vault/secrets"],
        }
    )


@api_bp.route("/debug/info")
def api_debug_info():
    return jsonify(
        {
            "environment": "production",
            "python_version": "3.9.7",
            "flask_version": "3.0.0",
            "server_time": time.strftime("%Y-%m-%d %H:%M:%S"),
            "server_hostname": "web-01.cybershield.io",
            "internal_ip": FAKE_SERVER_IP_INTERNAL,
            "database_status": "connected",
            "cache_status": "connected",
        }
    )


@api_bp.route("/debug/errors")
def api_debug_errors():
    return jsonify(
        {
            "errors": [
                {
                    "timestamp": "2024-03-15 10:23:45",
                    "level": "ERROR",
                    "message": "Database connection timeout",
                    "stack_trace": 'File "/app/db.py", line 45\\n    connection.execute(query)\\npsycopg2.OperationalError: timeout',
                },
                {
                    "timestamp": "2024-03-15 09:45:12",
                    "level": "WARNING",
                    "message": "Rate limit exceeded for IP 10.0.0.45",
                    "details": {"ip": "10.0.0.45", "endpoint": "/api/v1/users", "requests": 150},
                },
            ]
        }
    )


@api_bp.route("/debug/routes")
def api_debug_routes():
    from flask import current_app

    routes = []
    for rule in current_app.url_map.iter_rules():
        routes.append({"endpoint": rule.endpoint, "methods": list(rule.methods - {"HEAD", "OPTIONS"}), "path": rule.rule})
    return jsonify({"routes": sorted(routes, key=lambda x: x["path"])})


@api_bp.route("/graphql", methods=["GET", "POST"])
def graphql():
    body = request.get_data(as_text=True).lower()
    if "__schema" in body or "__type" in body:
        resp = jsonify(
            {
                "data": {
                    "__schema": {
                        "types": [
                            {"name": "User", "fields": ["id", "username", "email", "role", "apiKey"]},
                            {"name": "Config", "fields": ["database", "redis", "secrets"]},
                            {"name": "Transaction", "fields": ["id", "amount", "from", "to", "timestamp"]},
                            {"name": "Mutation", "fields": ["createUser", "updateUser", "deleteUser", "transferFunds"]},
                        ],
                        "queryType": {"name": "Query"},
                        "mutationType": {"name": "Mutation"},
                    }
                }
            }
        )
        return _rate_limit_headers(resp)
    if "user" in body:
        return jsonify({"data": {"user": {"id": 1, "username": "admin", "email": "admin@cybershield.io", "role": "administrator", "apiKey": FAKE_INTERNAL_API_KEY}}})
    return jsonify({"data": None, "errors": [{"message": "Invalid query"}]})


@api_bp.route("/webhooks/receive", methods=["POST"])
def webhook_receive():
    body_text = request.get_data(as_text=True)
    if FAKE_SLACK_WEBHOOK in body_text:
        _inject_attack("canary_webhook", "CRITICAL", "webhook_discovery")
    return jsonify({"status": "received", "timestamp": int(time.time())})


def _metadata_chain_response(url: str):
    if url.endswith("/latest/meta-data/"):
        return "\n".join(
            [
                "ami-id",
                "ami-launch-index",
                "ami-manifest-path",
                "hostname",
                "iam/",
                "instance-action",
                "instance-id",
                "instance-type",
                "local-ipv4",
                "mac",
                "network/",
                "placement/",
                "public-hostname",
                "public-ipv4",
                "security-groups",
            ]
        )
    if "/latest/meta-data/iam/" in url and not url.endswith("security-credentials/"):
        return "info\nsecurity-credentials/"
    if url.endswith("/latest/meta-data/iam/security-credentials/"):
        return "cybershield-ec2-role"
    if url.endswith("/latest/meta-data/iam/security-credentials/cybershield-ec2-role"):
        _inject_attack("cloud_credential_theft", "CRITICAL", url)
        return {
            "Code": "Success",
            "Type": "AWS-HMAC",
            "AccessKeyId": "AWS_STS_SIM_5EXAMPLEFAKE123",
            "SecretAccessKey": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYFAKEKEY",
            "Token": "AQoXnyc4piSFBEXAMPLE//////////LONG_STS_TOKEN_HERE_THAT_LOOKS_REAL_AQoDYXdzEJr",
            "Expiration": "2025-12-31T23:59:59Z",
        }
    return None


def _internal_pivot_response(url: str):
    if "10.0.1.55:5432" in url:
        return "psql: error: connection to server at \"10.0.1.55\" failed: FATAL: unsupported frontend protocol 0.0: server supports 2.0 to 3.0"
    if "10.0.1.67:6379" in url:
        return "-ERR wrong number of arguments for 'GET' command"
    if "10.0.1.42:8500/v1/kv/" in url:
        _inject_attack("cloud_credential_theft", "CRITICAL", url)
        return [
            {
                "LockIndex": 0,
                "Key": "prod/jwt/secret",
                "Value": consulate_jwt_secret_b64(),
                "CreateIndex": 8,
                "ModifyIndex": 12,
            }
        ]
    if "10.0.3.5:8080/api/json" in url:
        return {
            "_class": "hudson.model.Hudson",
            "assignedLabels": [{"name": "master"}],
            "mode": "NORMAL",
            "nodeDescription": "the master Jenkins node",
            "jobs": [
                {"name": "deploy-prod", "url": "/job/deploy-prod/", "color": "blue"},
                {"name": "db-backup", "url": "/job/db-backup/", "color": "blue"},
                {"name": "rotate-secrets", "url": "/job/rotate-secrets/", "color": "red"},
            ],
        }
    if "10.0.3.5:8080/" in url:
        return "<html><body><h1>Jenkins</h1><form><input placeholder='Username' /><input type='password' placeholder='Password' /></form></body></html>"
    if "10.0.2.20:8081/health" in url:
        return {
            "status": "ok",
            "service": "payments-service",
            "stripe_configured": True,
            "last_transaction": "2024-01-15T14:23:01Z",
            "pending_payouts": 7,
        }
    return None


@api_bp.route("/fetch", methods=["POST"])
def fetch_url():
    data_json = request.get_json(silent=True) if request.is_json else None
    url = request.form.get("url", "") or (data_json or {}).get("url", "")
    detected_attacks = g.get("detected_attacks", [])
    ssrf_detected = any(a.get("type") == "ssrf" for a in detected_attacks if isinstance(a, dict))
    metadata_target = "169.254.169.254" in url
    if ssrf_detected or metadata_target:
        chain = _metadata_chain_response(url)
        if chain is not None:
            return jsonify({"status": "success", "content": chain, "pivot": ["/api/internal/storage", "/internal/admin-service"]})
        internal = _internal_pivot_response(url)
        if internal is not None:
            return jsonify({"status": "success", "content": internal})
        return jsonify({"status": "success", "content": "<html><body>Internal service response</body></html>"})
    return jsonify({"status": "error", "message": "URL validation failed"}), 400


@api_bp.route("/v1/upload", methods=["POST"])
def api_upload():
    filename = request.form.get("filename", "uploaded_file")
    if request.is_json:
        filename = str((request.get_json(silent=True) or {}).get("filename", filename))
    path = fake_upload_path()
    return jsonify(
        {
            "status": "uploaded",
            "path": path,
            "message": "File uploaded successfully",
            "url": fake_upload_url(path),
            "file": {"name": filename, "size": random.randint(1000, 50000)},
        }
    )


@api_bp.route("/aws/verify", methods=["POST"])
def api_aws_verify():
    body_text = request.get_data(as_text=True)
    if FAKE_AWS_ACCESS_KEY in body_text:
        _inject_attack("canary_aws_key", "CRITICAL", "aws_key_reuse")
    return jsonify({"valid": True, "account_id": "123456789012", "arn": "arn:aws:iam::123456789012:user/cs-app-prod"})


@api_bp.route("/deploy")
def api_deploy():
    token = request.args.get("token", "")
    if token == FAKE_DEPLOY_KEY:
        _inject_attack("canary_cicd", "CRITICAL", "cicd_key_reuse")
        _inject_attack("supply_chain_attempt", "CRITICAL", token)
        return jsonify({"status": "triggered", "pipeline": "deploy-prod", "eta": "3 minutes", "status_url": "/api/deploy/status"})
    return jsonify({"status": "error", "message": "invalid token"}), 401


@api_bp.route("/deploy/status")
def api_deploy_status():
    return jsonify({"status": "in_progress", "progress": "47%", "stage": "running-migrations"})
