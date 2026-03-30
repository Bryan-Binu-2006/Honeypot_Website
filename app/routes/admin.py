"""
Admin Routes - Admin panel deception surfaces.
"""

from __future__ import annotations

import random
import string
import time

from flask import Blueprint, Response, g, jsonify, make_response, redirect, render_template, request, session, url_for

from ..deception.constants import (
    ADMIN_PASSWORD,
    ADMIN_USERNAME,
    FAKE_ADMIN_API_KEY,
    FAKE_AWS_ACCESS_KEY,
    FAKE_AWS_SECRET_KEY,
    FAKE_AWS_REGION,
    FAKE_DB_NAME,
    FAKE_DB_PASSWORD,
    FAKE_DB_USER,
    FAKE_EMPLOYEES,
    FAKE_INTERNAL_API_KEY,
    FAKE_JWT_SECRET,
    FAKE_REDIS_PASSWORD,
    FAKE_SENDGRID_KEY,
    FAKE_STRIPE_KEY,
    build_env_map,
    fake_users,
    rate_limit_reset_ts,
)


admin_bp = Blueprint("admin", __name__)

FAKE_USERS = fake_users(50)
FAKE_API_KEYS = [
    {
        "id": "key_1",
        "name": "Production API",
        "key": "cs_prod_" + "".join(random.choices(string.ascii_letters + string.digits, k=32)),
        "created": "2024-01-15",
        "last_used": "2024-03-15",
    },
    {
        "id": "key_2",
        "name": "Staging API",
        "key": "cs_stag_" + "".join(random.choices(string.ascii_letters + string.digits, k=32)),
        "created": "2024-02-20",
        "last_used": "2024-03-10",
    },
    {
        "id": "key_3",
        "name": "Development API",
        "key": "cs_dev_" + "".join(random.choices(string.ascii_letters + string.digits, k=32)),
        "created": "2024-03-01",
        "last_used": "2024-03-14",
    },
]


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


def _looks_like_sqli(value: str) -> bool:
    lowered = str(value or "").lower()
    markers = ["' or '", " or 1=1", "union select", "--", "/*", "sleep(", "benchmark(", "drop table"]
    return any(marker in lowered for marker in markers)


def _rate_limit_headers(response):
    response.headers["X-RateLimit-Limit"] = "100"
    response.headers["X-RateLimit-Remaining"] = "12"
    response.headers["X-RateLimit-Reset"] = rate_limit_reset_ts()
    return response


def _is_juicy_endpoint_delay(delay_ms: int) -> None:
    if delay_ms <= 0:
        return
    if str(session.get("flask_env", "production")).lower() == "production":
        time.sleep(delay_ms / 1000.0)


@admin_bp.before_request
def require_admin_login():
    allowed = {"admin.admin_login", "admin.admin_logout", "admin.admin_unlock"}
    if request.endpoint in allowed:
        return None
    if request.path.rstrip("/") in {"/admin/login", "/admin/unlock"}:
        return None
    if not session.get("admin_authenticated"):
        return redirect(url_for("admin.admin_login", next=request.path))
    return None


@admin_bp.route("/login", methods=["GET", "POST"])
def admin_login():
    if request.method == "GET":
        return render_template("admin/login.html")

    username = request.form.get("username", "").strip()
    password = request.form.get("password", "")
    if request.is_json:
        payload = request.get_json(silent=True) or {}
        username = str(payload.get("username", username)).strip()
        password = str(payload.get("password", password))

    detected_attacks = g.get("detected_attacks", [])
    sqli_detected = any(str(a.get("type", "")).startswith("sqli") for a in detected_attacks if isinstance(a, dict))
    if not sqli_detected:
        sqli_detected = _looks_like_sqli(username) or _looks_like_sqli(password)

    credential_match = username.lower() == ADMIN_USERNAME.lower() and password == ADMIN_PASSWORD

    if sqli_detected:
        _inject_attack("sqli_classic", "HIGH", f"{username}:{password}")
        session["admin_2fa_pending"] = True
        session["mfa_attempts"] = 0
        return redirect("/verify-2fa")

    if credential_match:
        session["admin_authenticated"] = True
        session["admin_username"] = username or "admin"
        session["admin_login_failures"] = 0
        next_url = request.args.get("next", "/admin/dashboard")
        if not str(next_url).startswith("/admin"):
            next_url = "/admin/dashboard"
        return redirect(next_url)

    failures = int(session.get("admin_login_failures", 0)) + 1
    session["admin_login_failures"] = failures
    if failures >= 5:
        return (
            render_template(
                "admin/login.html",
                error=(
                    "Account locked for 10 minutes due to too many failed attempts. "
                    "Unlock via email or contact admin@cybershield.io"
                ),
                username=username,
            ),
            401,
        )
    return render_template("admin/login.html", error="Invalid credentials", username=username), 401


@admin_bp.route("/unlock")
def admin_unlock():
    token = request.args.get("token", "")
    _inject_attack("admin_lockout_bypass_attempt", "CRITICAL", token)
    return Response(
        "This unlock token has expired. A new one has been sent to a.novak@cybershield.io",
        mimetype="text/plain",
    )


@admin_bp.route("/logout")
def admin_logout():
    session.pop("admin_authenticated", None)
    session.pop("admin_username", None)
    return redirect(url_for("admin.admin_login"))


@admin_bp.route("/")
@admin_bp.route("/dashboard")
def dashboard():
    stats = {
        "total_users": 1247,
        "active_sessions": 89,
        "api_calls_today": 45672,
        "revenue_mtd": 127450.00,
        "alerts": 3,
        "pending_tasks": 12,
    }
    recent_activity = [
        {"time": "10:23:45", "user": "admin", "action": "Login", "ip": "192.168.1.100"},
        {"time": "10:15:22", "user": "john.doe", "action": "API Key Generated", "ip": "10.0.0.45"},
        {"time": "09:45:18", "user": "system", "action": "Backup Completed", "ip": "localhost"},
        {"time": "09:30:00", "user": "jane.smith", "action": "Config Updated", "ip": "10.0.0.67"},
    ]
    return render_template(
        "admin/dashboard.html",
        stats=stats,
        activity=recent_activity,
        security_alert=(
            "Security Alert: 3 failed login attempts detected on your account from "
            "185.220.101.x (Tor exit node) at 14:32 UTC. Not you? Review activity."
        ),
        last_login="Previous session: 2 hours ago from 10.0.1.1 (internal) — Review",
    )


@admin_bp.route("/users")
def users():
    resp = make_response(render_template("admin/users.html", users=FAKE_USERS))
    return _rate_limit_headers(resp)


@admin_bp.route("/users/<int:user_id>")
def user_detail(user_id):
    user = next((u for u in FAKE_USERS if int(u.get("id", -1)) == user_id), None)
    if not user:
        user = {
            "id": user_id,
            "username": f"user_{user_id}",
            "email": f"user{user_id}@cybershield.io",
            "role": "user",
            "last_login": "2024-03-10 12:00:00",
            "phone": "+1-555-" + str(user_id).zfill(4)[-4:],
            "address": f"{user_id * 10} Fake Street",
            "ssn_last_four": str(user_id * 1234)[-4:],
            "api_key": "cs_user_" + "".join(random.choices(string.ascii_letters, k=24)),
        }
    resp = make_response(render_template("admin/user_detail.html", user=user))
    return _rate_limit_headers(resp)


@admin_bp.route("/api-keys")
def api_keys():
    return render_template("admin/api_keys.html", keys=FAKE_API_KEYS)


@admin_bp.route("/api-keys/create", methods=["POST"])
def create_api_key():
    name = request.form.get("name", "New Key")
    new_key = {
        "id": f"key_{len(FAKE_API_KEYS) + 1}",
        "name": name,
        "key": "cs_new_" + "".join(random.choices(string.ascii_letters + string.digits, k=32)),
        "created": "2024-03-15",
        "last_used": "Never",
    }
    return jsonify({"status": "success", "key": new_key})


@admin_bp.route("/api-keys/validate", methods=["POST"])
def validate_api_key():
    key = request.form.get("key", "")
    if request.is_json:
        payload = request.get_json(silent=True) or {}
        key = payload.get("key", key)
    key_lower = str(key).lower()
    if "adminkey" in key_lower or "cs_admin" in key_lower or FAKE_INTERNAL_API_KEY in key_lower:
        return jsonify(
            {
                "status": "success",
                "scope": ["admin:*", "vault:read", "db:read"],
                "next": [f"/internal/admin-service?x-internal-key={FAKE_INTERNAL_API_KEY}"],
            }
        )
    return jsonify({"status": "error", "message": "invalid key"}), 401


@admin_bp.route("/wallet")
def wallet():
    wallets = {
        "eth": {
            "address_hot": "0x742d35Cc6634C0532925a3b844Bc9e7595f12345",
            "address_cold": "0x8f39f19f2f5f055d8ac95ca0fbb3fb16d5f4a212",
            "balance": 14.7231,
            "usd_value": 47000.00,
        }
    }
    transactions = [
        {"date": "2024-03-14", "type": "Sent", "amount": "0.8 ETH", "to": "contractor payout"},
        {"date": "2024-03-12", "type": "Sent", "amount": "0.5 ETH", "to": "unknown address — investigation pending"},
        {"date": "2024-03-10", "type": "Sent", "amount": "1.2 ETH", "to": "Q1 bug bounty payout — do not discuss externally"},
    ]
    return render_template("admin/wallet.html", wallets=wallets, transactions=transactions)


@admin_bp.route("/wallet/transactions")
def wallet_transactions():
    ledger = []
    for i in range(40):
        emp = FAKE_EMPLOYEES[i % len(FAKE_EMPLOYEES)]
        note = "Contractor payout"
        if i == 4:
            note = "Q1 bug bounty payout — do not discuss externally"
        if i == 7:
            note = "0.5 ETH to unknown address — investigation pending"
        ledger.append(
            {
                "tx": f"0xabc{100 + i}",
                "asset": "ETH",
                "amount": round(random.uniform(0.05, 1.4), 4),
                "to": emp["name"],
                "note": note,
            }
        )
    return jsonify({"status": "success", "ledger": ledger})


@admin_bp.route("/wallet/withdraw", methods=["POST"])
def wallet_withdraw():
    _inject_attack("crypto_theft_attempt", "CRITICAL", request.get_data(as_text=True))
    _is_juicy_endpoint_delay(3000)
    return jsonify(
        {
            "status": "pending_compliance",
            "message": (
                "Withdrawal of 14.72 ETH initiated. Pending automated compliance review (2-4 hours). "
                "A confirmation will be sent to j.okafor@cybershield.io."
            ),
            "transaction_id": "tx_pending_a9f3c2b1",
        }
    )


@admin_bp.route("/config")
def config():
    config_data = {
        "database": {"host": "db.internal.cybershield.io", "port": 5432, "name": FAKE_DB_NAME, "user": FAKE_DB_USER, "password": "********"},
        "redis": {"host": "cache.internal.cybershield.io", "port": 6379, "password": "********"},
        "aws": {"region": FAKE_AWS_REGION, "bucket": "cybershield-production", "access_key": "REDACTED", "secret_key": "********"},
        "jwt": {"algorithm": "HS256", "expiry": 3600, "secret": "********"},
    }
    return render_template("admin/config.html", config=config_data)


@admin_bp.route("/config/export")
def config_export():
    _is_juicy_endpoint_delay(3000)
    full_config = {
        "database": {"host": "db.internal.cybershield.io", "port": 5432, "name": FAKE_DB_NAME, "user": FAKE_DB_USER, "password": FAKE_DB_PASSWORD},
        "redis": {"host": "cache.internal.cybershield.io", "port": 6379, "password": FAKE_REDIS_PASSWORD},
        "aws": {"region": FAKE_AWS_REGION, "access_key": FAKE_AWS_ACCESS_KEY, "secret_key": FAKE_AWS_SECRET_KEY},
        "jwt": {"algorithm": "HS256", "expiry": 3600, "secret": FAKE_JWT_SECRET},
        "services": {"stripe_key": FAKE_STRIPE_KEY, "sendgrid_key": FAKE_SENDGRID_KEY, "admin_api_key": FAKE_ADMIN_API_KEY},
        "all_env": build_env_map(),
    }
    return Response(
        jsonify(full_config).get_data(as_text=False),
        mimetype="application/json",
        headers={"Content-Disposition": 'attachment; filename="cybershield-config-export-2024-01-15.json"'},
    )


@admin_bp.route("/debug")
def debug():
    debug_info = {
        "server_time": time.strftime("%Y-%m-%d %H:%M:%S"),
        "python_version": "3.9.7",
        "flask_version": "3.0.0",
        "environment": "production",
        "debug_mode": False,
        "memory_usage": "245 MB",
        "cpu_usage": "12%",
        "active_connections": 89,
        "cache_size": "1.2 GB",
    }
    return render_template("admin/debug.html", debug_info=debug_info)


@admin_bp.route("/debug/config")
def debug_config_export():
    return jsonify(
        {
            "status": "success",
            "debug_mode": False,
            "jwt": {"algorithm": "HS256", "weak_secret": FAKE_JWT_SECRET, "example_forged_token": "Bearer forged_admin_token"},
            "internal_keys": {"admin_service_key": FAKE_INTERNAL_API_KEY, "storage_read_key": "stor_key_1f23b8bb"},
            "next": ["/api/v2/internal/users?token=forged_admin_token", f"/internal/admin-service?x-internal-key={FAKE_INTERNAL_API_KEY}"],
        }
    )


def _fake_subclasses_output() -> str:
    classes = [f"<class 'object_{i}'>" for i in range(1, 301)]
    return "[" + ", ".join(classes) + "]"


@admin_bp.route("/debug/eval", methods=["POST"])
def debug_eval():
    code = request.form.get("code", "")
    if request.is_json:
        code = str((request.get_json(silent=True) or {}).get("code", code))

    _is_juicy_endpoint_delay(2000)
    lowered = code.lower()

    def ssti(out: str):
        _inject_attack("ssti_attempt", "HIGH", code)
        return jsonify({"status": "success", "output": out})

    def rce(out: str):
        _inject_attack("rce_attempt", "CRITICAL", code)
        return jsonify({"status": "success", "output": out})

    if "{{7*7}}" in code or "{{49}}" in code or "7*7" in lowered:
        return ssti("49")
    if "config" in lowered:
        return ssti(str(build_env_map()))
    if "request" in lowered:
        return ssti("<Request 'https://cybershield.io/admin/debug/eval' [POST]>")
    if "join(" in lowered:
        return ssti("".join([c for c in code if c.isalnum()][:64]))
    if "__class__.__mro__" in lowered:
        return ssti("(<class 'str'>, <class 'object'>)")
    if "__subclasses__" in lowered:
        return ssti(_fake_subclasses_output())
    if "import " in lowered or "__import__" in lowered:
        return jsonify({"status": "error", "message": "NameError: name '__import__' is not defined in sandbox"}), 400
    if "subprocess" in lowered or "os.system" in lowered:
        return rce(
            "[Sandbox] Command executed in restricted environment\n"
            "uid=33(www-data) gid=33(www-data) groups=33(www-data)"
        )
    if "open(" in lowered:
        return rce("Permission denied")

    detected_attacks = g.get("detected_attacks", [])
    if any(a.get("type") == "command_injection" for a in detected_attacks):
        return rce("uid=33(www-data) gid=33(www-data) groups=33(www-data)")
    if any(str(a.get("type", "")).startswith("ssti") for a in detected_attacks):
        return ssti("49")
    return jsonify({"status": "error", "message": "Invalid expression"})


@admin_bp.route("/database")
def database():
    tables = [
        {"name": "users", "rows": 2847, "size": "45 MB"},
        {"name": "transactions", "rows": 456789, "size": "892 MB"},
        {"name": "api_keys", "rows": 1289, "size": "12 MB"},
        {"name": "sessions", "rows": 89234, "size": "128 MB"},
        {"name": "audit_log", "rows": 567890, "size": "456 MB"},
        {"name": "config", "rows": 234, "size": "1.2 MB"},
        {"name": "employees", "rows": 93, "size": "4 MB"},
        {"name": "secrets", "rows": 7, "size": "28 KB"},
        {"name": "encryption_keys", "rows": 5, "size": "14 KB"},
    ]
    return render_template("admin/database.html", tables=tables)


def _paginate(rows, page: int, limit: int):
    start = max(0, (page - 1) * limit)
    end = start + limit
    return rows[start:end]


@admin_bp.route("/database/query", methods=["POST"])
def database_query():
    query = request.form.get("query", "")
    if request.is_json:
        query = str((request.get_json(silent=True) or {}).get("query", query))
    q = query.lower()
    page = int(request.args.get("page", "1"))
    limit = int(request.args.get("limit", "10"))

    if "show tables" in q:
        return jsonify({"status": "success", "rows": ["users", "transactions", "api_keys", "sessions", "audit_log", "config", "employees", "secrets", "encryption_keys"]})
    if "select @@version" in q:
        return jsonify({"status": "success", "rows": [["8.0.32-MySQL Community Server"]]})
    if "select user()" in q:
        return jsonify({"status": "success", "rows": [[f"{FAKE_DB_USER}@localhost"]]})
    if "select @@datadir" in q:
        return jsonify({"status": "success", "rows": [["/var/lib/mysql/"]]})
    if "select * from secrets" in q:
        return jsonify({"status": "error", "message": "ERROR 1142: SELECT command denied to user 'cs_app'@'localhost' for table 'secrets'"})
    if "select * from encryption_keys" in q:
        _inject_attack("rce_attempt", "CRITICAL", query)
        return jsonify({"status": "error", "message": "ERROR 1142: SELECT command denied to user 'cs_app'@'localhost' for table 'encryption_keys'"})
    if "drop table" in q or "delete from" in q:
        _inject_attack("rce_attempt", "CRITICAL", query)
        return jsonify({"status": "success", "message": "Query OK, 0 rows affected (0.00 sec)"})
    if "insert into users" in q:
        return jsonify({"status": "success", "message": "Query OK, 1 row inserted"})
    if "select * from employees" in q:
        rows = [{**emp, "salary": 120000 + (idx * 7000)} for idx, emp in enumerate(FAKE_EMPLOYEES)]
        return jsonify({"status": "success", "rows": rows})

    if "select * from transactions" in q:
        tx_rows = [{"id": i + 1, "asset": "ETH", "amount": round(random.uniform(0.04, 2.4), 4)} for i in range(30)]
        return jsonify({"status": "success", "rows": tx_rows})

    if "select * from users" in q or "union select" in q:
        paged = _paginate(FAKE_USERS, page, limit)
        payload = {"status": "success", "rows": paged, "pagination": {"page": page, "limit": limit, "total": len(FAKE_USERS)}}
        resp = jsonify(payload)
        return _rate_limit_headers(resp)

    return jsonify({"status": "success", "columns": ["id", "data"], "rows": [[1, "Query executed successfully"]]})


@admin_bp.route("/database/console")
def database_console():
    query = request.args.get("q", "select id,username,role from users limit 3")
    return jsonify(
        {
            "status": "success",
            "engine": "postgresql 14.9",
            "query": query,
            "rows": [
                {"id": 1, "username": "admin", "role": "administrator"},
                {"id": 7, "username": "svc.sync", "role": "service"},
                {"id": 9, "username": "ops.breakglass", "role": "security"},
            ],
            "next": ["/internal/db?table=employees", "/internal/vault/secrets"],
        }
    )


@admin_bp.route("/logs")
def logs():
    fake_logs = [
        {"timestamp": "2024-01-14 03:47:22", "level": "ALERT", "message": "Unusual login from IP 185.220.101.x (Tor exit node) — user: api_service_account"},
        {"timestamp": "2024-01-14 03:51:09", "level": "INFO", "message": "/api/internal/config accessed — api_service_account"},
        {"timestamp": "2024-01-14 03:52:44", "level": "INFO", "message": "/internal/vault/secrets accessed — api_service_account"},
        {"timestamp": "2024-01-14 03:54:01", "level": "CRITICAL", "message": "Large data export initiated — api_service_account — 2.3GB"},
        {"timestamp": "2024-01-14 03:55:12", "level": "INFO", "message": "Session terminated"},
        {"timestamp": "2024-01-09 11:22:05", "level": "INFO", "message": "JWT secret rotated by a.novak@cybershield.io"},
        {"timestamp": "2024-01-03 08:00:00", "level": "INFO", "message": "Scheduled backup completed — cybershield-backups-private/db_backup_2024-01-03.sql.gz"},
        {"timestamp": "2023-12-28 22:14:55", "level": "WARN", "message": "/admin/debug/eval accessed outside business hours — m.torres@cybershield.io"},
    ]
    return render_template("admin/logs.html", logs=fake_logs)


@admin_bp.route("/settings")
def settings():
    return render_template("admin/settings.html")
