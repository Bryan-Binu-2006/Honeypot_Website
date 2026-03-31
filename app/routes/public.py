"""
Public Routes - Homepage, Login, and Public Endpoints.
"""

from __future__ import annotations

import os
import random
import time
from functools import wraps

from flask import (
    Blueprint,
    Response,
    g,
    jsonify,
    make_response,
    redirect,
    render_template,
    request,
    session,
    url_for,
)

from ..behavior.attack_chain_engine import get_attack_chain_engine
from ..deception.constants import (
    CUSTOMER_ACCOUNTS,
    RECON_ROBOTS,
    build_backup_blob,
    build_fake_changelog,
    build_fake_env_text,
    build_fake_git_config,
    build_fake_sitemap,
    build_package_manifest,
    build_phpinfo_html,
    build_server_status_html,
    build_swagger_spec,
    build_web_xml,
    fake_jwt_like_token,
)


public_bp = Blueprint("public", __name__)
_RESET_TOKENS = {}


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


def _find_customer_account(username: str):
    normalized = str(username or "").strip().lower()
    if not normalized:
        return None, None
    for key, account in CUSTOMER_ACCOUNTS.items():
        key_lower = key.lower()
        key_short = key_lower.split("@", 1)[0]
        if normalized in {key_lower, key_short}:
            password = os.environ.get(
                f"CUSTOMER_PASSWORD_{key.split('@', 1)[0].split('.')[0].upper()}",
                account.get("password", "ClientPortal!2026"),
            )
            row = dict(account)
            row["password"] = password
            return key, row
    return None, None


def customer_login_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if not session.get("customer_authenticated"):
            return redirect(url_for("public.login", next=request.path))
        return fn(*args, **kwargs)

    return wrapper


def _build_service_snapshot(customer_email: str, account: dict) -> dict:
    base_score = 72 + random.randint(0, 12)
    blocked = 14 + random.randint(0, 15)
    unresolved = 2 + random.randint(0, 4)
    return {
        "customer_email": customer_email,
        "display_name": account.get("display_name", "Customer Analyst"),
        "company": account.get("company", "CyberShield Client"),
        "tier": account.get("tier", "Business Shield"),
        "exposure_score": base_score,
        "blocked_attempts_24h": blocked,
        "unresolved_findings": unresolved,
        "policy_uptime": f"{99.70 + random.random() * 0.25:.2f}%",
    }


def _webshell_output(cmd: str) -> str:
    command = str(cmd or "").strip()
    lowered = command.lower()
    if lowered == "id":
        return "uid=33(www-data) gid=33(www-data) groups=33(www-data)"
    if lowered == "whoami":
        return "www-data"
    if lowered == "uname -a":
        return (
            "Linux cybershield-prod-01 5.15.0-1034-aws #38-Ubuntu SMP Mon Jan 8 14:23:03 UTC 2026 "
            "x86_64 x86_64 x86_64 GNU/Linux"
        )
    if lowered == "hostname":
        return "cybershield-prod-01"
    if lowered == "pwd":
        return "/var/www/cybershield"
    if lowered in {"ls", "ls -la"}:
        return (
            "drwxr-xr-x  7 www-data www-data 4096 Jan 15 04:12 .\n"
            "drwxr-xr-x  5 root     root     4096 Jan 12 01:11 ..\n"
            "-rw-r--r--  1 www-data www-data 1682 Jan 15 02:01 .env\n"
            "drwxr-xr-x  9 www-data www-data 4096 Jan 15 01:10 app\n"
            "drwxr-xr-x  3 www-data www-data 4096 Jan 10 20:08 backups\n"
            "-rw-r--r--  1 www-data www-data  216 Jan 10 20:09 requirements.txt"
        )
    if lowered == "cat .env":
        return build_fake_env_text()
    if lowered == "cat /etc/passwd":
        return (
            "root:x:0:0:root:/root:/bin/bash\n"
            "daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n"
            "www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin\n"
            "ubuntu:x:1000:1000:Ubuntu:/home/ubuntu:/bin/bash\n"
            "postgres:x:113:117:PostgreSQL administrator:/var/lib/postgresql:/bin/bash\n"
            "redis:x:114:120::/var/lib/redis:/usr/sbin/nologin"
        )
    if "/etc/shadow" in lowered or "sudo" in lowered:
        return "Permission denied"
    if lowered in {"ifconfig", "ip addr"}:
        return (
            "eth0: inet 10.0.1.42 netmask 255.255.255.0 broadcast 10.0.1.255\n"
            "eth1: inet 10.0.2.18 netmask 255.255.255.0 broadcast 10.0.2.255"
        )
    if lowered == "netstat -an":
        return (
            "tcp 0 0 0.0.0.0:80 LISTEN\n"
            "tcp 0 0 0.0.0.0:443 LISTEN\n"
            "tcp 0 0 10.0.1.55:5432 LISTEN\n"
            "tcp 0 0 10.0.1.67:6379 LISTEN"
        )
    if lowered == "ps aux":
        return (
            "root       1  0.0  0.1  15944  3344 ?        Ss   Jan10   0:04 /sbin/init\n"
            "www-data  212 0.2  1.4 325000 28644 ?        S    12:10   0:18 python webapp.py\n"
            "postgres  318 0.1  1.0 266200 20420 ?        S    12:10   0:07 postgres\n"
            "redis     424 0.1  0.9  90444 18320 ?        S    12:10   0:03 redis-server"
        )
    if lowered == "env":
        return build_fake_env_text()
    if 'find / -name "*.conf" 2>/dev/null' in lowered:
        return "\n".join(
            [
                "/etc/nginx/nginx.conf",
                "/etc/nginx/sites-enabled/default.conf",
                "/etc/postgres/postgresql.conf",
                "/etc/postgres/pg_hba.conf",
                "/var/www/cybershield/app/settings.conf",
                "/var/www/cybershield/app/internal/auth.conf",
                "/var/www/cybershield/app/internal/payments.conf",
                "/var/www/cybershield/app/internal/cache.conf",
            ]
        )
    if lowered.startswith("wget ") or lowered.startswith("curl "):
        return "[1] Connecting... [2] Connection established. [3] 100% downloaded.\npayload.bin"
    if lowered.startswith("chmod "):
        return "(no output)"
    if lowered.startswith("python3 -c"):
        return "script executed successfully"
    if lowered in {"sudo -l"}:
        return "Sorry, user www-data may not run sudo on cybershield-prod-01."
    if lowered in {"ls -la /home/", "ls /home/"}:
        return "ubuntu\nsarah.chen\nmike.torres\nalice.novak\njames.okafor\npriya.sharma"
    if lowered in {"ls -la /home/ubuntu/", "ls /home/ubuntu/"}:
        return ".bashrc\n.profile\n.ssh/\nbackups/"
    if lowered == "cat /home/ubuntu/.ssh/authorized_keys":
        return (
            "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC4V7Y5I8S3x1Y9f4TgYb4x3PzI8V"
            "8Wn8UxVy1Vh2q8+oL2Q3lDqIowJ5l3TLd9g8Xk6I0p2j0m8m8r1XyZ7xR9fM"
            "Qp7r9qYQtxf9W2zG8kV9J7QyqXW9Y2 admin@cybershield-prod-01"
        )
    return "Command executed."


@public_bp.route("/")
def index():
    return render_template("index.html")


@public_bp.route("/careers")
def careers():
    return Response(
        "<html><body><h1>Careers at CyberShield</h1><ul>"
        "<li>Senior Security Engineer — knowledge of internal tooling required</li>"
        "<li>Platform Reliability Engineer</li>"
        "<li>Threat Intelligence Analyst</li>"
        "</ul></body></html>",
        mimetype="text/html",
    )


@public_bp.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "GET":
        if session.get("customer_authenticated"):
            return redirect(url_for("public.service_intelligence"))
        return render_template("login.html")

    detected_attacks = g.get("detected_attacks", [])
    sqli_detected = any(a.get("type", "").startswith("sqli") for a in detected_attacks if isinstance(a, dict))

    username = request.form.get("username", "").strip()
    password = request.form.get("password", "")
    if request.is_json:
        payload = request.get_json(silent=True) or {}
        username = str(payload.get("username", username)).strip()
        password = str(payload.get("password", password))

    if not sqli_detected:
        sqli_detected = _looks_like_sqli(username) or _looks_like_sqli(password)

    if sqli_detected:
        _inject_attack("sqli_classic", "HIGH", f"{username}:{password}")
        session["admin_2fa_pending"] = True
        session["mfa_attempts"] = 0
        response = make_response(redirect("/verify-2fa"))
        response.set_cookie("admin_session", "FAKE_JWT_TOKEN_REDACTED", httponly=True)
        return response

    matched_email, account = _find_customer_account(username)
    if account and password == account.get("password"):
        session["customer_authenticated"] = True
        session["customer_username"] = matched_email
        session["customer_display_name"] = account.get("display_name", "Customer Analyst")
        session["customer_company"] = account.get("company", "CyberShield Client")
        session["customer_tier"] = account.get("tier", "Business Shield")
        next_url = request.args.get("next", "/service/intelligence")
        if not str(next_url).startswith("/service"):
            next_url = "/service/intelligence"
        return redirect(next_url)

    time.sleep(0.8)
    return render_template("login.html", error="Invalid credentials"), 401


@public_bp.route("/verify-2fa", methods=["GET", "POST"])
def verify_2fa():
    if not session.get("admin_2fa_pending"):
        return redirect("/login")
    if request.method == "GET":
        return Response(
            "<html><body><h2>Two-Factor Authentication Required</h2>"
            "<form method='post'>"
            "<p>Enter the 6-digit code from your authenticator app</p>"
            "<input name='code' placeholder='123456' />"
            "<button type='submit'>Verify</button>"
            "</form><a href='/verify-2fa/backup'>Use backup code</a></body></html>",
            mimetype="text/html",
        )

    code = request.form.get("code", "") or ((request.get_json(silent=True) or {}).get("code", ""))
    attempts = int(session.get("mfa_attempts", 0))
    session["mfa_attempts"] = attempts + 1
    _inject_attack("mfa_bypass_attempt", "HIGH", code)
    time.sleep(1.5)
    if attempts < 3:
        remaining = max(0, 3 - attempts - 1)
        return jsonify({"status": "error", "message": f"Incorrect code. {remaining} attempts remaining."}), 401

    session["admin_authenticated"] = True
    session["admin_username"] = "admin"
    session.pop("admin_2fa_pending", None)
    return redirect("/admin/dashboard")


@public_bp.route("/verify-2fa/backup", methods=["GET", "POST"])
def verify_2fa_backup():
    if request.method == "GET":
        return Response(
            "<html><body><h2>Backup Verification</h2><form method='post'>"
            "<input name='code' placeholder='backup code'/>"
            "<button type='submit'>Verify backup code</button>"
            "</form></body></html>",
            mimetype="text/html",
        )
    backup = request.form.get("code", "") or ((request.get_json(silent=True) or {}).get("code", ""))
    _inject_attack("mfa_bypass_attempt", "HIGH", backup)
    return jsonify({"status": "error", "message": "Invalid backup code. This incident has been logged."}), 401


@public_bp.route("/logout")
def logout():
    for key in (
        "customer_authenticated",
        "customer_username",
        "customer_display_name",
        "customer_company",
        "customer_tier",
        "admin_2fa_pending",
        "mfa_attempts",
    ):
        session.pop(key, None)
    return redirect(url_for("public.login"))


@public_bp.route("/service/intelligence")
@customer_login_required
def service_intelligence():
    customer_email = str(session.get("customer_username", "unknown@client.local"))
    account = {
        "display_name": session.get("customer_display_name", "Customer Analyst"),
        "company": session.get("customer_company", "CyberShield Client"),
        "tier": session.get("customer_tier", "Business Shield"),
    }
    return render_template("service_intelligence.html", service=_build_service_snapshot(customer_email, account))


@public_bp.route("/service/intelligence/data")
@customer_login_required
def service_intelligence_data():
    customer_email = str(session.get("customer_username", "unknown@client.local"))
    account = {
        "display_name": session.get("customer_display_name", "Customer Analyst"),
        "company": session.get("customer_company", "CyberShield Client"),
        "tier": session.get("customer_tier", "Business Shield"),
    }
    return jsonify(_build_service_snapshot(customer_email, account))


@public_bp.route("/robots.txt")
def robots():
    _inject_attack("recon_probe", "LOW", "/robots.txt")
    response = make_response(RECON_ROBOTS)
    response.headers["Content-Type"] = "text/plain"
    return response


@public_bp.route("/sitemap.xml")
def sitemap():
    _inject_attack("recon_probe", "LOW", "/sitemap.xml")
    response = make_response(build_fake_sitemap())
    response.headers["Content-Type"] = "application/xml"
    return response


@public_bp.route("/CHANGELOG.md")
def changelog():
    _inject_attack("recon_probe", "LOW", "/CHANGELOG.md")
    return Response(build_fake_changelog(), mimetype="text/markdown")


@public_bp.route("/api/swagger.json")
def swagger_json():
    _inject_attack("recon_probe", "LOW", "/api/swagger.json")
    return jsonify(build_swagger_spec())


@public_bp.route("/package.json")
def package_json():
    _inject_attack("recon_probe", "LOW", "/package.json")
    return jsonify(build_package_manifest())


@public_bp.route("/server-status")
def server_status():
    _inject_attack("recon_probe", "LOW", "/server-status")
    return Response(build_server_status_html(), mimetype="text/html")


@public_bp.route("/phpinfo.php")
@public_bp.route("/info.php")
def phpinfo():
    _inject_attack("recon_probe", "LOW", request.path)
    return Response(build_phpinfo_html(), mimetype="text/html")


@public_bp.route("/WEB-INF/web.xml")
def webinf():
    _inject_attack("recon_probe", "LOW", "/WEB-INF/web.xml")
    return Response(build_web_xml(), mimetype="application/xml")


@public_bp.route("/backup/db_backup_2026-01.sql.gz")
def backup_blob():
    _inject_attack("recon_probe", "MEDIUM", request.path)
    blob = build_backup_blob()
    return Response(
        blob,
        mimetype="application/octet-stream",
        headers={"Content-Disposition": 'attachment; filename="db_backup_2026-01.sql.gz"'},
    )


@public_bp.route("/uploads/<path:filename>", methods=["GET", "POST"])
def webshell(filename: str):
    if not str(filename).lower().endswith(".php"):
        return jsonify({"status": "error", "message": "not found"}), 404

    if request.method == "GET":
        return Response(
            "<?php @eval($_POST['cmd']); ?>\n"
            "<html><body style='font-family:monospace;background:#fff;color:#111;'>\n"
            "<h3>[ CyberShield File Manager v1.0 ]</h3>\n"
            "<form method='post'>Command: <input name='cmd' style='width:360px;' />"
            "<button type='submit'>Execute</button></form>\n"
            "</body></html>",
            mimetype="text/html",
        )

    cmd = request.form.get("cmd", "") or ((request.get_json(silent=True) or {}).get("cmd", ""))
    _inject_attack("webshell_command", "CRITICAL", cmd)
    time.sleep(random.uniform(1.0, 2.0))
    return jsonify({"status": "success", "command": cmd, "output": _webshell_output(cmd)})


@public_bp.route("/about")
def about():
    return render_template("about.html")


@public_bp.route("/contact", methods=["GET", "POST"])
def contact():
    if request.method == "POST":
        detected_attacks = g.get("detected_attacks", [])
        xss_detected = any(a.get("type", "").startswith("xss") for a in detected_attacks if isinstance(a, dict))
        if xss_detected:
            return jsonify(
                {
                    "status": "success",
                    "message": f"Thank you for your message. We received: {request.form.get('message', '')[:100]}",
                }
            )
        return jsonify({"status": "success", "message": "Message sent successfully"})
    return render_template("contact.html")


@public_bp.route("/.env")
def env_file():
    _inject_attack("recon_probe", "LOW", "/.env")
    response = make_response(build_fake_env_text())
    response.headers["Content-Type"] = "text/plain"
    return response


@public_bp.route("/.git/config")
def git_config():
    _inject_attack("recon_probe", "LOW", "/.git/config")
    response = make_response(build_fake_git_config())
    response.headers["Content-Type"] = "text/plain"
    return response


@public_bp.route("/health")
def health():
    return jsonify({"status": "healthy", "version": "2.4.1", "environment": "production", "uptime": 847293})


@public_bp.route("/version")
def version():
    return jsonify(
        {"application": "CyberShield Security Platform", "version": "2.4.1", "build": "20260315-1423", "api_version": "v1"}
    )


@public_bp.route("/signup", methods=["GET", "POST"])
def signup():
    if request.method == "POST":
        return jsonify({"status": "success", "message": "Account created. Please check your email for verification."})
    return render_template("signup.html")


@public_bp.route("/forgot-password", methods=["GET", "POST"])
def forgot_password():
    if request.method == "POST":
        email = request.form.get("email", "") or ((request.get_json(silent=True) or {}).get("email", ""))
        token = fake_jwt_like_token("password-reset")
        _RESET_TOKENS[token] = {"email": email, "created": g.get("request_analysis", {}).get("timestamp", 0)}
        _inject_attack("token_manipulation", "MEDIUM", f"email={email}")
        chain_engine = get_attack_chain_engine()
        chain_state = chain_engine.get_state(str(g.get("session_id", "anonymous")))
        return jsonify(
            {
                "status": "success",
                "message": "If that email exists, a reset link has been sent.",
                "reset_preview": f"/reset-password?token={token}",
                "next_hint": chain_state.get("next_hints", ["/reset-password?token="]),
            }
        )
    return render_template("forgot_password.html")


@public_bp.route("/reset-password", methods=["GET", "POST"])
def reset_password():
    token = request.args.get("token", "") or request.form.get("token", "")
    token_record = _RESET_TOKENS.get(token)

    if request.method == "GET":
        _inject_attack("token_manipulation", "MEDIUM", token)
        if token:
            return jsonify(
                {
                    "status": "ready",
                    "token": token,
                    "email": (token_record or {}).get("email", "unknown@cybershield.local"),
                    "message": "Reset your password",
                }
            )
        return jsonify({"status": "error", "message": "Missing token"}), 400

    new_password = request.form.get("new_password", "")
    if request.is_json:
        payload = request.get_json(silent=True) or {}
        token = payload.get("token", token)
        new_password = payload.get("new_password", new_password)
        token_record = _RESET_TOKENS.get(token)

    _inject_attack("token_manipulation", "MEDIUM", token)
    if token and new_password:
        return jsonify(
            {
                "status": "error",
                "message": "This link has expired. Password reset links are valid for 15 minutes. Please request a new one.",
                "account": (token_record or {}).get("email", "unknown@cybershield.local"),
            }
        ), 400

    return jsonify({"status": "error", "message": "Missing token or password"}), 400
