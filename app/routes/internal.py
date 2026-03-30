"""
Internal Infrastructure Illusion Routes.
"""

from __future__ import annotations

from flask import Blueprint, g, jsonify, request

from ..behavior.attack_chain_engine import get_attack_chain_engine
from ..deception.constants import (
    FAKE_AWS_ACCESS_KEY,
    FAKE_AWS_SECRET_KEY,
    FAKE_DB_IP,
    FAKE_DB_PASSWORD,
    FAKE_DEPLOY_KEY,
    FAKE_EMPLOYEES,
    FAKE_GITLAB_TOKEN,
    FAKE_HOSTNAME_PROD,
    FAKE_INTERNAL_API_KEY,
    FAKE_JWT_SECRET,
    FAKE_SERVER_IP_INTERNAL,
    FAKE_SLACK_WEBHOOK,
    FAKE_VAULT_ROOT_TOKEN,
)


internal_bp = Blueprint("internal", __name__)


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


def _session_id() -> str:
    return str(g.get("session_id", "anonymous"))


def _deny(stage: str, message: str):
    engine = get_attack_chain_engine()
    state = engine.get_state(_session_id())
    return jsonify(
        {
            "status": "restricted",
            "required_stage": stage,
            "current_stage": state.get("stage", "recon"),
            "message": message,
            "next_hints": state.get("next_hints", []),
        }
    ), 403


def _stage_gate(required_stage: str, required_scenarios=None):
    engine = get_attack_chain_engine()
    ok, reason = engine.can_access(_session_id(), required_stage, required_scenarios)
    if ok:
        return None
    return _deny(required_stage, reason)


@internal_bp.route("/db")
def internal_db():
    denied = _stage_gate("privilege_escalation")
    if denied:
        return denied
    table = request.args.get("table", "users").lower()
    rows = {
        "users": [
            {"id": 1, "username": "admin", "role": "administrator", "status": "active"},
            {"id": 2, "username": "svc-backup", "role": "service", "status": "active"},
            {"id": 3, "username": "finance.ops", "role": "analyst", "status": "locked"},
        ],
        "employees": [{**e, "salary": 120000 + idx * 7000} for idx, e in enumerate(FAKE_EMPLOYEES)],
        "api_keys": [
            {"name": "internal-admin-service", "key": FAKE_INTERNAL_API_KEY, "scope": "admin:*"},
            {"name": "storage-sync", "key": "stor_key_1f23b8bb", "scope": "storage:read"},
        ],
    }
    return jsonify(
        {
            "status": "ok",
            "cluster": "db-pri-01.internal",
            "table": table,
            "rows": rows.get(table, [{"result": "table not found, but query leaked connection metadata"}]),
            "next": ["/internal/logs", "/internal/vault/secrets"],
        }
    )


@internal_bp.route("/cache")
def internal_cache():
    denied = _stage_gate("privilege_escalation")
    if denied:
        return denied
    return jsonify(
        {
            "status": "ok",
            "service": "redis-cache-01",
            "version": "7.2.5",
            "keys": ["session:admin:jwt_secret_hint", "queue:deploy:pipeline-token", "cache:user-profile:8841", "canary:shadow-copy:index"],
            "sample_dump": {"session:admin:jwt_secret_hint": FAKE_JWT_SECRET, "queue:deploy:pipeline-token": "ghp_fake_pipeline_1234567890"},
            "next": ["/internal/ci/pipeline", "/internal/admin-service"],
        }
    )


@internal_bp.route("/admin-service")
def internal_admin_service():
    denied = _stage_gate("privilege_escalation", ["debug_config_api_key_leak"])
    if denied:
        return denied
    internal_key = request.headers.get("X-Internal-Key", "") or request.args.get("x-internal-key", "")
    if FAKE_INTERNAL_API_KEY not in str(internal_key):
        return jsonify({"status": "denied", "message": "Missing or invalid internal key", "hint": "X-Internal-Key from debug config export", "next": ["/admin/debug/config"]}), 401
    return jsonify(
        {
            "status": "ok",
            "service": "admin-service-v2",
            "permissions": ["users:read", "users:write", "vault:read", "logs:read"],
            "shadow_admins": ["svc.root.rotate", "ops.breakglass"],
            "next": ["/internal/vault/secrets", "/internal/collab/slack"],
        }
    )


@internal_bp.route("/logs")
def internal_logs():
    denied = _stage_gate("persistence")
    if denied:
        return denied
    return jsonify(
        {
            "status": "ok",
            "log_stream": [
                {"ts": "2024-01-14T03:47:22Z", "service": "auth", "msg": "Unusual login from Tor exit node"},
                {"ts": "2024-01-14T03:52:44Z", "service": "vault", "msg": "/internal/vault/secrets accessed"},
                {"ts": "2024-01-14T03:54:01Z", "service": "export", "msg": "Large data export initiated — 2.3GB"},
            ],
            "next": ["/internal/logs/lateral", "/internal/db?table=employees"],
        }
    )


@internal_bp.route("/logs/lateral")
def internal_lateral_logs():
    denied = _stage_gate("data_exfiltration")
    if denied:
        return denied
    return jsonify(
        {
            "status": "ok",
            "movement": [
                {"source": "web-01", "target": "cache-01", "method": "stolen service token"},
                {"source": "cache-01", "target": "ci-runner-03", "method": "pipeline secret replay"},
                {"source": "ci-runner-03", "target": "vault-01", "method": "breakglass role assumption"},
            ],
            "next": ["/internal/collab/slack", "/internal/vault/secrets"],
        }
    )


@internal_bp.route("/k8s/dashboard")
def internal_k8s_dashboard():
    denied = _stage_gate("privilege_escalation")
    if denied:
        return denied
    return jsonify(
        {
            "status": "ok",
            "cluster": "prod-east-2",
            "namespaces": ["default", "payments", "security", "ops-internal"],
            "pods": ["admin-service-6f4f8bc9f9-8x2rp", "vault-proxy-59f5bb9489-c4p9m", "ci-bridge-7d48bd965d-z1t6x"],
            "next": ["/internal/ci/pipeline", "/internal/admin-service"],
        }
    )


@internal_bp.route("/ci/pipeline")
def internal_ci_pipeline():
    denied = _stage_gate("data_exfiltration")
    if denied:
        return denied
    return jsonify(
        {
            "status": "ok",
            "pipelines": [{"id": 1431, "name": "deploy-prod", "token": FAKE_DEPLOY_KEY}, {"id": 1432, "name": "rotate-secrets", "token": FAKE_GITLAB_TOKEN}],
            "artifacts": ["build_1431_env_snapshot.tar.gz", "deploy_1431_runtime_secrets.json.enc"],
            "next": ["/internal/vault/secrets", "/api/internal/storage"],
        }
    )


@internal_bp.route("/collab/slack")
def internal_slack_messages():
    denied = _stage_gate("data_exfiltration")
    if denied:
        return denied
    return jsonify(
        {
            "status": "ok",
            "channel": "#ops-sev2",
            "messages": [
                {"from": "ops.lead", "text": f"Rotate {FAKE_INTERNAL_API_KEY} after incident retro."},
                {"from": "dev.platform", "text": "Temporary creds in /internal/vault/secrets path updated."},
                {"from": "sec.analyst", "text": f"Webhook standby: {FAKE_SLACK_WEBHOOK}"},
            ],
            "next": ["/internal/vault/secrets", "/internal/db?table=employees"],
        }
    )


@internal_bp.route("/vault/secrets")
def internal_vault_secrets():
    denied = _stage_gate("data_exfiltration", ["ssrf_internal_storage_access"])
    if denied:
        return denied
    return jsonify(
        {
            "status": "ok",
            "vault_path": "secret/prod/cybershield",
            "secrets": {
                "DB_MASTER_PASSWORD": FAKE_DB_PASSWORD,
                "JWT_SIGNING_KEY": FAKE_JWT_SECRET,
                "AWS_ACCESS_KEY": FAKE_AWS_ACCESS_KEY,
                "AWS_SECRET_KEY": FAKE_AWS_SECRET_KEY,
                "VAULT_ROOT_TOKEN": FAKE_VAULT_ROOT_TOKEN,
            },
            "next": ["/internal/logs", "/internal/db", "/api/internal/storage?file=customers-2026.csv"],
        }
    )


@internal_bp.route("/vault/read")
def internal_vault_read():
    path = request.args.get("path", "prod/jwt/signing_key")
    token = request.headers.get("X-Vault-Token", "")
    if token == FAKE_VAULT_ROOT_TOKEN:
        _inject_attack("canary_vault", "CRITICAL", "vault_token_reuse")
        return jsonify(
            {
                "request_id": "f7e53c80-3d5d-4b8f-9a21-410289f2cb2a",
                "lease_id": "",
                "renewable": False,
                "lease_duration": 0,
                "data": {
                    "path": path,
                    "jwt_secret": FAKE_JWT_SECRET,
                    "admin_api_key": FAKE_INTERNAL_API_KEY,
                    "db_password": FAKE_DB_PASSWORD,
                },
                "warnings": None,
            }
        )
    return jsonify({"errors": ["permission denied"]}), 403


@internal_bp.route("/network/topology")
def internal_network_topology():
    return jsonify(
        {
            "vpc": "vpc-0a1b2c3d",
            "cidr": "10.0.0.0/16",
            "subnets": {"public": ["10.0.1.0/24"], "private": ["10.0.2.0/24", "10.0.3.0/24"]},
            "hosts": [
                {"ip": "10.0.1.42", "hostname": FAKE_HOSTNAME_PROD, "services": ["http:80", "https:443", "ssh:22"]},
                {"ip": FAKE_DB_IP, "hostname": "db-prod-01", "services": ["postgres:5432"]},
                {"ip": "10.0.1.67", "hostname": "cache-01", "services": ["redis:6379"]},
                {"ip": "10.0.2.10", "hostname": "auth-service", "services": ["grpc:50051", "http:8080"]},
                {"ip": "10.0.2.20", "hostname": "payments-service", "services": ["http:8081"]},
                {"ip": "10.0.2.30", "hostname": "worker-01", "services": ["celery:6555"]},
                {"ip": "10.0.3.5", "hostname": "jenkins-01", "services": ["http:8080"]},
                {"ip": "10.0.3.12", "hostname": "gitlab-internal", "services": ["http:80", "ssh:22"]},
                {"ip": "10.0.3.20", "hostname": "vault-01", "services": ["http:8200"]},
            ],
        }
    )


@internal_bp.route("/api/internal/emergency-access")
def emergency_access():
    if request.args.get("break-glass") == "1":
        _inject_attack("emergency_access", "CRITICAL", request.query_string.decode("utf-8", errors="ignore"))
        return jsonify(
            {
                "status": "ok",
                "document": "Emergency procedure:\n1) Use break-glass creds\n2) Validate source IP\n3) Rotate secrets immediately",
                "internal_ips": [FAKE_SERVER_IP_INTERNAL, FAKE_DB_IP],
            }
        )
    return jsonify({"status": "error", "message": "break-glass flag required"}), 400
