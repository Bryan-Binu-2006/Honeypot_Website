"""
Internal Infrastructure Illusion Routes

Provides chain-gated fake internal systems for deep deception.
"""

from __future__ import annotations

from flask import Blueprint, jsonify, g, request

from ..behavior.attack_chain_engine import get_attack_chain_engine


internal_bp = Blueprint('internal', __name__)


def _session_id() -> str:
    return str(g.get('session_id', 'anonymous'))


def _deny(stage: str, message: str):
    engine = get_attack_chain_engine()
    state = engine.get_state(_session_id())
    return jsonify({
        'status': 'restricted',
        'required_stage': stage,
        'current_stage': state.get('stage', 'recon'),
        'message': message,
        'next_hints': state.get('next_hints', [])
    }), 403


def _stage_gate(required_stage: str, required_scenarios=None):
    engine = get_attack_chain_engine()
    ok, reason = engine.can_access(_session_id(), required_stage, required_scenarios)
    if ok:
        return None
    return _deny(required_stage, reason)


@internal_bp.route('/db')
def internal_db():
    denied = _stage_gate('privilege_escalation')
    if denied:
        return denied

    table = request.args.get('table', 'users').lower()
    rows = {
        'users': [
            {'id': 1, 'username': 'admin', 'role': 'administrator', 'status': 'active'},
            {'id': 2, 'username': 'svc-backup', 'role': 'service', 'status': 'active'},
            {'id': 3, 'username': 'finance.ops', 'role': 'analyst', 'status': 'locked'},
        ],
        'employees': [
            {'email': 'nina.r@cybershield.local', 'password': 'Fall2025!temp', 'dept': 'SecurityOps'},
            {'email': 'liam.p@cybershield.local', 'password': 'RotateMe#24', 'dept': 'Platform'},
            {'email': 'maya.k@cybershield.local', 'password': 'TempReset!998', 'dept': 'Finance'},
        ],
        'api_keys': [
            {'name': 'internal-admin-service', 'key': 'adminkey_int_7fce381d', 'scope': 'admin:*'},
            {'name': 'storage-sync', 'key': 'stor_key_1f23b8bb', 'scope': 'storage:read'},
        ],
    }

    return jsonify({
        'status': 'ok',
        'cluster': 'db-pri-01.internal',
        'table': table,
        'rows': rows.get(table, [{'result': 'table not found, but query leaked connection metadata'}]),
        'next': ['/internal/logs', '/internal/vault/secrets']
    })


@internal_bp.route('/cache')
def internal_cache():
    denied = _stage_gate('privilege_escalation')
    if denied:
        return denied

    return jsonify({
        'status': 'ok',
        'service': 'redis-cache-01',
        'version': '7.2.5',
        'keys': [
            'session:admin:jwt_secret_hint',
            'queue:deploy:pipeline-token',
            'cache:user-profile:8841',
            'canary:shadow-copy:index',
        ],
        'sample_dump': {
            'session:admin:jwt_secret_hint': 'debug-weak-secret-2026',
            'queue:deploy:pipeline-token': 'ghp_fake_pipeline_1234567890',
        },
        'next': ['/internal/ci/pipeline', '/internal/admin-service']
    })


@internal_bp.route('/admin-service')
def internal_admin_service():
    denied = _stage_gate('privilege_escalation', ['debug_config_api_key_leak'])
    if denied:
        return denied

    internal_key = request.headers.get('X-Internal-Key', '') or request.args.get('x-internal-key', '')
    if 'adminkey' not in internal_key.lower():
        return jsonify({
            'status': 'denied',
            'message': 'Missing or invalid internal key',
            'hint': 'X-Internal-Key from debug config export',
            'next': ['/admin/debug/config']
        }), 401

    return jsonify({
        'status': 'ok',
        'service': 'admin-service-v2',
        'permissions': ['users:read', 'users:write', 'vault:read', 'logs:read'],
        'shadow_admins': ['svc.root.rotate', 'ops.breakglass'],
        'next': ['/internal/vault/secrets', '/internal/collab/slack']
    })


@internal_bp.route('/logs')
def internal_logs():
    denied = _stage_gate('persistence')
    if denied:
        return denied

    return jsonify({
        'status': 'ok',
        'log_stream': [
            {'ts': '2026-03-26T02:11:12Z', 'service': 'auth', 'msg': 'token downgrade fallback accepted'},
            {'ts': '2026-03-26T02:11:27Z', 'service': 'storage', 'msg': 'signed-url generated for backup bundle'},
            {'ts': '2026-03-26T02:12:06Z', 'service': 'admin-service', 'msg': 'privileged query from 10.42.7.13'},
        ],
        'next': ['/internal/logs/lateral', '/internal/db?table=employees']
    })


@internal_bp.route('/logs/lateral')
def internal_lateral_logs():
    denied = _stage_gate('data_exfiltration')
    if denied:
        return denied

    return jsonify({
        'status': 'ok',
        'movement': [
            {'source': 'web-01', 'target': 'cache-01', 'method': 'stolen service token'},
            {'source': 'cache-01', 'target': 'ci-runner-03', 'method': 'pipeline secret replay'},
            {'source': 'ci-runner-03', 'target': 'vault-01', 'method': 'breakglass role assumption'},
        ],
        'next': ['/internal/vault/secrets', '/internal/collab/slack']
    })


@internal_bp.route('/k8s/dashboard')
def internal_k8s_dashboard():
    denied = _stage_gate('privilege_escalation')
    if denied:
        return denied

    return jsonify({
        'status': 'ok',
        'cluster': 'prod-east-2',
        'namespaces': ['default', 'payments', 'security', 'ops-internal'],
        'pods': [
            'admin-service-6f4f8bc9f9-8x2rp',
            'vault-proxy-59f5bb9489-c4p9m',
            'ci-bridge-7d48bd965d-z1t6x',
        ],
        'next': ['/internal/ci/pipeline', '/internal/admin-service']
    })


@internal_bp.route('/ci/pipeline')
def internal_ci_pipeline():
    denied = _stage_gate('data_exfiltration')
    if denied:
        return denied

    return jsonify({
        'status': 'ok',
        'pipelines': [
            {'id': 1431, 'name': 'deploy-prod', 'token': 'ghp_fake_pipeline_1234567890'},
            {'id': 1432, 'name': 'rotate-secrets', 'token': 'vault_rotator_ci_token'},
        ],
        'artifacts': [
            'build_1431_env_snapshot.tar.gz',
            'deploy_1431_runtime_secrets.json.enc',
        ],
        'next': ['/internal/vault/secrets', '/api/internal/storage']
    })


@internal_bp.route('/collab/slack')
def internal_slack_messages():
    denied = _stage_gate('data_exfiltration')
    if denied:
        return denied

    return jsonify({
        'status': 'ok',
        'channel': '#ops-sev2',
        'messages': [
            {'from': 'ops.lead', 'text': 'Rotate adminkey_int_7fce381d after incident retro.'},
            {'from': 'dev.platform', 'text': 'Temporary creds in /internal/vault/secrets path updated.'},
            {'from': 'sec.analyst', 'text': 'Employee reset list exported to db table employees.'},
        ],
        'next': ['/internal/vault/secrets', '/internal/db?table=employees']
    })


@internal_bp.route('/vault/secrets')
def internal_vault_secrets():
    denied = _stage_gate('data_exfiltration', ['ssrf_internal_storage_access'])
    if denied:
        return denied

    return jsonify({
        'status': 'ok',
        'vault_path': 'secret/prod/cybershield',
        'secrets': {
            'DB_MASTER_PASSWORD': 'ProdDbMaster!Fake!2026',
            'JWT_SIGNING_KEY': 'debug-weak-secret-2026',
            'AWS_BACKUP_ROLE': 'arn:aws:iam::111111111111:role/backup-role',
            'WALLET_HOT_SIGNER': '0xFAKEHOTWALLETSIGNERKEY000111',
        },
        'next': ['/internal/logs', '/internal/db', '/api/internal/storage?file=customers-2026.csv']
    })
