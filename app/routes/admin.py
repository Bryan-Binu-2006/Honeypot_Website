"""
Admin Routes - Admin Panel and Dashboard

Simulates a realistic admin panel with various attack surfaces.

INTERNAL DOCUMENTATION:
- Admin panel is accessible after "successful" SQLi
- Contains API key management, wallet, file explorer
- All actions are tracked and logged
- Fake sensitive data encourages deeper exploration
"""

from flask import Blueprint, render_template, request, jsonify, g, redirect, url_for
import json
import time
import random
import string


admin_bp = Blueprint('admin', __name__)


# Fake admin data
FAKE_USERS = [
    {'id': 1, 'username': 'admin', 'email': 'admin@cybershield.local', 'role': 'administrator', 'last_login': '2024-03-15 10:23:45'},
    {'id': 2, 'username': 'john.doe', 'email': 'john.doe@cybershield.local', 'role': 'analyst', 'last_login': '2024-03-14 18:45:22'},
    {'id': 3, 'username': 'jane.smith', 'email': 'jane.smith@cybershield.local', 'role': 'developer', 'last_login': '2024-03-15 09:12:33'},
    {'id': 4, 'username': 'mike.wilson', 'email': 'mike.wilson@cybershield.local', 'role': 'analyst', 'last_login': '2024-03-13 14:30:00'},
    {'id': 5, 'username': 'sarah.jones', 'email': 'sarah.jones@cybershield.local', 'role': 'manager', 'last_login': '2024-03-15 08:00:00'},
]

FAKE_API_KEYS = [
    {'id': 'key_1', 'name': 'Production API', 'key': 'cs_prod_' + ''.join(random.choices(string.ascii_letters + string.digits, k=32)), 'created': '2024-01-15', 'last_used': '2024-03-15'},
    {'id': 'key_2', 'name': 'Staging API', 'key': 'cs_stag_' + ''.join(random.choices(string.ascii_letters + string.digits, k=32)), 'created': '2024-02-20', 'last_used': '2024-03-10'},
    {'id': 'key_3', 'name': 'Development API', 'key': 'cs_dev_' + ''.join(random.choices(string.ascii_letters + string.digits, k=32)), 'created': '2024-03-01', 'last_used': '2024-03-14'},
]


@admin_bp.route('/')
@admin_bp.route('/dashboard')
def dashboard():
    """
    Admin dashboard - Main admin interface.
    
    INTERNAL: Shows fake but realistic dashboard data.
    """
    stats = {
        'total_users': 1247,
        'active_sessions': 89,
        'api_calls_today': 45672,
        'revenue_mtd': 127450.00,
        'alerts': 3,
        'pending_tasks': 12
    }
    
    recent_activity = [
        {'time': '10:23:45', 'user': 'admin', 'action': 'Login', 'ip': '192.168.1.100'},
        {'time': '10:15:22', 'user': 'john.doe', 'action': 'API Key Generated', 'ip': '10.0.0.45'},
        {'time': '09:45:18', 'user': 'system', 'action': 'Backup Completed', 'ip': 'localhost'},
        {'time': '09:30:00', 'user': 'jane.smith', 'action': 'Config Updated', 'ip': '10.0.0.67'},
    ]
    
    return render_template('admin/dashboard.html', stats=stats, activity=recent_activity)


@admin_bp.route('/users')
def users():
    """
    User management - IDOR target.
    
    INTERNAL: User IDs are exposed for IDOR testing.
    """
    return render_template('admin/users.html', users=FAKE_USERS)


@admin_bp.route('/users/<int:user_id>')
def user_detail(user_id):
    """
    User detail page - IDOR vulnerable endpoint.
    
    INTERNAL: Returns different user data based on ID.
    This simulates IDOR vulnerability.
    """
    # Find user by ID
    user = next((u for u in FAKE_USERS if u['id'] == user_id), None)
    
    if not user:
        # Generate fake user for any ID (makes IDOR seem successful)
        user = {
            'id': user_id,
            'username': f'user_{user_id}',
            'email': f'user{user_id}@cybershield.local',
            'role': 'user',
            'last_login': '2024-03-10 12:00:00',
            'phone': '+1-555-' + str(user_id).zfill(4)[-4:],
            'address': f'{user_id * 10} Fake Street',
            'ssn_last_four': str(user_id * 1234)[-4:],
            'api_key': 'cs_user_' + ''.join(random.choices(string.ascii_letters, k=24))
        }
    
    return render_template('admin/user_detail.html', user=user)


@admin_bp.route('/api-keys')
def api_keys():
    """
    API Key management page.
    """
    return render_template('admin/api_keys.html', keys=FAKE_API_KEYS)


@admin_bp.route('/api-keys/create', methods=['POST'])
def create_api_key():
    """Create new API key (fake)."""
    name = request.form.get('name', 'New Key')
    new_key = {
        'id': f'key_{len(FAKE_API_KEYS) + 1}',
        'name': name,
        'key': 'cs_new_' + ''.join(random.choices(string.ascii_letters + string.digits, k=32)),
        'created': '2024-03-15',
        'last_used': 'Never'
    }
    return jsonify({'status': 'success', 'key': new_key})


@admin_bp.route('/api-keys/validate', methods=['POST'])
def validate_api_key():
    """Validate leaked or discovered API key against fake internal scopes."""
    key = request.form.get('key', '')
    if request.is_json:
        payload = request.get_json(silent=True) or {}
        key = payload.get('key', key)

    key_lower = key.lower()
    if 'adminkey' in key_lower or 'cs_admin' in key_lower:
        return jsonify({
            'status': 'success',
            'scope': ['admin:*', 'vault:read', 'db:read'],
            'next': ['/internal/admin-service?x-internal-key=adminkey_int_7fce381d']
        })

    return jsonify({'status': 'error', 'message': 'invalid key'}), 401


@admin_bp.route('/wallet')
def wallet():
    """
    Crypto wallet page - High-value target.
    
    INTERNAL: Shows fake crypto balances and wallet addresses.
    """
    wallets = {
        'btc': {
            'address': '1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa',
            'balance': 2.45678,
            'usd_value': 156789.45
        },
        'eth': {
            'address': '0x742d35Cc6634C0532925a3b844Bc9e7595f12345',
            'balance': 45.892,
            'usd_value': 145678.90
        },
        'usdt': {
            'address': 'TN3W4H6rK2ce4vX9YnFQHwKENnHjoxb3m9',
            'balance': 250000.00,
            'usd_value': 250000.00
        }
    }
    
    transactions = [
        {'date': '2024-03-14', 'type': 'Received', 'amount': '0.5 BTC', 'from': '3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy'},
        {'date': '2024-03-12', 'type': 'Sent', 'amount': '10 ETH', 'to': '0x89205A3A3b2A69De6Dbf7f01ED13B2108B2c43e7'},
        {'date': '2024-03-10', 'type': 'Received', 'amount': '50000 USDT', 'from': 'Internal Transfer'},
    ]
    
    return render_template('admin/wallet.html', wallets=wallets, transactions=transactions)


@admin_bp.route('/wallet/transactions')
def wallet_transactions():
    """Detailed transaction ledger used as a high-value data lure."""
    return jsonify({
        'status': 'success',
        'ledger': [
            {'tx': '0xabc102', 'asset': 'BTC', 'amount': 0.83, 'to': 'cold-vault-1', 'approved_by': 'ops.breakglass'},
            {'tx': '0xabc103', 'asset': 'ETH', 'amount': 12.4, 'to': 'hot-wallet-7', 'approved_by': 'finance.lead'},
            {'tx': '0xabc104', 'asset': 'USDT', 'amount': 95000.0, 'to': 'vendor-clearing', 'approved_by': 'payroll.bot'},
        ],
        'next': ['/internal/logs', '/internal/vault/secrets']
    })


@admin_bp.route('/config')
def config():
    """
    Configuration panel - Shows fake system config.
    
    INTERNAL: Exposes "sensitive" configuration data.
    """
    config_data = {
        'database': {
            'host': 'db.internal.cybershield.local',
            'port': 3306,
            'name': 'cybershield_prod',
            'user': 'cs_admin',
            'password': '********'  # Shown as masked
        },
        'redis': {
            'host': 'cache.internal.cybershield.local',
            'port': 6379,
            'password': '********'
        },
        'aws': {
            'region': 'us-east-1',
            'bucket': 'cybershield-production',
            'access_key': 'FAKE_AWS_KEY_REDACTED',
            'secret_key': '********'
        },
        'jwt': {
            'algorithm': 'HS256',
            'expiry': 3600,
            'secret': '********'
        }
    }
    
    return render_template('admin/config.html', config=config_data)


@admin_bp.route('/config/export')
def config_export():
    """
    Export configuration - Returns full config.
    
    INTERNAL: This endpoint "accidentally" returns unmasked credentials.
    """
    detected_attacks = g.get('detected_attacks', [])
    
    # Full config with "secrets"
    full_config = {
        'database': {
            'host': 'db.internal.cybershield.local',
            'port': 3306,
            'name': 'cybershield_prod',
            'user': 'cs_admin',
            'password': 'Pr0d_DB_P@ssw0rd_2024!'
        },
        'redis': {
            'host': 'cache.internal.cybershield.local',
            'port': 6379,
            'password': 'R3d1s_C@che_P@ss!'
        },
        'aws': {
            'region': 'us-east-1',
            'bucket': 'cybershield-production',
            'access_key': 'FAKE_AWS_KEY_EXAMPLE',
            'secret_key': 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY'
        },
        'jwt': {
            'algorithm': 'HS256',
            'expiry': 3600,
            'secret': 'super_secret_jwt_key_production_2024'
        },
        'admin': {
            'email': 'admin@cybershield.local',
            'default_password': 'Ch@ngeM3_2024!'
        }
    }
    
    return jsonify(full_config)


@admin_bp.route('/debug')
def debug():
    """
    Debug panel - Template injection target.
    
    INTERNAL: This endpoint pretends to be a debug interface.
    """
    debug_info = {
        'server_time': time.strftime('%Y-%m-%d %H:%M:%S'),
        'python_version': '3.9.7',
        'flask_version': '3.0.0',
        'environment': 'production',
        'debug_mode': False,
        'memory_usage': '245 MB',
        'cpu_usage': '12%',
        'active_connections': 89,
        'cache_size': '1.2 GB'
    }
    
    return render_template('admin/debug.html', debug_info=debug_info)


@admin_bp.route('/debug/config')
def debug_config_export():
    """Debug config export with intentionally weak secrets for JWT/key abuse chains."""
    return jsonify({
        'status': 'success',
        'debug_mode': False,
        'jwt': {
            'algorithm': 'HS256',
            'weak_secret': 'debug-weak-secret-2026',
            'example_forged_token': 'Bearer forged_admin_token'
        },
        'internal_keys': {
            'admin_service_key': 'adminkey_int_7fce381d',
            'storage_read_key': 'stor_key_1f23b8bb'
        },
        'next': ['/api/v2/internal/users?token=forged_admin_token', '/internal/admin-service?x-internal-key=adminkey_int_7fce381d']
    })


@admin_bp.route('/debug/eval', methods=['POST'])
def debug_eval():
    """
    Debug eval endpoint - Command injection target.
    
    INTERNAL: Appears to execute Python code but returns fake output.
    """
    code = request.form.get('code', '')
    
    # Check for detected attacks
    detected_attacks = g.get('detected_attacks', [])
    
    if any(a.get('type') == 'command_injection' for a in detected_attacks):
        # Return fake shell output
        return jsonify({
            'status': 'success',
            'output': 'uid=33(www-data) gid=33(www-data) groups=33(www-data)'
        })
    
    if any(a.get('type', '').startswith('ssti') for a in detected_attacks):
        # Return fake template injection result
        if '7*7' in code or '7*6' in code:
            return jsonify({'status': 'success', 'output': '49'})
        if 'config' in code.lower():
            return jsonify({
                'status': 'success',
                'output': "<Config {'DEBUG': False, 'SECRET_KEY': 'prod-key', 'DATABASE_URI': '...'}>"}
            )
    
    return jsonify({'status': 'error', 'message': 'Invalid expression'})


@admin_bp.route('/database')
def database():
    """
    Database management page.
    """
    tables = [
        {'name': 'users', 'rows': 12847, 'size': '45 MB'},
        {'name': 'sessions', 'rows': 89234, 'size': '128 MB'},
        {'name': 'transactions', 'rows': 456789, 'size': '892 MB'},
        {'name': 'api_logs', 'rows': 2345678, 'size': '2.1 GB'},
        {'name': 'audit_logs', 'rows': 567890, 'size': '456 MB'},
        {'name': 'config', 'rows': 234, 'size': '1.2 MB'},
    ]
    
    return render_template('admin/database.html', tables=tables)


@admin_bp.route('/database/query', methods=['POST'])
def database_query():
    """
    Database query endpoint - SQL injection target.
    
    INTERNAL: Returns fake query results.
    """
    query = request.form.get('query', '').lower()
    
    # Check for SQL injection
    detected_attacks = g.get('detected_attacks', [])
    
    if any(a.get('type', '').startswith('sqli') for a in detected_attacks):
        # Return fake data based on query
        if 'users' in query:
            return jsonify({
                'status': 'success',
                'columns': ['id', 'username', 'email', 'password_hash', 'role'],
                'rows': [
                    [1, 'admin', 'admin@cybershield.local', '$2b$12$fakehash1234567890abcdef', 'administrator'],
                    [2, 'john', 'john@cybershield.local', '$2b$12$anotherfakehash12345678', 'analyst'],
                    [3, 'jane', 'jane@cybershield.local', '$2b$12$yetanotherfakehash12345', 'developer'],
                ]
            })
        
        return jsonify({
            'status': 'success',
            'columns': ['id', 'data'],
            'rows': [[1, 'Query executed successfully']]
        })
    
    return jsonify({'status': 'error', 'message': 'Query validation failed'})


@admin_bp.route('/database/console')
def database_console():
    """Fake interactive database console endpoint."""
    query = request.args.get('q', 'select id,username,role from users limit 3')
    return jsonify({
        'status': 'success',
        'engine': 'postgresql 14.9',
        'query': query,
        'rows': [
            {'id': 1, 'username': 'admin', 'role': 'administrator'},
            {'id': 7, 'username': 'svc.sync', 'role': 'service'},
            {'id': 9, 'username': 'ops.breakglass', 'role': 'security'},
        ],
        'next': ['/internal/db?table=employees', '/internal/vault/secrets']
    })


@admin_bp.route('/logs')
def logs():
    """
    Log viewer page.
    """
    fake_logs = [
        {'timestamp': '2024-03-15 10:25:34', 'level': 'INFO', 'message': 'User admin logged in from 192.168.1.100'},
        {'timestamp': '2024-03-15 10:24:12', 'level': 'WARNING', 'message': 'Failed login attempt for user admin from 10.0.0.45'},
        {'timestamp': '2024-03-15 10:22:45', 'level': 'INFO', 'message': 'API key cs_prod_xxx generated by admin'},
        {'timestamp': '2024-03-15 10:20:00', 'level': 'ERROR', 'message': 'Database connection timeout - retrying'},
        {'timestamp': '2024-03-15 10:15:30', 'level': 'INFO', 'message': 'Scheduled backup started'},
    ]
    
    return render_template('admin/logs.html', logs=fake_logs)


@admin_bp.route('/settings')
def settings():
    """Admin settings page."""
    return render_template('admin/settings.html')
