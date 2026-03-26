"""
API Routes - Fake Internal APIs

Simulates internal API endpoints that attackers might target.

INTERNAL DOCUMENTATION:
- APIs return fake but realistic data
- Some endpoints intentionally "leak" information
- All API calls are logged with full request/response data
"""

from flask import Blueprint, request, jsonify, g
import time
import random


api_bp = Blueprint('api', __name__)


# =============================================================================
# PUBLIC API ENDPOINTS
# =============================================================================

@api_bp.route('/v1/health')
def api_health():
    """API health check."""
    return jsonify({
        'status': 'healthy',
        'timestamp': int(time.time()),
        'version': 'v1.2.3'
    })


@api_bp.route('/v1/auth/login', methods=['POST'])
def api_login():
    """
    API login endpoint - Authentication bypass target.
    
    INTERNAL: Returns fake JWT for SQLi/NoSQLi attempts.
    """
    detected_attacks = g.get('detected_attacks', [])
    
    # Check for injection attacks
    injection_detected = any(
        a.get('type', '') in ['sqli_classic', 'sqli_blind', 'nosql_injection']
        for a in detected_attacks
    )
    
    if injection_detected:
        return jsonify({
            'status': 'success',
            'token': 'FAKE_JWT_TOKEN_REDACTED_FOR_SECURITY',
            'user': {
                'id': 1,
                'username': 'admin',
                'email': 'admin@cybershield.local',
                'role': 'administrator'
            },
            'expires_in': 86400
        })
    
    return jsonify({
        'status': 'error',
        'message': 'Invalid credentials'
    }), 401


@api_bp.route('/v1/users')
def api_users():
    """
    Users list - IDOR and enumeration target.
    """
    users = [
        {'id': 1, 'username': 'admin', 'email': 'admin@cybershield.local', 'role': 'admin'},
        {'id': 2, 'username': 'john.doe', 'email': 'john.doe@cybershield.local', 'role': 'user'},
        {'id': 3, 'username': 'jane.smith', 'email': 'jane.smith@cybershield.local', 'role': 'user'},
    ]
    
    return jsonify({
        'status': 'success',
        'data': users,
        'total': 1247,
        'page': 1,
        'per_page': 10
    })


@api_bp.route('/v1/users/<int:user_id>')
def api_user_detail(user_id):
    """
    User detail - IDOR vulnerable endpoint.
    
    INTERNAL: Returns detailed user data for any ID.
    """
    # Generate consistent fake user based on ID
    random.seed(user_id)
    
    user = {
        'id': user_id,
        'username': f'user_{user_id}',
        'email': f'user{user_id}@cybershield.local',
        'role': random.choice(['user', 'analyst', 'developer']),
        'created_at': f'2023-{random.randint(1,12):02d}-{random.randint(1,28):02d}',
        'last_login': f'2024-03-{random.randint(1,15):02d} {random.randint(8,18):02d}:{random.randint(0,59):02d}',
        'phone': f'+1-555-{random.randint(1000,9999)}',
        'department': random.choice(['Engineering', 'Sales', 'Security', 'Operations']),
        'api_key': f'cs_user_{user_id}_{"".join(random.choices("abcdefghijklmnopqrstuvwxyz", k=16))}'
    }
    
    random.seed()  # Reset seed
    
    return jsonify({
        'status': 'success',
        'data': user
    })


# =============================================================================
# INTERNAL API ENDPOINTS (supposed to be hidden)
# =============================================================================

@api_bp.route('/internal/config')
def api_internal_config():
    """
    Internal config API - Should be "hidden".
    
    INTERNAL: Returns fake sensitive configuration.
    """
    return jsonify({
        'database': {
            'host': 'db.internal.cybershield.local',
            'port': 3306,
            'username': 'app_user',
            'password': 'D@t@b@se_P@ss_2024!'
        },
        'redis': {
            'host': 'cache.internal.cybershield.local',
            'port': 6379
        },
        'services': {
            'payment_api': 'https://payment.internal.cybershield.local',
            'email_service': 'https://email.internal.cybershield.local',
            'storage': 's3://cybershield-internal-data'
        },
        'secrets': {
            'jwt_key': 'internal_jwt_secret_key_2024',
            'encryption_key': 'aes256_encryption_key_that_looks_real'
        }
    })


@api_bp.route('/internal/users/admin')
def api_internal_admin_user():
    """Internal admin user endpoint."""
    return jsonify({
        'id': 1,
        'username': 'admin',
        'email': 'admin@cybershield.local',
        'password_hash': '$2b$12$LQv3c1yqBWVHxkd0LHAkCOYz6TtxMQJqhN8/X4.fakehash',
        'role': 'super_admin',
        'permissions': ['*'],
        'api_key': 'cs_admin_master_key_super_secret_12345',
        'mfa_secret': 'JBSWY3DPEHPK3PXP',
        'recovery_codes': ['abc123', 'def456', 'ghi789', 'jkl012']
    })


@api_bp.route('/internal/metrics')
def api_internal_metrics():
    """Internal metrics endpoint."""
    return jsonify({
        'requests_per_second': 1234,
        'active_users': 89,
        'database_connections': 45,
        'cache_hit_rate': 0.94,
        'error_rate': 0.002,
        'avg_response_time_ms': 45
    })


# =============================================================================
# DEBUG API ENDPOINTS
# =============================================================================

@api_bp.route('/debug/info')
def api_debug_info():
    """Debug information endpoint."""
    return jsonify({
        'environment': 'production',
        'python_version': '3.9.7',
        'flask_version': '3.0.0',
        'server_time': time.strftime('%Y-%m-%d %H:%M:%S'),
        'server_hostname': 'web-01.cybershield.local',
        'internal_ip': '10.0.0.5',
        'database_status': 'connected',
        'cache_status': 'connected'
    })


@api_bp.route('/debug/errors')
def api_debug_errors():
    """Recent errors endpoint."""
    return jsonify({
        'errors': [
            {
                'timestamp': '2024-03-15 10:23:45',
                'level': 'ERROR',
                'message': 'Database connection timeout',
                'stack_trace': 'File "/app/db.py", line 45\n    connection.execute(query)\npsycopg2.OperationalError: timeout'
            },
            {
                'timestamp': '2024-03-15 09:45:12',
                'level': 'WARNING',
                'message': 'Rate limit exceeded for IP 10.0.0.45',
                'details': {'ip': '10.0.0.45', 'endpoint': '/api/v1/users', 'requests': 150}
            }
        ]
    })


@api_bp.route('/debug/routes')
def api_debug_routes():
    """List all routes - Information disclosure."""
    from flask import current_app
    
    routes = []
    for rule in current_app.url_map.iter_rules():
        routes.append({
            'endpoint': rule.endpoint,
            'methods': list(rule.methods - {'HEAD', 'OPTIONS'}),
            'path': rule.rule
        })
    
    return jsonify({
        'routes': sorted(routes, key=lambda x: x['path'])
    })


# =============================================================================
# GRAPHQL ENDPOINT (simulated)
# =============================================================================

@api_bp.route('/graphql', methods=['GET', 'POST'])
def graphql():
    """
    GraphQL endpoint - Introspection and query target.
    
    INTERNAL: Returns fake GraphQL responses.
    """
    detected_attacks = g.get('detected_attacks', [])
    
    # Check for introspection
    body = request.get_data(as_text=True).lower()
    
    if '__schema' in body or '__type' in body:
        # Return fake schema
        return jsonify({
            'data': {
                '__schema': {
                    'types': [
                        {'name': 'User', 'fields': ['id', 'username', 'email', 'role', 'apiKey']},
                        {'name': 'Config', 'fields': ['database', 'redis', 'secrets']},
                        {'name': 'Transaction', 'fields': ['id', 'amount', 'from', 'to', 'timestamp']},
                        {'name': 'Mutation', 'fields': ['createUser', 'updateUser', 'deleteUser', 'transferFunds']}
                    ],
                    'queryType': {'name': 'Query'},
                    'mutationType': {'name': 'Mutation'}
                }
            }
        })
    
    # Handle user query
    if 'user' in body:
        return jsonify({
            'data': {
                'user': {
                    'id': 1,
                    'username': 'admin',
                    'email': 'admin@cybershield.local',
                    'role': 'administrator',
                    'apiKey': 'cs_admin_graphql_key_12345'
                }
            }
        })
    
    return jsonify({
        'data': None,
        'errors': [{'message': 'Invalid query'}]
    })


# =============================================================================
# WEBHOOK/CALLBACK ENDPOINTS
# =============================================================================

@api_bp.route('/webhooks/receive', methods=['POST'])
def webhook_receive():
    """
    Webhook receiver - SSRF callback target.
    
    INTERNAL: Logs the callback for SSRF detection.
    """
    return jsonify({
        'status': 'received',
        'timestamp': int(time.time())
    })


@api_bp.route('/fetch', methods=['POST'])
def fetch_url():
    """
    URL fetcher - SSRF target.
    
    INTERNAL: Simulates fetching remote URLs.
    """
    url = request.form.get('url', '') or request.json.get('url', '') if request.is_json else ''
    
    detected_attacks = g.get('detected_attacks', [])
    
    # Check for SSRF
    ssrf_detected = any(a.get('type') == 'ssrf' for a in detected_attacks)
    
    if ssrf_detected:
        # Return fake metadata response
        if '169.254.169.254' in url:
            return jsonify({
                'status': 'success',
                'content': {
                    'Code': 'Success',
                    'Type': 'AWS-HMAC',
                    'AccessKeyId': 'ASIAFAKEKEY12345678',
                    'SecretAccessKey': 'FakeSecretAccessKey1234567890',
                    'Token': 'FakeSessionToken...'
                }
            })
        
        return jsonify({
            'status': 'success',
            'content': '<html><body>Internal service response</body></html>'
        })
    
    return jsonify({
        'status': 'error',
        'message': 'URL validation failed'
    }), 400


@api_bp.route('/v1/upload', methods=['POST'])
def api_upload():
    """
    File upload API - File upload bypass target.
    """
    detected_attacks = g.get('detected_attacks', [])
    
    # Always return success for uploads
    filename = request.form.get('filename', 'uploaded_file')
    
    return jsonify({
        'status': 'success',
        'file': {
            'name': filename,
            'path': f'/uploads/2024/03/{filename}',
            'url': f'https://cdn.cybershield.local/uploads/2024/03/{filename}',
            'size': random.randint(1000, 50000)
        }
    })
