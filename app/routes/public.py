"""
Public Routes - Homepage, Login, and Public Endpoints

These routes are the public-facing entry points for the honeypot.
They simulate a legitimate cybersecurity company web application.

INTERNAL DOCUMENTATION:
- All routes are monitored by the detection engine
- robots.txt intentionally exposes "hidden" paths
- Login accepts various injection attempts and returns fake success
"""

from flask import Blueprint, render_template, request, redirect, url_for, g, jsonify, make_response
from ..response.engine import get_response_engine
from ..session.manager import SessionManager
from ..behavior.attack_chain_engine import get_attack_chain_engine


_RESET_TOKENS = {}


public_bp = Blueprint('public', __name__)


@public_bp.route('/')
def index():
    """
    Homepage - Professional cybersecurity company landing page.
    
    INTERNAL: This is the entry point for most attackers.
    We track who visits and what they do next.
    """
    return render_template('index.html')


@public_bp.route('/login', methods=['GET', 'POST'])
def login():
    """
    Login page - Primary target for authentication attacks.
    
    INTERNAL: This endpoint is designed to:
    1. Detect SQL injection in username/password fields
    2. Return fake success for SQLi attacks
    3. Track brute force attempts
    4. Never actually authenticate anyone (it's a honeypot)
    """
    if request.method == 'GET':
        return render_template('login.html')
    
    # POST - Check for detected attacks
    detected_attacks = g.get('detected_attacks', [])
    
    # If SQLi detected, simulate successful login
    sqli_detected = any(
        a.get('type', '').startswith('sqli') 
        for a in detected_attacks
    )
    
    if sqli_detected:
        # Generate fake admin session
        response = make_response(redirect('/admin/dashboard'))
        response.set_cookie(
            'admin_session',
            'FAKE_JWT_TOKEN_REDACTED',
            httponly=True
        )
        return response
    
    # Normal login attempt - always fail after delay
    return render_template('login.html', error='Invalid credentials'), 401


@public_bp.route('/robots.txt')
def robots():
    """
    robots.txt - Intentionally reveals "hidden" paths.
    
    INTERNAL: This is bait. We expose paths that attackers will want to explore:
    - /admin (admin panel)
    - /api/internal (internal API)
    - /debug (debug panel)
    - /files (file explorer)
    - /.env (environment file)
    
    This is a common recon technique - we give them what they're looking for.
    """
    robots_content = """# robots.txt for CyberShield Security Platform
# Please do not access restricted areas

User-agent: *
Disallow: /admin
Disallow: /admin/config
Disallow: /admin/users
Disallow: /admin/api-keys
Disallow: /admin/wallet
Disallow: /admin/database
Disallow: /api/internal
Disallow: /api/v1/admin
Disallow: /api/v1/debug
Disallow: /debug
Disallow: /debug/config
Disallow: /files
Disallow: /files/backup
Disallow: /terminal
Disallow: /.env
Disallow: /.git
Disallow: /backup
Disallow: /config
Disallow: /logs

# Development endpoints - do not index
Disallow: /dev
Disallow: /staging
Disallow: /test

Sitemap: /sitemap.xml
"""
    response = make_response(robots_content)
    response.headers['Content-Type'] = 'text/plain'
    return response


@public_bp.route('/sitemap.xml')
def sitemap():
    """
    Sitemap - More paths for attackers to discover.
    """
    sitemap_content = """<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
  <url>
    <loc>https://cybershield.local/</loc>
    <lastmod>2024-03-15</lastmod>
    <priority>1.0</priority>
  </url>
  <url>
    <loc>https://cybershield.local/login</loc>
    <lastmod>2024-03-15</lastmod>
    <priority>0.8</priority>
  </url>
  <url>
    <loc>https://cybershield.local/about</loc>
    <lastmod>2024-03-10</lastmod>
    <priority>0.5</priority>
  </url>
  <url>
    <loc>https://cybershield.local/contact</loc>
    <lastmod>2024-03-10</lastmod>
    <priority>0.5</priority>
  </url>
  <url>
    <loc>https://cybershield.local/pricing</loc>
    <lastmod>2024-03-08</lastmod>
    <priority>0.6</priority>
  </url>
</urlset>
"""
    response = make_response(sitemap_content)
    response.headers['Content-Type'] = 'application/xml'
    return response


@public_bp.route('/about')
def about():
    """About page for the fake company."""
    return render_template('about.html')


@public_bp.route('/contact', methods=['GET', 'POST'])
def contact():
    """
    Contact form - Can capture XSS attempts.
    """
    if request.method == 'POST':
        # Check for XSS
        detected_attacks = g.get('detected_attacks', [])
        xss_detected = any(
            a.get('type', '').startswith('xss')
            for a in detected_attacks
        )
        
        if xss_detected:
            # Return response that "reflects" the XSS (sanitized)
            return jsonify({
                'status': 'success',
                'message': f"Thank you for your message. We received: {request.form.get('message', '')[:100]}"
            })
        
        return jsonify({'status': 'success', 'message': 'Message sent successfully'})
    
    return render_template('contact.html')


@public_bp.route('/.env')
def env_file():
    """
    Fake .env file - High-value target for attackers.
    
    INTERNAL: This returns fake but realistic-looking credentials.
    """
    env_content = """# Application Environment Configuration
# DO NOT COMMIT TO VERSION CONTROL

APP_ENV=production
APP_DEBUG=false
APP_KEY=FAKE_BASE64_KEY

# Database Configuration
DB_CONNECTION=mysql
DB_HOST=db.internal.cybershield.local
DB_PORT=3306
DB_DATABASE=cybershield_prod
DB_USERNAME=cs_admin
DB_PASSWORD=CyB3r$h13ld_Pr0d_2024!

# AWS Configuration
AWS_ACCESS_KEY_ID=FAKE_AWS_KEY
AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
AWS_DEFAULT_REGION=us-east-1
AWS_BUCKET=cybershield-production-data

# API Keys
STRIPE_SECRET_KEY=fake
SENDGRID_API_KEY=FAKE_SENDGRID_KEY
TWILIO_ACCOUNT_SID=FAKE_TWILIO_SID
TWILIO_AUTH_TOKEN=fake1234567890abcdef1234567890ab

# Internal Services
REDIS_URL=redis://cache.internal.cybershield.local:6379
ELASTICSEARCH_HOST=http://search.internal.cybershield.local:9200

# JWT Secret
JWT_SECRET=super_secret_jwt_key_that_should_never_be_exposed_12345

# Admin Credentials (backup)
ADMIN_EMAIL=admin@cybershield.local
ADMIN_PASSWORD=Adm1n_B@ckup_P@ss_2024!
"""
    response = make_response(env_content)
    response.headers['Content-Type'] = 'text/plain'
    return response


@public_bp.route('/.git/config')
def git_config():
    """Fake git config exposure."""
    content = """[core]
    repositoryformatversion = 0
    filemode = true
    bare = false
    logallrefupdates = true
[remote "origin"]
    url = git@github.com:cybershield/platform-internal.git
    fetch = +refs/heads/*:refs/remotes/origin/*
[branch "main"]
    remote = origin
    merge = refs/heads/main
[user]
    email = devops@cybershield.local
    name = CyberShield DevOps
"""
    response = make_response(content)
    response.headers['Content-Type'] = 'text/plain'
    return response


@public_bp.route('/health')
def health():
    """Health check endpoint - common target for service discovery."""
    return jsonify({
        'status': 'healthy',
        'version': '2.4.1',
        'environment': 'production',
        'uptime': 847293
    })


@public_bp.route('/version')
def version():
    """Version endpoint."""
    return jsonify({
        'application': 'CyberShield Security Platform',
        'version': '2.4.1',
        'build': '20240315-1423',
        'api_version': 'v1'
    })


@public_bp.route('/signup', methods=['GET', 'POST'])
def signup():
    """Signup page for fake registration."""
    if request.method == 'POST':
        return jsonify({
            'status': 'success',
            'message': 'Account created. Please check your email for verification.'
        })
    return render_template('signup.html')


@public_bp.route('/forgot-password', methods=['GET', 'POST'])
def forgot_password():
    """Password reset - potential for account enumeration."""
    if request.method == 'POST':
        email = request.form.get('email', '')
        predictable_seed = (email or 'unknown').split('@')[0].replace('.', '').replace('_', '')[:10]
        token = f"RST-{predictable_seed}-{len(email):02d}"
        _RESET_TOKENS[token] = {
            'email': email,
            'created': g.get('request_analysis', {}).get('timestamp', 0)
        }

        chain_engine = get_attack_chain_engine()
        chain_state = chain_engine.get_state(str(g.get('session_id', 'anonymous')))

        return jsonify({
            'status': 'success',
            'message': f'If an account exists for {email}, a reset link has been sent.',
            'debug_note': 'mail_queue fallback active - token preview enabled for testing',
            'reset_preview': f'/reset-password?token={token}',
            'next_hint': chain_state.get('next_hints', ['/reset-password?token='])
        })
    return render_template('forgot_password.html')


@public_bp.route('/reset-password', methods=['GET', 'POST'])
def reset_password():
    """
    Password reset endpoint with intentionally predictable token flow.
    """
    token = request.args.get('token', '') or request.form.get('token', '')
    token_record = _RESET_TOKENS.get(token)

    if request.method == 'GET':
        if token_record:
            return jsonify({
                'status': 'ready',
                'email': token_record.get('email', 'unknown@cybershield.local'),
                'token': token,
                'message': 'Token accepted. Submit new_password via POST to complete reset.'
            })
        return jsonify({'status': 'error', 'message': 'Invalid token'}), 400

    new_password = request.form.get('new_password', '')
    if request.is_json:
        payload = request.get_json(silent=True) or {}
        token = payload.get('token', token)
        new_password = payload.get('new_password', new_password)
        token_record = _RESET_TOKENS.get(token)

    if token_record and new_password:
        return jsonify({
            'status': 'success',
            'message': 'Password reset accepted',
            'account': token_record.get('email', 'unknown@cybershield.local'),
            'session_token': f"sess_reset_{token.lower()}_granted",
            'next': ['/api/v1/auth/login', '/admin/dashboard']
        })

    return jsonify({'status': 'error', 'message': 'Missing token or password'}), 400
