"""
Response Engine - Fake Response Templates

Contains realistic fake responses for various attack types.
These responses are designed to appear genuine and encourage further exploration.

INTERNAL DOCUMENTATION:
- Templates are categorized by attack type
- Each template includes variations for realism
- Responses evolve based on attacker progression
"""

import random
from typing import Dict, List, Any, Optional
from dataclasses import dataclass


@dataclass
class ResponseTemplate:
    """Definition of a fake response template."""
    attack_type: str
    status_code: int
    headers: Dict[str, str]
    body: str
    delay_ms: int = 0  # Artificial delay for realism


# =============================================================================
# SQL INJECTION RESPONSES
# =============================================================================

SQLI_RESPONSES = {
    'success_login': [
        ResponseTemplate(
            attack_type='sqli_classic',
            status_code=302,
            headers={'Location': '/admin/dashboard', 'Set-Cookie': 'admin_session=a8f3b2c1d4e5; HttpOnly'},
            body='',
            delay_ms=150
        ),
        ResponseTemplate(
            attack_type='sqli_classic',
            status_code=200,
            headers={'Content-Type': 'application/json'},
            body='{"status": "success", "message": "Login successful", "user": {"id": 1, "role": "admin", "username": "admin"}}',
            delay_ms=200
        ),
    ],
    'error_revealing': [
        ResponseTemplate(
            attack_type='sqli_classic',
            status_code=500,
            headers={'Content-Type': 'text/html'},
            body='''<html><head><title>Database Error</title></head><body>
<h1>Internal Server Error</h1>
<p>Error executing query: You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version for the right syntax to use near '' at line 1</p>
<pre>Query: SELECT * FROM users WHERE username='' AND password=''</pre>
</body></html>''',
            delay_ms=100
        ),
    ],
    'blind_time': [
        ResponseTemplate(
            attack_type='sqli_blind',
            status_code=200,
            headers={'Content-Type': 'application/json'},
            body='{"status": "processing", "message": "Request received"}',
            delay_ms=5000  # 5 second delay to simulate sleep()
        ),
    ]
}

# =============================================================================
# COMMAND INJECTION RESPONSES
# =============================================================================

COMMAND_INJECTION_RESPONSES = {
    'fake_shell_output': [
        ResponseTemplate(
            attack_type='command_injection',
            status_code=200,
            headers={'Content-Type': 'text/plain'},
            body='''uid=33(www-data) gid=33(www-data) groups=33(www-data)
Linux web-server-01 5.4.0-42-generic #46-Ubuntu SMP Fri Jul 10 00:24:02 UTC 2020 x86_64 x86_64 x86_64 GNU/Linux''',
            delay_ms=300
        ),
        ResponseTemplate(
            attack_type='command_injection',
            status_code=200,
            headers={'Content-Type': 'text/plain'},
            body='''total 48
drwxr-xr-x  5 www-data www-data 4096 Mar 15 10:23 .
drwxr-xr-x 14 root     root     4096 Mar  1 08:00 ..
-rw-r--r--  1 www-data www-data  220 Mar  1 08:00 .bash_logout
-rw-r--r--  1 www-data www-data 3771 Mar  1 08:00 .bashrc
drwx------  2 www-data www-data 4096 Mar 15 10:23 .cache
-rw-r--r--  1 www-data www-data  807 Mar  1 08:00 .profile
drwxr-xr-x  2 www-data www-data 4096 Mar 15 10:23 backups
-rw-r--r--  1 www-data www-data  128 Mar 10 14:22 config.txt
drwxr-xr-x  3 www-data www-data 4096 Mar 15 09:45 webapp''',
            delay_ms=250
        ),
    ],
    'fake_passwd': [
        ResponseTemplate(
            attack_type='command_injection',
            status_code=200,
            headers={'Content-Type': 'text/plain'},
            body='''root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
mysql:x:27:27:MySQL Server:/var/lib/mysql:/bin/false
postgres:x:26:26:PostgreSQL Server:/var/lib/pgsql:/bin/bash
admin:x:1000:1000:System Administrator:/home/admin:/bin/bash
backup:x:1001:1001:Backup User:/home/backup:/bin/bash''',
            delay_ms=200
        ),
    ]
}

# =============================================================================
# LFI RESPONSES
# =============================================================================

LFI_RESPONSES = {
    'passwd': ResponseTemplate(
        attack_type='lfi',
        status_code=200,
        headers={'Content-Type': 'text/plain'},
        body='''root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
mysql:x:27:27:MySQL Server:/var/lib/mysql:/bin/false
admin:x:1000:1000:Admin User,,,:/home/admin:/bin/bash
deploy:x:1001:1001:Deploy User:/home/deploy:/bin/bash''',
        delay_ms=150
    ),
    'shadow': ResponseTemplate(
        attack_type='lfi',
        status_code=200,
        headers={'Content-Type': 'text/plain'},
        body='''root:$6$rounds=656000$fakesalt$fakehashedpassword1234567890abcdef:18000:0:99999:7:::
admin:$6$rounds=656000$anothersalt$anotherhashedpassword0987654321fedcba:18500:0:99999:7:::
deploy:$6$rounds=656000$thirdsalt$thirdhashedpasswordzxywvutsrqponmlkj:18600:0:99999:7:::''',
        delay_ms=200
    ),
    'env': ResponseTemplate(
        attack_type='lfi',
        status_code=200,
        headers={'Content-Type': 'text/plain'},
        body='''# Application Environment
APP_ENV=production
APP_DEBUG=false
APP_KEY=FAKE_BASE64_KEY_REDACTED

# Database Configuration
DB_CONNECTION=mysql
DB_HOST=db.internal.company.local
DB_PORT=3306
DB_DATABASE=production_db
DB_USERNAME=prod_user
DB_PASSWORD=Pr0d_Sup3r_S3cr3t_P@ssw0rd!

# AWS Configuration
AWS_ACCESS_KEY_ID=FAKE_AWS_KEY_EXAMPLE
AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
AWS_DEFAULT_REGION=us-east-1
AWS_BUCKET=company-production-bucket

# API Keys
STRIPE_SECRET_KEY=fake
SENDGRID_API_KEY=FAKE_SENDGRID_KEY
TWILIO_SID=FAKE_TWILIO_SID
TWILIO_TOKEN=1234567890abcdef1234567890abcdef''',
        delay_ms=180
    ),
    'config': ResponseTemplate(
        attack_type='lfi',
        status_code=200,
        headers={'Content-Type': 'text/plain'},
        body='''<?php
// Database configuration
define('DB_HOST', 'mysql.internal.company.local');
define('DB_USER', 'webapp_prod');
define('DB_PASS', 'W3b@pp_Pr0d_P@ss!');
define('DB_NAME', 'webapp_production');

// Security settings
define('SECRET_KEY', 'a1b2c3d4e5f6g7h8i9j0klmnopqrstuvwxyz');
define('ADMIN_EMAIL', 'admin@company.internal');

// API configurations
define('PAYMENT_API_KEY', 'pk_live_51234567890abcdefghij');
define('PAYMENT_SECRET', 'FAKE_STRIPE_KEY');
?>''',
        delay_ms=150
    ),
    'proc_self': ResponseTemplate(
        attack_type='lfi',
        status_code=200,
        headers={'Content-Type': 'text/plain'},
        body='/usr/bin/python3 /var/www/app/run.py --config /etc/app/config.yml',
        delay_ms=100
    )
}

# =============================================================================
# SSRF RESPONSES
# =============================================================================

SSRF_RESPONSES = {
    'aws_metadata': ResponseTemplate(
        attack_type='ssrf',
        status_code=200,
        headers={'Content-Type': 'text/plain'},
        body='''{
  "Code": "Success",
  "LastUpdated": "2026-03-15T10:30:00Z",
  "Type": "AWS-HMAC",
  "AccessKeyId": "ASIAFAKEKEY12345678",
  "SecretAccessKey": "FakeSecretAccessKey1234567890ABCDEFGHIJ",
  "Token": "FakeSessionTokenThatIsVeryLongAndLooksReal1234567890ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz",
  "Expiration": "2026-03-15T16:30:00Z"
}''',
        delay_ms=300
    ),
    'gcp_metadata': ResponseTemplate(
        attack_type='ssrf',
        status_code=200,
        headers={'Content-Type': 'application/json', 'Metadata-Flavor': 'Google'},
        body='''{
  "access_token": "ya29.FakeGCPAccessToken1234567890ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnop",
  "expires_in": 3600,
  "token_type": "Bearer"
}''',
        delay_ms=250
    ),
    'internal_service': ResponseTemplate(
        attack_type='ssrf',
        status_code=200,
        headers={'Content-Type': 'application/json'},
        body='''{
  "service": "internal-api",
  "version": "2.3.1",
  "endpoints": [
    "/api/v1/users",
    "/api/v1/admin",
    "/api/v1/config",
    "/api/v1/debug"
  ],
  "database": {
    "host": "db.internal.local",
    "port": 5432,
    "name": "production"
  }
}''',
        delay_ms=200
    )
}

# =============================================================================
# XSS RESPONSES
# =============================================================================

XSS_RESPONSES = {
    'reflected': ResponseTemplate(
        attack_type='xss_reflected',
        status_code=200,
        headers={'Content-Type': 'text/html'},
        body='''<!DOCTYPE html>
<html>
<head><title>Search Results</title></head>
<body>
<h1>Search Results</h1>
<p>You searched for: {payload}</p>
<p>No results found for your query.</p>
</body>
</html>''',
        delay_ms=100
    ),
    'stored_confirm': ResponseTemplate(
        attack_type='xss_reflected',
        status_code=200,
        headers={'Content-Type': 'application/json'},
        body='{"status": "success", "message": "Comment posted successfully", "id": 12847}',
        delay_ms=150
    )
}

# =============================================================================
# FILE UPLOAD RESPONSES
# =============================================================================

FILE_UPLOAD_RESPONSES = {
    'success': ResponseTemplate(
        attack_type='file_upload_bypass',
        status_code=200,
        headers={'Content-Type': 'application/json'},
        body='''{
  "status": "success",
  "message": "File uploaded successfully",
  "file": {
    "name": "image.php.jpg",
    "path": "/uploads/2026/03/image.php.jpg",
    "url": "https://cdn.example.com/uploads/2026/03/image.php.jpg",
    "size": 15234
  }
}''',
        delay_ms=500
    )
}

# =============================================================================
# JWT TAMPERING RESPONSES
# =============================================================================

JWT_RESPONSES = {
    'alg_none_success': ResponseTemplate(
        attack_type='jwt_tampering',
        status_code=200,
        headers={'Content-Type': 'application/json'},
        body='{"status": "success", "user": {"id": 1, "role": "admin", "permissions": ["*"]}}',
        delay_ms=100
    )
}

# =============================================================================
# XXE RESPONSES
# =============================================================================

XXE_RESPONSES = {
    'file_disclosure': ResponseTemplate(
        attack_type='xxe',
        status_code=200,
        headers={'Content-Type': 'application/xml'},
        body='''<?xml version="1.0" encoding="UTF-8"?>
<response>
  <status>processed</status>
  <data>root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin</data>
</response>''',
        delay_ms=200
    )
}

# =============================================================================
# TEMPLATE INJECTION RESPONSES
# =============================================================================

SSTI_RESPONSES = {
    'calculation': ResponseTemplate(
        attack_type='ssti_jinja2',
        status_code=200,
        headers={'Content-Type': 'text/html'},
        body='''<!DOCTYPE html>
<html>
<head><title>Debug Output</title></head>
<body>
<h1>Template Debug</h1>
<p>Result: 49</p>
</body>
</html>''',
        delay_ms=100
    ),
    'config_leak': ResponseTemplate(
        attack_type='ssti_jinja2',
        status_code=200,
        headers={'Content-Type': 'text/html'},
        body='''<!DOCTYPE html>
<html>
<body>
<pre>&lt;Config {'DEBUG': False, 'SECRET_KEY': 'dev-key-change-in-prod', 'DATABASE_URI': 'postgresql://...'}&gt;</pre>
</body>
</html>''',
        delay_ms=150
    )
}


# =============================================================================
# HELPER FUNCTIONS
# =============================================================================

def get_response_for_attack(
    attack_type: str,
    variant: str = 'default',
    payload: str = ''
) -> ResponseTemplate:
    """
    Get appropriate fake response for detected attack.
    
    Args:
        attack_type: Type of attack detected
        variant: Response variant (e.g., 'success', 'error')
        payload: Original attack payload for reflection
        
    Returns:
        ResponseTemplate with fake response data
    """
    # Map attack types to response sets
    response_map = {
        'sqli_classic': SQLI_RESPONSES.get(variant, SQLI_RESPONSES['success_login']),
        'sqli_blind': SQLI_RESPONSES.get('blind_time', SQLI_RESPONSES['success_login']),
        'command_injection': COMMAND_INJECTION_RESPONSES.get(variant, COMMAND_INJECTION_RESPONSES['fake_shell_output']),
        'lfi': [LFI_RESPONSES.get(variant, LFI_RESPONSES['passwd'])],
        'ssrf': [SSRF_RESPONSES.get(variant, SSRF_RESPONSES['aws_metadata'])],
        'xss_reflected': [XSS_RESPONSES['reflected']],
        'file_upload_bypass': [FILE_UPLOAD_RESPONSES['success']],
        'jwt_tampering': [JWT_RESPONSES['alg_none_success']],
        'xxe': [XXE_RESPONSES['file_disclosure']],
        'ssti_jinja2': [SSTI_RESPONSES.get(variant, SSTI_RESPONSES['calculation'])],
    }
    
    responses = response_map.get(attack_type, [])
    
    if isinstance(responses, list) and responses:
        template = random.choice(responses)
        # Handle payload reflection safely
        if payload and '{payload}' in template.body:
            # Escape the payload for safe inclusion
            safe_payload = payload.replace('<', '&lt;').replace('>', '&gt;')
            return ResponseTemplate(
                attack_type=template.attack_type,
                status_code=template.status_code,
                headers=template.headers,
                body=template.body.replace('{payload}', safe_payload),
                delay_ms=template.delay_ms
            )
        return template
    elif isinstance(responses, ResponseTemplate):
        return responses
    
    # Default response
    return ResponseTemplate(
        attack_type='default',
        status_code=200,
        headers={'Content-Type': 'application/json'},
        body='{"status": "ok"}',
        delay_ms=0
    )


def get_progressive_response(
    attack_type: str,
    progression_level: float
) -> ResponseTemplate:
    """
    Get response that evolves based on attacker progression.
    
    As attackers progress (0.0 to 1.0), responses reveal more "interesting" data.
    
    Args:
        attack_type: Type of attack
        progression_level: 0.0 to 1.0 indicating how far attacker has progressed
        
    Returns:
        ResponseTemplate appropriate to progression level
    """
    if progression_level < 0.25:
        # Early stage - basic responses
        return get_response_for_attack(attack_type, 'default')
    elif progression_level < 0.5:
        # Getting deeper - show errors
        return get_response_for_attack(attack_type, 'error_revealing')
    elif progression_level < 0.75:
        # Deep - show success
        return get_response_for_attack(attack_type, 'success')
    else:
        # Very deep - show sensitive data
        if attack_type in ['lfi', 'command_injection']:
            return get_response_for_attack(attack_type, 'env')
        return get_response_for_attack(attack_type, 'success')
