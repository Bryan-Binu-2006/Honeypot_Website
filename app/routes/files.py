"""
File Explorer Routes - LFI/IDOR Simulation

Simulates a file explorer with intentional path traversal vulnerabilities.

INTERNAL DOCUMENTATION:
- File paths are virtualized (no real filesystem access)
- Path traversal attempts return fake sensitive files
- All file access is logged
"""

from flask import Blueprint, request, jsonify, g, Response
import os
import time
from typing import Dict


files_bp = Blueprint('files', __name__)


_UPLOADED_PAYLOADS: Dict[str, Dict[str, str]] = {}


# Fake filesystem structure
FAKE_FILESYSTEM = {
    '/': ['home', 'etc', 'var', 'opt', 'usr', 'tmp'],
    '/home': ['admin', 'deploy', 'www-data'],
    '/home/admin': ['.bashrc', '.ssh', 'backups', 'scripts'],
    '/home/admin/.ssh': ['id_rsa', 'id_rsa.pub', 'authorized_keys', 'known_hosts'],
    '/home/admin/backups': ['db_backup_2024.sql', 'config_backup.tar.gz', 'users_export.csv'],
    '/etc': ['passwd', 'shadow', 'hosts', 'nginx', 'mysql', 'ssh'],
    '/etc/nginx': ['nginx.conf', 'sites-enabled', 'ssl'],
    '/etc/mysql': ['my.cnf', 'debian.cnf'],
    '/var': ['log', 'www', 'lib'],
    '/var/log': ['auth.log', 'syslog', 'nginx', 'mysql'],
    '/var/www': ['html', 'cybershield'],
    '/var/www/cybershield': ['app.py', 'config.py', '.env', 'requirements.txt'],
}

# Fake file contents
FAKE_FILE_CONTENTS = {
    '/etc/passwd': '''root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
mysql:x:27:27:MySQL Server:/var/lib/mysql:/bin/false
admin:x:1000:1000:Admin User:/home/admin:/bin/bash
deploy:x:1001:1001:Deploy User:/home/deploy:/bin/bash''',

    '/etc/shadow': '''root:$6$rounds=656000$salt$hashedpassword1234567890:18000:0:99999:7:::
admin:$6$rounds=656000$salt2$hashedpassword0987654321:18500:0:99999:7:::
deploy:$6$rounds=656000$salt3$hashedpasswordabcdefghij:18600:0:99999:7:::''',

    '/etc/hosts': '''127.0.0.1       localhost
10.0.0.5        web-01.cybershield.local web-01
10.0.0.10       db.internal.cybershield.local db
10.0.0.11       cache.internal.cybershield.local cache
10.0.0.20       backup.internal.cybershield.local backup
192.168.1.100   admin-workstation''',

    '/home/admin/.ssh/id_rsa': '''-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEA0Z3VW2x7CL7FakePrivateKeyThatLooksRealButIsNot
ThisIsAFakeSSHPrivateKeyForTheHoneypotSystemItShouldLookReal
ButItIsCompletelyInvalidAndCannotBeUsedToAccessAnything
MoreFakeDataHereToMakeItLookLikeARealPrivateKey1234567890
ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz
FakeKeyDataContinuesHereForRealism12345678901234567890
-----END RSA PRIVATE KEY-----''',

    '/home/admin/.ssh/id_rsa.pub': '''ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDFakePublicKey1234567890 admin@cybershield.local''',

    '/home/admin/.ssh/authorized_keys': '''ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDKey1Fake admin@cybershield.local
ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDKey2Fake deploy@cybershield.local
ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDKey3Fake devops@backup.cybershield.local''',

    '/var/www/cybershield/.env': '''APP_ENV=production
APP_DEBUG=false
APP_KEY=FAKE_BASE64_KEY

DB_CONNECTION=mysql
DB_HOST=db.internal.cybershield.local
DB_PORT=3306
DB_DATABASE=cybershield_production
DB_USERNAME=cs_app_user
DB_PASSWORD=Pr0duct10n_DB_P@ssw0rd_2024!

REDIS_HOST=cache.internal.cybershield.local
REDIS_PASSWORD=R3d1s_C@che_S3cr3t!
REDIS_PORT=6379

AWS_ACCESS_KEY_ID=FAKE_AWS_KEY
AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
AWS_DEFAULT_REGION=us-east-1
AWS_BUCKET=cybershield-production

JWT_SECRET=jwt_production_secret_key_never_share_this
API_SECRET=api_master_secret_key_2024''',

    '/var/www/cybershield/config.py': '''# CyberShield Configuration
import os

class Config:
    SECRET_KEY = os.environ.get('APP_KEY', 'dev-secret-key')
    DATABASE_URI = 'mysql://cs_app_user:Pr0duct10n_DB_P@ssw0rd_2024!@db.internal.cybershield.local/cybershield_production'
    REDIS_URL = 'redis://:R3d1s_C@che_S3cr3t!@cache.internal.cybershield.local:6379/0'
    
    # API Keys
    STRIPE_KEY = 'fake'
    SENDGRID_KEY = 'FAKE_SENDGRID_KEY'
    
    # Admin settings
    ADMIN_EMAIL = 'admin@cybershield.local'
    ADMIN_PASSWORD = 'Adm1n_Def@ult_P@ss!'
''',

    '/home/admin/backups/db_backup_2024.sql': '''-- MySQL dump - CyberShield Database Backup
-- Generated: 2024-03-15 02:00:00

CREATE DATABASE IF NOT EXISTS cybershield_production;
USE cybershield_production;

-- Users table
CREATE TABLE users (
    id INT PRIMARY KEY AUTO_INCREMENT,
    username VARCHAR(50) NOT NULL,
    email VARCHAR(100) NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    role VARCHAR(20) DEFAULT 'user'
);

INSERT INTO users VALUES 
(1, 'admin', 'admin@cybershield.local', '$2b$12$FakeHashedPassword1', 'administrator'),
(2, 'john.doe', 'john@cybershield.local', '$2b$12$FakeHashedPassword2', 'analyst'),
(3, 'jane.smith', 'jane@cybershield.local', '$2b$12$FakeHashedPassword3', 'developer');

-- API Keys table
CREATE TABLE api_keys (
    id INT PRIMARY KEY AUTO_INCREMENT,
    user_id INT,
    key_value VARCHAR(64) NOT NULL,
    name VARCHAR(100)
);

INSERT INTO api_keys VALUES
(1, 1, 'cs_admin_key_1234567890abcdef', 'Admin Master Key'),
(2, 2, 'cs_user_key_0987654321fedcba', 'John API Key');
''',

    '/home/admin/backups/users_export.csv': '''id,username,email,password_hash,role,phone,ssn_last_four
1,admin,admin@cybershield.local,$2b$12$hashedpassword1,administrator,+1-555-0001,1234
2,john.doe,john@cybershield.local,$2b$12$hashedpassword2,analyst,+1-555-0002,5678
3,jane.smith,jane@cybershield.local,$2b$12$hashedpassword3,developer,+1-555-0003,9012
4,mike.wilson,mike@cybershield.local,$2b$12$hashedpassword4,analyst,+1-555-0004,3456
5,sarah.jones,sarah@cybershield.local,$2b$12$hashedpassword5,manager,+1-555-0005,7890''',

    '/etc/nginx/nginx.conf': '''user www-data;
worker_processes auto;
pid /run/nginx.pid;

events {
    worker_connections 768;
}

http {
    upstream backend {
        server 127.0.0.1:5000;
    }
    
    server {
        listen 80;
        server_name cybershield.local;
        
        location / {
            proxy_pass http://backend;
            proxy_set_header Host $host;
            proxy_set_header X-Real-IP $remote_addr;
        }
        
        # Admin interface - internal only
        location /admin {
            allow 10.0.0.0/8;
            allow 192.168.1.0/24;
            deny all;
            proxy_pass http://backend;
        }
    }
}''',

    '/var/log/auth.log': '''Mar 15 08:23:45 web-01 sshd[1234]: Accepted publickey for admin from 192.168.1.100 port 52341
Mar 15 09:15:22 web-01 sshd[1235]: Failed password for invalid user root from 45.67.89.123 port 44231
Mar 15 09:15:25 web-01 sshd[1235]: Failed password for invalid user admin from 45.67.89.123 port 44232
Mar 15 10:00:00 web-01 sudo: admin : TTY=pts/0 ; PWD=/home/admin ; USER=root ; COMMAND=/bin/systemctl restart nginx
Mar 15 10:23:45 web-01 sshd[1236]: Accepted publickey for deploy from 10.0.0.50 port 38921''',
}


@files_bp.route('/')
def file_list():
    """
    File explorer root.
    """
    return jsonify({
        'status': 'success',
        'path': '/',
        'files': FAKE_FILESYSTEM.get('/', []),
        'type': 'directory'
    })


@files_bp.route('/browse')
def file_browse():
    """
    Browse files - LFI target.
    
    INTERNAL: Handles path traversal attempts.
    """
    path = request.args.get('path', '/')
    detected_attacks = g.get('detected_attacks', [])
    
    # Normalize path (simulate real traversal processing)
    normalized = normalize_path(path)
    
    # Check for LFI attack
    lfi_detected = any(a.get('type') == 'lfi' for a in detected_attacks)
    
    if lfi_detected:
        # Return fake file content based on what they're trying to access
        return get_lfi_response(path)
    
    # Check if directory
    if normalized in FAKE_FILESYSTEM:
        return jsonify({
            'status': 'success',
            'path': normalized,
            'files': FAKE_FILESYSTEM[normalized],
            'type': 'directory'
        })
    
    # Check if file
    if normalized in FAKE_FILE_CONTENTS:
        return jsonify({
            'status': 'success',
            'path': normalized,
            'content': FAKE_FILE_CONTENTS[normalized],
            'type': 'file'
        })
    
    return jsonify({
        'status': 'error',
        'message': 'Path not found'
    }), 404


@files_bp.route('/download')
def file_download():
    """
    File download - LFI target.
    """
    path = request.args.get('path', '')
    file_id = request.args.get('id', '')
    
    detected_attacks = g.get('detected_attacks', [])
    lfi_detected = any(a.get('type') == 'lfi' for a in detected_attacks)
    
    if lfi_detected:
        return get_lfi_response(path)
    
    # Normal file download
    normalized = normalize_path(path)
    
    if normalized in FAKE_FILE_CONTENTS:
        content = FAKE_FILE_CONTENTS[normalized]
        return Response(
            content,
            mimetype='text/plain',
            headers={'Content-Disposition': f'attachment; filename={os.path.basename(normalized)}'}
        )
    
    return jsonify({'status': 'error', 'message': 'File not found'}), 404


@files_bp.route('/read')
def file_read():
    """
    Read file content - Another LFI endpoint.
    """
    filename = request.args.get('file', '')
    path = request.args.get('path', '')
    
    detected_attacks = g.get('detected_attacks', [])
    
    # Combine parameters for traversal check
    target = path or filename
    
    lfi_detected = any(a.get('type') == 'lfi' for a in detected_attacks)
    
    if lfi_detected:
        return get_lfi_response(target)
    
    normalized = normalize_path(target)

    # Chain simulation: uploaded polyglot payload executed via read endpoint.
    if normalized in _UPLOADED_PAYLOADS:
        cmd = request.args.get('cmd', 'id')
        return jsonify({
            'status': 'success',
            'execution': 'simulated',
            'file': normalized,
            'command': cmd,
            'output': [
                'uid=33(www-data) gid=33(www-data) groups=33(www-data)',
                'sudo: session opened for user root by www-data(uid=33)',
                'pivot hint: /internal/logs/lateral',
            ],
            'next': [
                '/internal/logs/lateral',
                '/internal/db?table=employees'
            ]
        })
    
    if normalized in FAKE_FILE_CONTENTS:
        return jsonify({
            'status': 'success',
            'content': FAKE_FILE_CONTENTS[normalized]
        })
    
    return jsonify({'status': 'error', 'message': 'File not found'}), 404


@files_bp.route('/upload', methods=['POST'])
def file_upload():
    """
    File upload endpoint.
    
    INTERNAL: Always accepts uploads (they go nowhere).
    """
    detected_attacks = g.get('detected_attacks', [])
    
    filename = request.form.get('filename', 'uploaded_file')
    if request.is_json:
        payload = request.get_json(silent=True) or {}
        filename = payload.get('filename', filename)

    upload_path = f'/uploads/2024/03/{filename}'
    looks_polyglot = '.php' in filename.lower() and any(ext in filename.lower() for ext in ['.jpg', '.png', '.gif'])

    if looks_polyglot:
        _UPLOADED_PAYLOADS[upload_path] = {
            'session_id': str(g.get('session_id', 'unknown')),
            'created': str(time.time())
        }
    
    # Always return success
    return jsonify({
        'status': 'success',
        'message': 'File uploaded successfully',
        'file': {
            'name': filename,
            'path': upload_path,
            'size': len(request.data) if request.data else 0
        },
        'analysis': {
            'mime_check': 'image/jpeg',
            'extension_check': 'passed',
            'executable_signature': 'not_detected' if looks_polyglot else 'clean'
        },
        'next': [
            f'/files/read?path={upload_path}&cmd=id',
            '/internal/logs/lateral'
        ]
    })


def normalize_path(path: str) -> str:
    """
    Normalize file path (simulate real path handling).
    """
    # Handle path traversal
    path = path.replace('\\', '/')
    
    # Resolve ../ sequences
    parts = path.split('/')
    resolved = []
    
    for part in parts:
        if part == '..':
            if resolved:
                resolved.pop()
        elif part and part != '.':
            resolved.append(part)
    
    return '/' + '/'.join(resolved)


def get_lfi_response(path: str) -> Response:
    """
    Generate appropriate LFI response based on path.
    """
    path_lower = path.lower()
    
    # Check for common LFI targets
    if 'passwd' in path_lower:
        content = FAKE_FILE_CONTENTS['/etc/passwd']
    elif 'shadow' in path_lower:
        content = FAKE_FILE_CONTENTS['/etc/shadow']
    elif '.env' in path_lower:
        content = FAKE_FILE_CONTENTS['/var/www/cybershield/.env']
    elif 'id_rsa' in path_lower and 'pub' not in path_lower:
        content = FAKE_FILE_CONTENTS['/home/admin/.ssh/id_rsa']
    elif 'authorized_keys' in path_lower:
        content = FAKE_FILE_CONTENTS['/home/admin/.ssh/authorized_keys']
    elif 'hosts' in path_lower:
        content = FAKE_FILE_CONTENTS['/etc/hosts']
    elif 'config.py' in path_lower:
        content = FAKE_FILE_CONTENTS['/var/www/cybershield/config.py']
    elif 'backup' in path_lower and 'sql' in path_lower:
        content = FAKE_FILE_CONTENTS['/home/admin/backups/db_backup_2024.sql']
    elif 'users' in path_lower and 'csv' in path_lower:
        content = FAKE_FILE_CONTENTS['/home/admin/backups/users_export.csv']
    elif 'nginx' in path_lower and 'conf' in path_lower:
        content = FAKE_FILE_CONTENTS['/etc/nginx/nginx.conf']
    elif 'auth.log' in path_lower:
        content = FAKE_FILE_CONTENTS['/var/log/auth.log']
    else:
        # Default to passwd
        content = FAKE_FILE_CONTENTS['/etc/passwd']
    
    return Response(content, mimetype='text/plain')
