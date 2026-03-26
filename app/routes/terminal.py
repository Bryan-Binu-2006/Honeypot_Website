"""
Terminal Routes - Web Terminal Simulation

Simulates a web-based terminal for command injection testing.

INTERNAL DOCUMENTATION:
- Commands are never actually executed
- Returns fake output based on command patterns
- Tracks command sequences for behavioral analysis
"""

from flask import Blueprint, request, jsonify, render_template, g
import time
import random


terminal_bp = Blueprint('terminal', __name__)


# Fake command outputs
FAKE_OUTPUTS = {
    'id': 'uid=33(www-data) gid=33(www-data) groups=33(www-data)',
    
    'whoami': 'www-data',
    
    'uname -a': 'Linux web-01 5.4.0-42-generic #46-Ubuntu SMP Fri Jul 10 00:24:02 UTC 2020 x86_64 x86_64 x86_64 GNU/Linux',
    
    'uname': 'Linux',
    
    'pwd': '/var/www/cybershield',
    
    'ls': 'app.py\nconfig.py\nrequirements.txt\nstatic\ntemplates\nuploads\n.env',
    
    'ls -la': '''total 48
drwxr-xr-x  5 www-data www-data 4096 Mar 15 10:23 .
drwxr-xr-x  3 www-data www-data 4096 Mar  1 08:00 ..
-rw-r--r--  1 www-data www-data 1234 Mar 15 10:23 app.py
-rw-r--r--  1 www-data www-data  456 Mar 10 14:22 config.py
-rw-r--r--  1 www-data www-data  789 Mar  1 08:00 requirements.txt
drwxr-xr-x  2 www-data www-data 4096 Mar 15 09:45 static
drwxr-xr-x  2 www-data www-data 4096 Mar 15 09:45 templates
drwxr-xr-x  2 www-data www-data 4096 Mar 15 10:23 uploads
-rw-r--r--  1 www-data www-data  567 Mar 10 14:22 .env''',

    'cat /etc/passwd': '''root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
mysql:x:27:27:MySQL Server:/var/lib/mysql:/bin/false
admin:x:1000:1000:Admin User:/home/admin:/bin/bash
deploy:x:1001:1001:Deploy User:/home/deploy:/bin/bash''',

    'cat /etc/shadow': '''root:$6$rounds=656000$fakesalt$hashedpassword1234567890:18000:0:99999:7:::
admin:$6$rounds=656000$salt2$hashedpassword0987654321:18500:0:99999:7:::
deploy:$6$rounds=656000$salt3$hashedpasswordabcdefghij:18600:0:99999:7:::''',

    'cat .env': '''APP_ENV=production
APP_DEBUG=false
APP_KEY=FAKE_BASE64_KEY
DB_HOST=db.internal.cybershield.local
DB_DATABASE=cybershield_production
DB_USERNAME=cs_app_user
DB_PASSWORD=Pr0duct10n_DB_P@ss!
REDIS_PASSWORD=R3d1s_S3cr3t!
JWT_SECRET=jwt_secret_key_production''',

    'cat config.py': '''# CyberShield Configuration
DATABASE_URI = 'mysql://cs_app:Pr0d_P@ss!@db.internal:3306/prod'
SECRET_KEY = 'super_secret_production_key_2024'
ADMIN_PASSWORD = 'Adm1n_Def@ult!'
API_KEY = 'FAKE_STRIPE_KEY' ''',

    'ps aux': '''USER       PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND
root         1  0.0  0.1 169432  9876 ?        Ss   Mar14   0:05 /sbin/init
root       234  0.0  0.0  39324  3456 ?        Ss   Mar14   0:00 /usr/sbin/sshd
mysql      456  0.1  2.5 1789456 204832 ?      Ssl  Mar14   2:34 /usr/sbin/mysqld
www-data  1234  0.5  1.2 456789  98765 ?       Sl   10:00   0:23 python3 app.py
www-data  1235  0.0  0.5 234567  45678 ?       Sl   10:00   0:02 python3 app.py''',

    'netstat -tlnp': '''Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      234/sshd
tcp        0      0 0.0.0.0:80              0.0.0.0:*               LISTEN      567/nginx
tcp        0      0 127.0.0.1:3306          0.0.0.0:*               LISTEN      456/mysqld
tcp        0      0 127.0.0.1:6379          0.0.0.0:*               LISTEN      789/redis-server
tcp        0      0 127.0.0.1:5000          0.0.0.0:*               LISTEN      1234/python3''',

    'env': '''PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
HOME=/var/www
USER=www-data
FLASK_ENV=production
DATABASE_URL=mysql://cs_app:Pr0d_P@ss!@db.internal:3306/prod
REDIS_URL=redis://:R3d1s_S3cr3t!@cache.internal:6379
SECRET_KEY=production_secret_key_never_share
AWS_ACCESS_KEY_ID=FAKE_AWS_KEY
AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY''',

    'ifconfig': '''eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500
        inet 10.0.0.5  netmask 255.255.255.0  broadcast 10.0.0.255
        inet6 fe80::1  prefixlen 64  scopeid 0x20<link>
        ether 02:42:ac:11:00:02  txqueuelen 0  (Ethernet)

lo: flags=73<UP,LOOPBACK,RUNNING>  mtu 65536
        inet 127.0.0.1  netmask 255.0.0.0
        inet6 ::1  prefixlen 128  scopeid 0x10<host>''',

    'curl': '''curl: try 'curl --help' for more information''',
    
    'wget': '''wget: missing URL
Usage: wget [OPTION]... [URL]...''',

    'python -c': '''Python 3.9.7 (default, Sep 16 2021, 13:09:58)
[GCC 7.5.0] on linux''',

    'nc': '''usage: nc [-46CDdFhklNnrStUuvZz] [-I length] [-i interval] [-M ttl]
          [-m minttl] [-O length] [-P proxy_username] [-p source_port]
          [-q seconds] [-s sourceaddr] [-T keyword] [-V rtable] [-W recvlimit]
          [-w timeout] [-X proxy_protocol] [-x proxy_address[:port]]
          [destination] [port]''',
}


@terminal_bp.route('/')
def terminal_page():
    """
    Terminal interface page.
    """
    return render_template('terminal.html')


@terminal_bp.route('/exec', methods=['POST'])
def terminal_exec():
    """
    Execute command - Command injection target.
    
    INTERNAL: This never executes real commands.
    It pattern-matches and returns fake output.
    """
    command = request.form.get('cmd', '') or request.form.get('command', '')
    
    if request.is_json:
        command = request.json.get('cmd', '') or request.json.get('command', '')
    
    detected_attacks = g.get('detected_attacks', [])
    
    # Check for command injection
    cmd_injection = any(
        a.get('type') == 'command_injection'
        for a in detected_attacks
    )
    
    # Get fake output
    output = get_fake_output(command)
    
    return jsonify({
        'status': 'success',
        'command': command,
        'output': output,
        'exit_code': 0,
        'timestamp': int(time.time())
    })


@terminal_bp.route('/api/exec', methods=['POST'])
def terminal_api_exec():
    """
    API-based command execution.
    """
    command = ''
    
    if request.is_json:
        command = request.json.get('cmd', '') or request.json.get('command', '')
    else:
        command = request.form.get('cmd', '') or request.form.get('command', '')
    
    output = get_fake_output(command)
    
    return jsonify({
        'result': output,
        'success': True
    })


@terminal_bp.route('/shell', methods=['GET', 'POST'])
def terminal_shell():
    """
    Shell endpoint - Another command injection target.
    """
    command = request.args.get('cmd', '') or request.form.get('cmd', '')
    
    if not command:
        return jsonify({
            'status': 'ready',
            'message': 'Shell ready. Use ?cmd= to execute commands.'
        })
    
    output = get_fake_output(command)
    
    return output, 200, {'Content-Type': 'text/plain'}


def get_fake_output(command: str) -> str:
    """
    Get fake output for a command.
    
    Pattern matches common commands and returns realistic output.
    """
    if not command:
        return ''
    
    command = command.strip()
    cmd_lower = command.lower()
    
    # Direct matches
    if command in FAKE_OUTPUTS:
        return FAKE_OUTPUTS[command]
    
    # Pattern matching
    if cmd_lower.startswith('id'):
        return FAKE_OUTPUTS['id']
    
    if cmd_lower == 'whoami':
        return FAKE_OUTPUTS['whoami']
    
    if 'uname' in cmd_lower:
        if '-a' in cmd_lower:
            return FAKE_OUTPUTS['uname -a']
        return FAKE_OUTPUTS['uname']
    
    if cmd_lower == 'pwd':
        return FAKE_OUTPUTS['pwd']
    
    if cmd_lower.startswith('ls'):
        if '-' in cmd_lower:
            return FAKE_OUTPUTS['ls -la']
        return FAKE_OUTPUTS['ls']
    
    if 'cat' in cmd_lower:
        if '/etc/passwd' in cmd_lower or 'passwd' in cmd_lower:
            return FAKE_OUTPUTS['cat /etc/passwd']
        if '/etc/shadow' in cmd_lower or 'shadow' in cmd_lower:
            return FAKE_OUTPUTS['cat /etc/shadow']
        if '.env' in cmd_lower:
            return FAKE_OUTPUTS['cat .env']
        if 'config' in cmd_lower:
            return FAKE_OUTPUTS['cat config.py']
        # Default cat output
        return 'File contents would appear here'
    
    if cmd_lower.startswith('ps'):
        return FAKE_OUTPUTS['ps aux']
    
    if 'netstat' in cmd_lower or 'ss ' in cmd_lower:
        return FAKE_OUTPUTS['netstat -tlnp']
    
    if cmd_lower == 'env' or cmd_lower.startswith('printenv'):
        return FAKE_OUTPUTS['env']
    
    if 'ifconfig' in cmd_lower or 'ip addr' in cmd_lower:
        return FAKE_OUTPUTS['ifconfig']
    
    if cmd_lower.startswith('curl'):
        if 'http' in cmd_lower:
            return '<html><body>Response from internal server</body></html>'
        return FAKE_OUTPUTS['curl']
    
    if cmd_lower.startswith('wget'):
        if 'http' in cmd_lower:
            return '2024-03-15 10:00:00 (1.23 MB/s) - saved'
        return FAKE_OUTPUTS['wget']
    
    if 'python' in cmd_lower or 'python3' in cmd_lower:
        if '-c' in cmd_lower:
            # Simulate code execution
            if '7*7' in command or '7*6' in command:
                return '49'
            if 'import os' in command and 'system' in command:
                return 'uid=33(www-data) gid=33(www-data)'
            return ''
        return FAKE_OUTPUTS['python -c']
    
    if cmd_lower.startswith('nc') or 'netcat' in cmd_lower:
        return FAKE_OUTPUTS['nc']
    
    if cmd_lower.startswith('echo'):
        # Return what they're trying to echo
        return command[5:].strip().strip('"\'')
    
    if cmd_lower.startswith('cd'):
        return ''  # cd produces no output
    
    if 'bash' in cmd_lower or 'sh ' in cmd_lower:
        # Pretend shell spawned
        return 'www-data@web-01:/var/www/cybershield$ '
    
    # Default: command not found (but looks like it tried)
    cmd_name = command.split()[0] if command.split() else command
    return f'{cmd_name}: command executed'


@terminal_bp.route('/history')
def terminal_history():
    """
    Command history endpoint.
    """
    # Fake history
    history = [
        {'id': 1, 'command': 'ls -la', 'timestamp': '2024-03-15 10:00:00'},
        {'id': 2, 'command': 'cat config.py', 'timestamp': '2024-03-15 10:01:23'},
        {'id': 3, 'command': 'ps aux', 'timestamp': '2024-03-15 10:02:45'},
        {'id': 4, 'command': 'netstat -tlnp', 'timestamp': '2024-03-15 10:03:12'},
    ]
    
    return jsonify({
        'status': 'success',
        'history': history
    })
