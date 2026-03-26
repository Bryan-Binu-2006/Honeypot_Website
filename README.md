# 🍯 CyberShield Honeypot - Production-Grade Web Application Security Platform

A sophisticated cybersecurity honeypot web application that simulates a realistic vulnerable platform to detect, track, and analyze cyber attacks. All attacker actions are secretly logged while sophisticated deception keeps them engaged.

---

## 📋 Table of Contents

- [Overview](#overview)
- [Architecture](#architecture)
- [Features](#features)
- [Attack Patterns Detected](#attack-patterns-detected)
- [Installation](#installation)
- [Local Development](#local-development)
- [Production Deployment](#production-deployment)
- [Configuration](#configuration)
- [Project Structure](#project-structure)
- [API Endpoints](#api-endpoints)
- [Operator Dashboard](#operator-dashboard)
- [Security Considerations](#security-considerations)
- [Troubleshooting](#troubleshooting)

---

## 🎯 Overview

**CyberShield Honeypot** is a deception platform that:

1. **Simulates a real cybersecurity company** - Professional UI/UX that looks legitimate
2. **Detects 30+ real-world attack patterns** - Pattern matching + heuristic analysis
3. **Generates fake responses** - Attackers believe they're succeeding
4. **Tracks attacker behavior** - Sessions, IP addresses, attack types
5. **Logs everything securely** - Tamper-proof, isolated logging system
6. **Integrates external honeypots** - Cowrie SSH, Wazuh SIEM, OpenCanary support
7. **Provides real-time monitoring** - Private operator dashboard for you

---

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────────────────────────┐
│                              External Client                           │
└───────────────────────────────┬─────────────────────────────────────────┘
                                │ HTTP(S)
┌───────────────────────────────▼─────────────────────────────────────────┐
│                       Flask Honeypot App (run.py)                      │
│                                 Port 5000                              │
│                                                                         │
│  before_request                                                         │
│  1) SessionManager.get_or_create_session()                              │
│     - HMAC-based session identity                                       │
│  2) RequestInterceptor.analyze()                                        │
│     - Detection engine + stage inference                                │
│                                                                         │
│  route handler                                                          │
│  3) Public/Admin/API/Files/Terminal deception responses                 │
│                                                                         │
│  after_request                                                          │
│  4) Security headers + persist sid cookie                               │
│  5) queue_event() -> logging_service.interface                          │
└───────────────────────────────┬─────────────────────────────────────────┘
                                │ append JSONL events
┌───────────────────────────────▼─────────────────────────────────────────┐
│                           data/operatordata.jsonl                      │
│                           (append-only event log)                      │
└───────────────────────────────┬─────────────────────────────────────────┘
                                │ polled every 2s
┌───────────────────────────────▼─────────────────────────────────────────┐
│                Standalone Operator Dashboard (operator_dashboard.py)    │
│                           Port 5001 (localhost only)                    │
│                                                                         │
│  - Auth + lockout controls                                               │
│  - Active sessions (time-windowed)                                       │
│  - Historical sessions (separate section/API)                            │
│  - Live event stream + attack timeline                                   │
└─────────────────────────────────────────────────────────────────────────┘
```

### Runtime Notes

- One browser session is correlated by the sid cookie written in after_request.
- The operator dashboard separates active vs historical sessions.
- Active window defaults to 15 minutes and is configurable via OPERATOR_ACTIVE_WINDOW_MINUTES.
- Asset hits (static files, favicon, robots/sitemap) are tracked separately from interactive requests.

---

## ✨ Features

### Public Honeypot (Port 5000)

- **Homepage** - Professional CyberShield branding
- **Login Page** - SQLi detection, fake success on attack
- **Admin Panel** - Fake dashboard (accessible after "successful" login)
  - User management (IDOR target)
  - API key management
  - Crypto wallet simulation
  - File explorer (LFI simulation)
  - Web terminal
  - Debug console
- **Public Endpoints**
  - `/robots.txt` - Exposes "hidden" paths
  - `/.env` - Fake credentials
  - `/.git/config` - Fake git config
  - `/health` - Status endpoint
  - `/version` - Version info
- **Detection & Logging** - Every request analyzed, logged, tracked

### Private Operator Dashboard (Port 5001)

- **Password Protected** - Only you can access
- **Real-time Monitoring**
   - Active attacker wall (live session cards)
   - Historical sessions table (separate from active)
  - Recent attacks timeline
  - Live event log
  - Statistics dashboard
- **Session Tracking** - IP, stage, request count, attacks, asset vs interactive request mix
- **Attack Analytics** - By type, severity, endpoint
- **Event Log** - Full request/response history

---

## 🛡️ Attack Patterns Detected (30+)

### SQL Injection (SQLi)
- Classic: `' OR '1'='1`, UNION SELECT, INSERT/UPDATE/DELETE
- Blind: Time-based, boolean-based
- NoSQL: MongoDB injection patterns

### Cross-Site Scripting (XSS)
- Reflected: `<script>alert(1)</script>`
- DOM: JavaScript code execution
- Stored: Persistent payload detection

### Command Injection
- Shell metacharacters: `; | & $ ( )`
- System commands: `cat`, `ls`, `whoami`
- Encoding bypasses: URL, base64, hex

### File Inclusion
- LFI: `../../../etc/passwd`, `....//etc/shadow`
- RFI: Remote file loading
- Path traversal variants

### SSRF (Server-Side Request Forgery)
- Cloud metadata: `169.254.169.254`
- Internal services: `localhost:6379`, `127.0.0.1:3306`
- Protocol abuse: `file://`, `gopher://`

### Template Injection
- Jinja2: `{{7*7}}`, `{{config}}`
- ERB: `<%= 7*7 %>`
- Handlebars: `{{this}}`

### XXE (XML External Entity)
- Entity definition attacks
- DTD injection
- External entity references

### LDAP Injection
- Filter manipulation: `*))(&`
- Authentication bypass

### JWT Tampering
- Algorithm confusion (HS256/RS256)
- Key manipulation
- Signature forgery

### IDOR (Insecure Direct Object Reference)
- Sequential ID access
- Parameter tampering

### Session Attacks
- Session fixation attempts
- Cookie tampering
- Token prediction

### Other Patterns
- MIME type bypass (multipart, double extension)
- GraphQL abuse
- API fuzzing
- Directory enumeration
- Rate-based scanning
- User-Agent manipulation
- X-Forwarded-For spoofing
- Prototype pollution
- Deserialization attacks
- Header injection

---

## 📦 Installation

### Prerequisites
- Python 3.8+
- pip (Python package manager)

### Steps

1. **Clone or download the project**
   ```bash
   git clone <your-repo>
   cd Honeypot_Website
   ```

2. **Create virtual environment (optional but recommended)**
   ```bash
   python -m venv venv
   venv\Scripts\activate  # On Windows
   # source venv/bin/activate  # On Linux/Mac
   ```

3. **Install dependencies**
   ```bash
   pip install -r requirements.txt
   ```

4. **Create .env file**
   ```bash
   copy .env.example .env
   ```

5. **Edit .env with your settings**
   ```ini
   SECRET_KEY=your-random-32-char-string
   SESSION_SECRET=another-random-string
   FLASK_ENV=production
   FLASK_DEBUG=0
   HOST=0.0.0.0
   PORT=5000
   OPERATOR_USERNAME=operator_admin
   OPERATOR_PASSWORD=change_me_to_strong_password
   OPERATOR_SECRET_KEY=change_me_to_random_string
   OPERATOR_HOST=127.0.0.1
   OPERATOR_PORT=5001
   ```

---

## 🚀 Local Development

### Terminal 1 - Run Honeypot
```bash
cd C:\Users\[YourUsername]\Documents\Honeypot_Website
python run.py
```

**Access:** http://127.0.0.1:5000

### Terminal 2 - Run Operator Dashboard
```bash
cd C:\Users\[YourUsername]\Documents\Honeypot_Website
python operator_dashboard.py
```

**Access:** http://127.0.0.1:5001
**Login:** Use `.env` values `OPERATOR_USERNAME` + `OPERATOR_PASSWORD`

### Test Exploits

Try these attacks:

**SQL Injection (Login):**
```
Username: admin' OR '1'='1
Password: test
```
→ Redirects to /admin/dashboard

**LFI (File Explorer):**
```
http://127.0.0.1:5000/files/browse?path=../../../etc/passwd
```

**SSRF:**
```
curl -X POST http://127.0.0.1:5000/api/fetch -H "Content-Type: application/json" -d "{\"url\":\"http://169.254.169.254/latest/meta-data/\"}"
```

**XSS (Contact Form):**
```
<script>alert('XSS')</script>
```

**IDOR:**
```
http://127.0.0.1:5000/admin/users/1
http://127.0.0.1:5000/admin/users/2
```

---

## 🌐 Production Deployment (Render)

### Step 1: Push to GitHub

```bash
git add .
git commit -m "Honeypot application"
git push origin main
```

**Important:** Only push these files:
- `app/` directory
- `requirements.txt`
- `run.py`
- `.env.example`
- `.gitignore`
- `nginx/`
- `README.md`

**DO NOT PUSH:**
- `.env` (contains secrets)
- `operator_dashboard.py` (keep locally)
- `data/` directory (logs)

### Step 2: Deploy on Render.com

1. Go to https://render.com
2. Click "New" → "Web Service"
3. Connect GitHub repository
4. Configure:
   - **Name:** honeypot-security
   - **Environment:** Python 3
   - **Build Command:** `pip install -r requirements.txt`
   - **Start Command:** `gunicorn -w 4 -b 0.0.0.0:$PORT "app:create_app()"`

5. Add environment variables:
   ```
   FLASK_ENV=production
   SECRET_KEY=<random-32-chars>
   SESSION_SECRET=<random-32-chars>
   FLASK_DEBUG=0
   ```

6. Deploy!

### Step 3: Run Operator Dashboard Locally

```bash
# On YOUR machine (not on Render)
python operator_dashboard.py
```

Access: http://127.0.0.1:5001

**Note:** Operator dashboard reads logs from `data/operatordata.jsonl`. On Render, this file doesn't persist between restarts. To fix this, upgrade to PostgreSQL database (see Configuration section).

---

## ⚙️ Configuration

### Environment Variables

| Variable | Description | Example | Required |
|----------|-------------|---------|----------|
| `FLASK_ENV` | Environment mode | `production` | ✓ |
| `FLASK_DEBUG` | Debug mode (always 0 in prod) | `0` | ✓ |
| `SECRET_KEY` | Flask secret key (32+ chars) | Random string | ✓ |
| `SESSION_SECRET` | Session HMAC key (32+ chars) | Random string | ✓ |
| `HOST` | Bind address | `0.0.0.0` or `127.0.0.1` | ✗ |
| `PORT` | Port number | `5000` | ✗ |
| `OPERATOR_USERNAME` | Operator login username | `operator_admin` | ✓ |
| `OPERATOR_PASSWORD` | Operator dashboard password | Strong password | ✓ |
| `OPERATOR_PASSWORD_HASH` | Optional pre-hashed password | PBKDF2 hash | ✗ |
| `OPERATOR_SECRET_KEY` | Operator session secret | Random string | ✓ |
| `OPERATOR_HOST` | Operator bind host | `127.0.0.1` | ✓ |
| `OPERATOR_PORT` | Operator bind port | `5001` | ✓ |
| `OPERATOR_ACTIVE_WINDOW_MINUTES` | Active session lookback window | `15` | ✗ |
| `DATABASE_URL` | PostgreSQL connection (optional) | `postgresql://...` | ✗ |
| `REDIS_URL` | Redis connection (optional) | `redis://localhost:6379` | ✗ |

### Session Configuration

Session IDs are generated using HMAC(IP + UserAgent + Timestamp + Nonce, SECRET).

- Stored in HttpOnly cookies (prevents XSS theft)
- Marked as Secure in production HTTPS paths
- Localhost HTTP fallback is supported for local testing so session correlation remains stable
- SameSite=Lax (prevents CSRF)
- Automatically regenerated if tampering detected

---

## 📁 Project Structure

```
Honeypot_Website/
├── run.py                          # Main application entry point
├── operator_dashboard.py           # Standalone operator console
├── requirements.txt                # Python dependencies
├── .env                           # Configuration (DO NOT COMMIT)
├── .env.example                   # Configuration template
├── .gitignore                     # Git ignore rules
├── README.md                      # This file
│
├── app/                           # Main Flask application
│   ├── __init__.py               # App factory
│   ├── config.py                 # Configuration loading
│   │
│   ├── routes/                   # Route handlers
│   │   ├── public.py            # Public endpoints (/, /login, /robots.txt, etc.)
│   │   ├── admin.py             # Admin panel (fake)
│   │   ├── api.py               # Internal APIs (fake)
│   │   ├── files.py             # File explorer (LFI simulation)
│   │   └── terminal.py          # Web terminal (command injection simulation)
│   │
│   ├── detection/               # Attack detection engine
│   │   ├── patterns.py          # 30+ attack pattern definitions
│   │   ├── classifiers.py       # Pattern matching logic
│   │   ├── engine.py            # Main detection coordinator
│   │   └── __init__.py
│   │
│   ├── response/                # Fake response generation
│   │   ├── templates.py         # Pre-defined fake responses
│   │   └── engine.py            # Response selection logic
│   │
│   ├── session/                 # Session management
│   │   ├── manager.py           # HMAC-based session creation
│   │   └── tracker.py           # Attacker behavior tracking
│   │
│   ├── behavior/                # Progressive deception
│   │   └── engine.py            # Attacker stage progression
│   │
│   ├── middleware/              # Request/response middleware
│   │   ├── interceptor.py       # Request interception
│   │   └── security.py          # Security headers
│   │
│   ├── logging_service/         # Isolated logging
│   │   ├── interface.py         # Abstract logging interface
│   │   ├── sanitizer.py         # Input sanitization
│   │   └── __init__.py
│   │
│   ├── integrations/            # External honeypot integration
│   │   ├── base.py             # Base classes
│   │   ├── cowrie.py           # Cowrie SSH integration
│   │   ├── wazuh.py            # Wazuh SIEM integration
│   │   ├── opencanary.py       # OpenCanary integration
│   │   └── __init__.py
│   │
│   ├── static/                  # Static assets
│   │   ├── css/
│   │   │   └── style.css       # Main stylesheet
│   │   └── js/
│   │       └── main.js         # Frontend JavaScript
│   │
│   └── templates/               # HTML templates
│       ├── base.html           # Base template
│       ├── index.html          # Homepage
│       ├── login.html          # Login page
│       ├── signup.html         # Signup page
│       ├── contact.html        # Contact form
│       ├── about.html          # About page
│       ├── forgot_password.html # Password reset
│       ├── terminal.html       # Web terminal
│       ├── admin/              # Admin panel templates
│       │   ├── dashboard.html
│       │   ├── users.html
│       │   ├── user_detail.html
│       │   ├── api_keys.html
│       │   ├── wallet.html
│       │   ├── config.html
│       │   ├── debug.html
│       │   ├── database.html
│       │   ├── logs.html
│       │   ├── settings.html
│       │   └── nav.html
│       ├── operator/           # Operator dashboard templates
│       │   └── dashboard.html
│       ├── components/         # Reusable components
│       └── errors/             # Error pages
│           ├── 404.html
│           └── 500.html
│
├── logging_daemon/              # Separate logging service (optional)
│   ├── service.py              # Logging daemon
│   ├── database.py             # Database connector
│   └── __init__.py
│
├── nginx/                       # Nginx configuration
│   └── honeypot.conf           # Reverse proxy config
│
└── data/                        # Runtime data (NOT committed)
    └── operatordata.jsonl      # Event log (append-only)
```

---

## 🔗 API Endpoints

### Public Endpoints (Honeypot - Port 5000)

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/` | Homepage |
| GET/POST | `/login` | Login page (SQLi target) |
| GET/POST | `/signup` | Signup page |
| GET/POST | `/forgot-password` | Password reset |
| GET/POST | `/contact` | Contact form (XSS target) |
| GET | `/about` | About page |
| GET | `/robots.txt` | Exposes hidden paths |
| GET | `/.env` | Fake environment file |
| GET | `/.git/config` | Fake git config |
| GET | `/health` | Health check |
| GET | `/version` | Version info |

### Admin Endpoints (Honeypot - Port 5000)

| Method | Endpoint | Description | Auth |
|--------|----------|-------------|------|
| GET | `/admin` | Admin dashboard | SQLi redirect |
| GET | `/admin/users` | User management | SQLi redirect |
| GET | `/admin/users/<id>` | User detail (IDOR target) | SQLi redirect |
| GET | `/admin/api-keys` | API key management | SQLi redirect |
| GET | `/admin/wallet` | Crypto wallet | SQLi redirect |
| GET | `/admin/config` | Configuration | SQLi redirect |
| GET | `/admin/debug` | Debug panel | SQLi redirect |
| GET | `/admin/database` | Database interface | SQLi redirect |
| GET | `/admin/logs` | System logs | SQLi redirect |
| GET | `/admin/settings` | Settings | SQLi redirect |

### API Endpoints (Honeypot - Port 5000)

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/v1/health` | API health check |
| POST | `/api/v1/auth/login` | API login (injection target) |
| GET | `/api/v1/users` | Fake user list |
| GET | `/api/v1/users/<id>` | Fake user detail (IDOR target) |
| GET | `/api/internal/config` | Config API (fake) |
| GET | `/api/internal/users/admin` | Internal admin user data |
| GET | `/api/internal/metrics` | Internal metrics |
| GET | `/api/debug/info` | Debug info leak |
| GET | `/api/debug/errors` | Debug error dump |
| GET | `/api/debug/routes` | Route enumeration |
| GET/POST | `/api/graphql` | GraphQL simulation |
| POST | `/api/webhooks/receive` | Webhook callback endpoint |
| POST | `/api/fetch` | URL fetch (SSRF target) |
| POST | `/api/v1/upload` | File upload simulation |

### File Endpoints (Honeypot - Port 5000)

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/files/` | File explorer root |
| GET | `/files/browse?path=` | Browse path (LFI target) |
| GET | `/files/read?path=` | Read file content simulation (`file=` also accepted) |
| GET | `/files/download?path=` | File download simulation (`id=` also accepted) |
| POST | `/files/upload` | Upload simulation |

### Terminal Endpoints (Honeypot - Port 5000)

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/terminal` | Web terminal page |
| POST | `/terminal/exec` | Command execution (simulated) |
| POST | `/terminal/api/exec` | API-style command execution |
| GET/POST | `/terminal/shell` | Shell-style command endpoint |
| GET | `/terminal/history` | Command history simulation |

### Operator Dashboard Endpoints (Port 5001)

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/` | Dashboard (password protected) |
| POST | `/login` | Login |
| GET | `/logout` | Logout |
| GET | `/api/sessions` | Sessions (default scope=active; scope=active/history/all) |
| GET | `/api/sessions/active` | Active sessions only |
| GET | `/api/sessions/history` | Historical sessions only |
| GET | `/api/attacks` | Recent attacks (`?limit=` supported) |
| GET | `/api/events` | Event log (`?limit=` supported) |
| GET | `/api/stats` | Statistics |

---

## 👨‍💻 Operator Dashboard

### Accessing the Dashboard

```bash
python operator_dashboard.py
```

Access: http://127.0.0.1:5001

Credentials from `.env` → `OPERATOR_USERNAME` + `OPERATOR_PASSWORD`

### Dashboard Features

**Statistics Panel:**
- Active sessions (last 15 minutes)
- Total sessions
- Total requests
- Total attacks detected

**Sessions Panel:**
- Active users shown as live cards
- IP + stage + request and attack counts
- Asset vs interactive request split
- Recent per-session action feed

**Historical Sessions Panel:**
- Separate table for non-active sessions
- Last seen time, request totals, and stage
- Keeps prior sessions visible without polluting active view

**Attacks Panel:**
- Timestamp
- Attacker IP
- Attack type (SQLi, XSS, LFI, etc.)
- Severity level (LOW, MEDIUM, HIGH, CRITICAL)

**Event Log:**
- Real-time activity stream
- Timestamp, IP, method, endpoint
- Response code
- Attack count

**Auto-refresh:** Dashboard updates every 3 seconds

---

## 🔐 Security Considerations

### What This IS:
- ✓ A teaching tool to understand attack patterns
- ✓ A deception platform to catch reconnaissance
- ✓ A honeypot for analyzing attacker behavior
- ✓ A training ground for security analysts

### What This IS NOT:
- ✗ A real production application
- ✗ A secure web application
- ✗ Protected against determined attackers (it's meant to be vulnerable)
- ✗ Suitable for handling real user data

### Security Best Practices When Deploying:

1. **Use strong secrets:**
   ```bash
   # Generate random keys
   python -c "import secrets; print(secrets.token_urlsafe(32))"
   ```

2. **Enable HTTPS:**
   - Use Let's Encrypt
   - Configure Nginx with SSL certificates

3. **Isolate the honeypot:**
   - Run in separate network if possible
   - Firewall non-honeypot ports
   - Monitor for outbound connections

4. **Keep operator dashboard private:**
   - Never expose on public internet
   - Only accessible from trusted IPs
   - Use VPN if accessing remotely

5. **Rotate passwords regularly:**
   - Update `OPERATOR_PASSWORD` monthly
   - Regenerate `SECRET_KEY` quarterly

6. **Monitor logs:**
   - Check `data/operatordata.jsonl` regularly
   - Set up alerts for CRITICAL attacks
   - Archive logs for analysis

---

## 🐛 Troubleshooting

### Issue: "Redis connection refused"

**Solution:** Redis is optional. The app uses in-memory fallback.
- No action needed for local development
- For rate limiting, install Redis or use memory storage

### Issue: "Port 5000 already in use"

**Solution:** Change port in `.env`:
```ini
PORT=5001
```

### Issue: "Operator dashboard shows no sessions"

**Solution:**
1. Make sure honeypot (run.py) is running
2. Make sure you've browsed the honeypot (generate activity)
3. Check that `data/operatordata.jsonl` exists
4. Restart operator dashboard: `python operator_dashboard.py`
5. If traffic appears only in history, increase `OPERATOR_ACTIVE_WINDOW_MINUTES`

### Issue: "Login doesn't work"

**Solution:**
1. Try SQLi payload: `admin' OR '1'='1`
2. Check that detection engine is working
3. Check Flask debug output for errors

### Issue: "CORS errors"

**Solution:** Should not happen since both apps are separate. If it does:
1. Check browser console for exact error
2. Verify both apps are running on correct ports
3. Check `.env` settings

### Issue: "502 Bad Gateway on Render"

**Solution:**
1. Check Render logs
2. Verify `run.py` starts correctly locally
3. Check environment variables are set
4. Verify `requirements.txt` installs all dependencies

---

## 📚 Additional Resources

### Learning Materials
- OWASP Top 10: https://owasp.org/www-project-top-ten/
- PortSwigger Web Security Academy: https://portswigger.net/web-security
- HackerOne Hacker101: https://www.hacker101.com/

### Honeypot Examples
- Cowrie (SSH): https://github.com/cowrie/cowrie
- Wazuh (SIEM): https://wazuh.com/
- OpenCanary: https://opencanary.org/

### Deployment
- Render Docs: https://render.com/docs
- Flask Deployment: https://flask.palletsprojects.com/deployment/
- Nginx Config: https://nginx.org/en/docs/

---

## 📝 License

This project is for educational and authorized security testing purposes only.

---

## 👤 Author

Created for cybersecurity research and threat analysis.

---

## ⚠️ Disclaimer

**This honeypot is intentionally vulnerable.** Do not use this code or patterns in production applications. This is designed specifically for security research and analysis.

Unauthorized access to computer systems is illegal. Use this honeypot only on systems you own or have explicit permission to test.

---

**Last Updated:** March 26, 2026
**Version:** 1.1
**Status:** Production-Ready
