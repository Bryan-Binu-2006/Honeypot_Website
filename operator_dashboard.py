"""
Standalone operator dashboard for honeypot monitoring.

Security model:
- Binds to localhost only (127.0.0.1:5001) on the VM.
- Accessed remotely only via SSH tunnel.
- Requires operator username + password login.
- Session cookie is HttpOnly and SameSite=Lax.
"""

from __future__ import annotations

import json
import os
import threading
import time
from datetime import datetime, timedelta
from functools import wraps
from typing import Any, Dict, List

from flask import Flask, jsonify, redirect, render_template_string, request, session, url_for
from werkzeug.security import check_password_hash, generate_password_hash
from dotenv import load_dotenv


BASE_DIR = os.path.dirname(os.path.abspath(__file__))
LOG_FILE = os.path.join(BASE_DIR, "data", "operatordata.jsonl")
os.makedirs(os.path.dirname(LOG_FILE), exist_ok=True)


def ensure_operator_log_file() -> None:
    """
    Ensure operator log file exists on every startup.

    Also migrates old file name once if present.
    """
    legacy_file = os.path.join(BASE_DIR, "data", "operator_events.jsonl")
    try:
        if os.path.exists(legacy_file) and not os.path.exists(LOG_FILE):
            with open(legacy_file, "r", encoding="utf-8") as src, open(LOG_FILE, "w", encoding="utf-8") as dst:
                dst.write(src.read())
        if not os.path.exists(LOG_FILE):
            with open(LOG_FILE, "a", encoding="utf-8"):
                pass
    except OSError:
        # Do not block app startup; subsequent operations will retry.
        pass

# Load environment from project .env for standalone execution
load_dotenv(os.path.join(BASE_DIR, ".env"))

OPERATOR_HOST = os.environ.get("OPERATOR_HOST", "127.0.0.1")
OPERATOR_PORT = int(os.environ.get("OPERATOR_PORT", "5001"))
OPERATOR_USERNAME = os.environ.get("OPERATOR_USERNAME", "operator_admin")
OPERATOR_PASSWORD = os.environ.get("OPERATOR_PASSWORD", "ChangeThisNow_UseEnvVar_2026!")
OPERATOR_PASSWORD_HASH = os.environ.get("OPERATOR_PASSWORD_HASH", "").strip()
OPERATOR_SECRET_KEY = os.environ.get("OPERATOR_SECRET_KEY", "change-this-operator-secret")
OPERATOR_SESSION_TIMEOUT_MINUTES = int(os.environ.get("OPERATOR_SESSION_TIMEOUT_MINUTES", "120"))
OPERATOR_FAILED_LOGIN_LIMIT = int(os.environ.get("OPERATOR_FAILED_LOGIN_LIMIT", "5"))
OPERATOR_LOCKOUT_SECONDS = int(os.environ.get("OPERATOR_LOCKOUT_SECONDS", "300"))

if OPERATOR_PASSWORD_HASH:
    _PASSWORD_HASH = OPERATOR_PASSWORD_HASH
else:
    _PASSWORD_HASH = generate_password_hash(OPERATOR_PASSWORD)

app = Flask(__name__)
app.secret_key = OPERATOR_SECRET_KEY
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=False,  # HTTPS termination may be external; tunnel is encrypted.
    PERMANENT_SESSION_LIFETIME=timedelta(minutes=OPERATOR_SESSION_TIMEOUT_MINUTES),
)

_sessions: Dict[str, Dict[str, Any]] = {}
_attacks: List[Dict[str, Any]] = []
_events: List[Dict[str, Any]] = []
_lock = threading.Lock()
_last_loaded_mtime: float = 0.0
_failed_logins: Dict[str, Dict[str, Any]] = {}


def _client_key() -> str:
    forwarded = request.headers.get("X-Forwarded-For", "")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.remote_addr or "unknown"


def _is_locked_out(client: str) -> bool:
    entry = _failed_logins.get(client)
    if not entry:
        return False
    locked_until = entry.get("locked_until")
    if locked_until and time.time() < locked_until:
        return True
    if locked_until and time.time() >= locked_until:
        _failed_logins.pop(client, None)
    return False


def _register_failed_login(client: str) -> None:
    entry = _failed_logins.setdefault(client, {"count": 0, "locked_until": None})
    entry["count"] += 1
    if entry["count"] >= OPERATOR_FAILED_LOGIN_LIMIT:
        entry["locked_until"] = time.time() + OPERATOR_LOCKOUT_SECONDS


def _clear_failed_login(client: str) -> None:
    _failed_logins.pop(client, None)


def login_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if not session.get("operator_authenticated"):
            return redirect(url_for("login"))
        return fn(*args, **kwargs)

    return wrapper


def api_login_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if not session.get("operator_authenticated"):
            return jsonify({"error": "Unauthorized"}), 401
        return fn(*args, **kwargs)

    return wrapper


def _safe_parse_iso(ts: str) -> datetime | None:
    if not isinstance(ts, str) or not ts:
        return None
    try:
        # Keep everything naive for local comparisons
        return datetime.fromisoformat(ts.replace("Z", ""))
    except ValueError:
        return None


def process_event(event: Dict[str, Any]) -> None:
    session_id = str(event.get("session_id", "unknown"))

    if session_id not in _sessions:
        _sessions[session_id] = {
            "id": session_id,
            "ip": str(event.get("ip", "unknown")),
            "first_seen": str(event.get("timestamp", "")),
            "last_seen": str(event.get("timestamp", "")),
            "request_count": 0,
            "attacks_detected": 0,
            "user_agent": str(event.get("user_agent", ""))[:120],
            "stage": str(event.get("stage", "recon")),
            "attack_types": [],
        }

    session_data = _sessions[session_id]
    session_data["last_seen"] = str(event.get("timestamp", session_data["last_seen"]))
    session_data["request_count"] += 1
    session_data["stage"] = str(event.get("stage", session_data["stage"]))

    detected = event.get("detected_attacks", [])
    if isinstance(detected, list):
        session_data["attacks_detected"] += len(detected)
        for attack in detected:
            if not isinstance(attack, dict):
                continue
            attack_type = str(attack.get("type", "unknown"))
            if attack_type not in session_data["attack_types"]:
                session_data["attack_types"].append(attack_type)
            _attacks.append(
                {
                    "session_id": f"{session_id[:16]}...",
                    "ip": str(event.get("ip", "unknown")),
                    "type": attack_type,
                    "severity": str(attack.get("severity", "UNKNOWN")),
                    "endpoint": str(event.get("endpoint", "/")),
                    "timestamp": str(event.get("timestamp", "")),
                }
            )

    _events.append(
        {
            "timestamp": str(event.get("timestamp", "")),
            "session_id": f"{session_id[:16]}...",
            "ip": str(event.get("ip", "unknown")),
            "method": str(event.get("method", "GET")),
            "endpoint": str(event.get("endpoint", "/")),
            "attacks": len(detected) if isinstance(detected, list) else 0,
            "response": int(event.get("response_code", 200)),
        }
    )

    if len(_attacks) > 800:
        del _attacks[:-800]
    if len(_events) > 2000:
        del _events[:-2000]


def load_events_from_file() -> None:
    global _last_loaded_mtime
    if not os.path.exists(LOG_FILE):
        return

    try:
        mtime = os.path.getmtime(LOG_FILE)
        if mtime <= _last_loaded_mtime:
            return

        with open(LOG_FILE, "r", encoding="utf-8") as f:
            sessions_local: Dict[str, Dict[str, Any]] = {}
            attacks_local: List[Dict[str, Any]] = []
            events_local: List[Dict[str, Any]] = []

            for raw_line in f:
                line = raw_line.strip()
                if not line:
                    continue
                try:
                    event = json.loads(line)
                except json.JSONDecodeError:
                    continue

                session_id = str(event.get("session_id", "unknown"))
                if session_id not in sessions_local:
                    sessions_local[session_id] = {
                        "id": session_id,
                        "ip": str(event.get("ip", "unknown")),
                        "first_seen": str(event.get("timestamp", "")),
                        "last_seen": str(event.get("timestamp", "")),
                        "request_count": 0,
                        "attacks_detected": 0,
                        "user_agent": str(event.get("user_agent", ""))[:120],
                        "stage": str(event.get("stage", "recon")),
                        "attack_types": [],
                    }

                session_data = sessions_local[session_id]
                session_data["last_seen"] = str(event.get("timestamp", session_data["last_seen"]))
                session_data["request_count"] += 1
                session_data["stage"] = str(event.get("stage", session_data["stage"]))

                detected = event.get("detected_attacks", [])
                if isinstance(detected, list):
                    session_data["attacks_detected"] += len(detected)
                    for attack in detected:
                        if not isinstance(attack, dict):
                            continue
                        attack_type = str(attack.get("type", "unknown"))
                        if attack_type not in session_data["attack_types"]:
                            session_data["attack_types"].append(attack_type)
                        attacks_local.append(
                            {
                                "session_id": f"{session_id[:16]}...",
                                "ip": str(event.get("ip", "unknown")),
                                "type": attack_type,
                                "severity": str(attack.get("severity", "UNKNOWN")),
                                "endpoint": str(event.get("endpoint", "/")),
                                "timestamp": str(event.get("timestamp", "")),
                            }
                        )

                events_local.append(
                    {
                        "timestamp": str(event.get("timestamp", "")),
                        "session_id": f"{session_id[:16]}...",
                        "ip": str(event.get("ip", "unknown")),
                        "method": str(event.get("method", "GET")),
                        "endpoint": str(event.get("endpoint", "/")),
                        "attacks": len(detected) if isinstance(detected, list) else 0,
                        "response": int(event.get("response_code", 200)),
                    }
                )

        with _lock:
            _sessions.clear()
            _sessions.update(sessions_local)
            _attacks.clear()
            _attacks.extend(attacks_local[-800:])
            _events.clear()
            _events.extend(events_local[-2000:])
            _last_loaded_mtime = mtime
    except OSError:
        return


def get_stats() -> Dict[str, int]:
    now = datetime.now()
    cutoff = now - timedelta(minutes=15)
    active = 0

    for sess in _sessions.values():
        last_seen_dt = _safe_parse_iso(sess.get("last_seen", ""))
        if last_seen_dt and last_seen_dt >= cutoff:
            active += 1

    return {
        "active_sessions": active,
        "total_sessions": len(_sessions),
        "total_requests": sum(s["request_count"] for s in _sessions.values()),
        "total_attacks": sum(s["attacks_detected"] for s in _sessions.values()),
    }


def background_reload() -> None:
    while True:
        time.sleep(2)
        load_events_from_file()


reload_thread = threading.Thread(target=background_reload, daemon=True)
reload_thread.start()


LOGIN_HTML = """
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Operator Login</title>
  <style>
    body { background:#0b0f14; color:#d6e2f0; font-family:Arial,sans-serif; margin:0; min-height:100vh; display:flex; align-items:center; justify-content:center; }
    .card { width:360px; background:#121820; border:1px solid #263241; border-radius:12px; padding:24px; box-shadow:0 8px 24px rgba(0,0,0,.35); }
    h1 { margin:0 0 8px; font-size:20px; color:#7dd3fc; }
    p { margin:0 0 16px; color:#94a3b8; font-size:14px; }
    label { display:block; font-size:13px; margin:10px 0 6px; color:#cbd5e1; }
    input { width:100%; box-sizing:border-box; padding:10px 12px; border-radius:8px; border:1px solid #334155; background:#0f172a; color:#e2e8f0; }
    button { margin-top:14px; width:100%; background:#0284c7; color:white; border:none; border-radius:8px; padding:10px; cursor:pointer; font-weight:600; }
    button:hover { background:#0369a1; }
    .err { margin-top:10px; color:#fca5a5; font-size:13px; }
    .hint { margin-top:8px; color:#64748b; font-size:12px; }
  </style>
</head>
<body>
  <form class="card" method="POST">
    <h1>Operator Dashboard</h1>
    <p>Private monitoring console</p>
    <label for="username">Username</label>
    <input id="username" name="username" type="text" autocomplete="username" required />
    <label for="password">Password</label>
    <input id="password" name="password" type="password" autocomplete="current-password" required />
    <button type="submit">Sign in</button>
    {% if error %}<div class="err">{{ error }}</div>{% endif %}
    <div class="hint">Access via SSH tunnel only.</div>
  </form>
</body>
</html>
"""


DASHBOARD_HTML = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Honeypot Operator Dashboard</title>
    <style>
        * { box-sizing: border-box; margin: 0; padding: 0; }
        body { font-family: Consolas, Monaco, monospace; background: #0a0a0a; color: #00ff88; min-height: 100vh; padding: 1rem; }
        .top { display:flex; justify-content:space-between; align-items:center; margin-bottom:1rem; border-bottom:1px solid #1f2937; padding-bottom:.75rem; }
        .actions { display:flex; gap:.5rem; align-items:center; }
        .btn { color:#0a0a0a; background:#00ff88; text-decoration:none; padding:.35rem .6rem; border-radius:6px; font-weight:700; }
        .stats { display:grid; grid-template-columns:repeat(4,1fr); gap:1rem; margin-bottom:1rem; }
        .card { background:#111; border:1px solid #1f2937; border-radius:8px; padding:1rem; }
        .big { font-size:2rem; color:#7dd3fc; }
        .label { color:#9ca3af; font-size:.8rem; }
        .grid { display:grid; grid-template-columns:1fr 1fr; gap:1rem; }
        .panel { background:#111; border:1px solid #1f2937; border-radius:8px; height:390px; overflow:hidden; display:flex; flex-direction:column; }
        .ph { padding:.6rem .8rem; border-bottom:1px solid #1f2937; color:#cbd5e1; }
        .pc { padding:.5rem; overflow:auto; flex:1; }
        table { width:100%; border-collapse:collapse; font-size:.82rem; }
        th, td { text-align:left; padding:.4rem; border-bottom:1px solid #1f2937; }
        th { color:#94a3b8; }
        .sev-CRITICAL { color:#ef4444; font-weight:700; } .sev-HIGH { color:#f97316; } .sev-MEDIUM { color:#facc15; } .sev-LOW { color:#22c55e; }
        .stage { text-transform:uppercase; font-size:.75rem; color:#93c5fd; }
        .events { font-size:.78rem; }
        .event { border-bottom:1px solid #1f2937; padding:.3rem 0; }
        .muted { color:#9ca3af; }
        .warn { margin-bottom:.75rem; color:#fca5a5; }
    </style>
</head>
<body>
  <div class="warn">Private operator console (localhost only). Use SSH tunnel: local 6001 → VM 127.0.0.1:5001</div>
  <div class="top">
    <h2>Honeypot Operator Dashboard</h2>
    <div class="actions">
      <span class="muted">User: {{ username }}</span>
      <a class="btn" href="/logout">Logout</a>
    </div>
  </div>

  <div class="stats">
    <div class="card"><div id="s-active" class="big">0</div><div class="label">ACTIVE (15m)</div></div>
    <div class="card"><div id="s-total" class="big">0</div><div class="label">TOTAL SESSIONS</div></div>
    <div class="card"><div id="s-req" class="big">0</div><div class="label">TOTAL REQUESTS</div></div>
    <div class="card"><div id="s-att" class="big">0</div><div class="label">TOTAL ATTACKS</div></div>
  </div>

  <div class="grid">
    <div class="panel">
      <div class="ph">Sessions</div>
      <div class="pc">
        <table>
          <thead><tr><th>IP</th><th>Stage</th><th>Req</th><th>Atk</th><th>Last</th></tr></thead>
          <tbody id="sessions"></tbody>
        </table>
      </div>
    </div>
    <div class="panel">
      <div class="ph">Recent attacks</div>
      <div class="pc">
        <table>
          <thead><tr><th>Time</th><th>IP</th><th>Type</th><th>Severity</th></tr></thead>
          <tbody id="attacks"></tbody>
        </table>
      </div>
    </div>
  </div>

  <div class="panel" style="margin-top:1rem;height:260px;">
    <div class="ph">Events</div>
    <div id="events" class="pc events"></div>
  </div>

  <script>
    function t(ts){ try{return new Date(ts).toLocaleTimeString()}catch{return '-'} }
    function esc(v){ return String(v ?? '').replace(/[&<>"]/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c])); }

    async function j(u){
      const r = await fetch(u, { credentials: 'same-origin' });
      if (r.status === 401) { window.location = '/login'; return null; }
      return r.json();
    }

    async function refresh(){
      const [stats, sessions, attacks, events] = await Promise.all([j('/api/stats'), j('/api/sessions'), j('/api/attacks'), j('/api/events')]);
      if(!stats || !sessions || !attacks || !events) return;

      document.getElementById('s-active').textContent = stats.active_sessions;
      document.getElementById('s-total').textContent = stats.total_sessions;
      document.getElementById('s-req').textContent = stats.total_requests;
      document.getElementById('s-att').textContent = stats.total_attacks;

      const s = document.getElementById('sessions');
      if(!sessions.length){ s.innerHTML = '<tr><td colspan="5" class="muted">No sessions</td></tr>'; }
      else {
        s.innerHTML = sessions.slice(0,50).map(x =>
          `<tr><td>${esc(x.ip)}</td><td class="stage">${esc(x.stage)}</td><td>${x.requests}</td><td>${x.attacks}</td><td>${t(x.last_seen)}</td></tr>`
        ).join('');
      }

      const a = document.getElementById('attacks');
      if(!attacks.length){ a.innerHTML = '<tr><td colspan="4" class="muted">No attacks</td></tr>'; }
      else {
        a.innerHTML = attacks.slice(0,100).map(x =>
          `<tr><td>${t(x.timestamp)}</td><td>${esc(x.ip)}</td><td>${esc(x.type)}</td><td class="sev-${esc(x.severity)}">${esc(x.severity)}</td></tr>`
        ).join('');
      }

      const e = document.getElementById('events');
      if(!events.length){ e.innerHTML = '<div class="muted">No events</div>'; }
      else {
        e.innerHTML = events.slice(0,150).map(x =>
          `<div class="event">${t(x.timestamp)} <span class="muted">${esc(x.ip)}</span> ${esc(x.method)} ${esc(x.endpoint)} ${x.attacks ? '['+x.attacks+' atk]' : ''} <span class="muted">[${x.response}]</span></div>`
        ).join('');
      }
    }
    refresh();
    setInterval(refresh, 3000);
  </script>
</body>
</html>
"""


@app.route("/")
@login_required
def dashboard():
    return render_template_string(DASHBOARD_HTML, username=session.get("operator_username", OPERATOR_USERNAME))


@app.route("/login", methods=["GET", "POST"])
def login():
    client = _client_key()
    if request.method == "POST":
        if _is_locked_out(client):
            return render_template_string(LOGIN_HTML, error="Too many failed attempts. Try again later."), 429

        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        if username == OPERATOR_USERNAME and check_password_hash(_PASSWORD_HASH, password):
            _clear_failed_login(client)
            session.clear()
            session["operator_authenticated"] = True
            session["operator_username"] = username
            session.permanent = True
            return redirect(url_for("dashboard"))

        _register_failed_login(client)
        return render_template_string(LOGIN_HTML, error="Invalid username or password"), 401

    return render_template_string(LOGIN_HTML, error=None)


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


@app.route("/api/stats")
@api_login_required
def api_stats():
    with _lock:
        return jsonify(get_stats())


@app.route("/api/sessions")
@api_login_required
def api_sessions():
    with _lock:
        rows = []
        for sid, data in _sessions.items():
            rows.append(
                {
                    "id": f"{sid[:16]}...",
                    "ip": data["ip"],
                    "first_seen": data["first_seen"],
                    "last_seen": data["last_seen"],
                    "requests": data["request_count"],
                    "attacks": data["attacks_detected"],
                    "stage": data["stage"],
                    "attack_types": data["attack_types"],
                }
            )
        rows.sort(key=lambda x: x["last_seen"] or "", reverse=True)
        return jsonify(rows[:80])


@app.route("/api/attacks")
@api_login_required
def api_attacks():
    with _lock:
        return jsonify(list(reversed(_attacks[-120:])))


@app.route("/api/events")
@api_login_required
def api_events():
    with _lock:
        return jsonify(list(reversed(_events[-300:])))


if __name__ == "__main__":
    print(
        f"""
╔══════════════════════════════════════════════════════════════╗
║                 HONEYPOT OPERATOR CONSOLE                   ║
║                                                              ║
║  VM bind:    {OPERATOR_HOST}:{OPERATOR_PORT:<40}║
║  Username:   {OPERATOR_USERNAME:<40}║
║  Access:     SSH tunnel only                                 ║
║                                                              ║
║  Example local tunnel:                                       ║
║  ssh -L 6001:127.0.0.1:5001 <user>@<vm-ip>                  ║
║  then open: http://127.0.0.1:6001                           ║
╚══════════════════════════════════════════════════════════════╝
"""
    )
    ensure_operator_log_file()
    load_events_from_file()
    app.run(host=OPERATOR_HOST, port=OPERATOR_PORT, debug=False)
