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
OPERATOR_ACTIVE_WINDOW_MINUTES = int(os.environ.get("OPERATOR_ACTIVE_WINDOW_MINUTES", "15"))
OPERATOR_GROUP_ACTIVE_BY_IP = os.environ.get("OPERATOR_GROUP_ACTIVE_BY_IP", "1").strip().lower() not in {
    "0", "false", "no"
}

# Keep operator dashboard local-only by default for safety.
_ALLOW_REMOTE_OPERATOR = os.environ.get("ALLOW_REMOTE_OPERATOR", "0").strip().lower() in {
    "1", "true", "yes", "on"
}
if not _ALLOW_REMOTE_OPERATOR and OPERATOR_HOST not in {"127.0.0.1", "localhost", "::1"}:
    print(
        "[operator] OPERATOR_HOST is not local but remote operator access is disabled. "
        "Forcing OPERATOR_HOST=127.0.0.1"
    )
    OPERATOR_HOST = "127.0.0.1"

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


def _safe_int(value: Any, default: int = 0) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _is_asset_endpoint(endpoint: str) -> bool:
    normalized = str(endpoint or "").lower()
    if not normalized:
        return False
    return (
        normalized.startswith("/static/")
        or normalized in {"/favicon.ico", "/robots.txt", "/sitemap.xml"}
        or normalized.endswith((".css", ".js", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".webp", ".map"))
    )


def _session_is_active(session_data: Dict[str, Any], now: datetime | None = None) -> bool:
    now = now or datetime.now()
    cutoff = now - timedelta(minutes=OPERATOR_ACTIVE_WINDOW_MINUTES)
    last_seen_dt = _safe_parse_iso(str(session_data.get("last_seen", "")))
    return bool(last_seen_dt and last_seen_dt >= cutoff)


def _build_recent_actions_index(max_events: int = 1500, per_session: int = 8) -> Dict[str, List[Dict[str, Any]]]:
    actions: Dict[str, List[Dict[str, Any]]] = {}
    scanned = 0
    for event in reversed(_events):
        if scanned >= max_events:
            break
        scanned += 1

        session_id_full = str(event.get("session_id_full", ""))
        if not session_id_full:
            continue

        session_actions = actions.setdefault(session_id_full, [])
        if len(session_actions) >= per_session:
            continue

        session_actions.append(
            {
                "timestamp": str(event.get("timestamp", "")),
                "method": str(event.get("method", "GET")),
                "endpoint": str(event.get("endpoint", "/")),
                "response": _safe_int(event.get("response"), 200),
                "attacks": _safe_int(event.get("attacks"), 0),
                "is_asset_request": bool(event.get("is_asset_request", False)),
            }
        )

    return actions


def _canonical_ip(ip_value: Any) -> str:
    raw = str(ip_value or "unknown").strip()
    if not raw:
        return "unknown"
    return raw.split(",")[0].strip() or "unknown"


def _stage_rank(stage: str) -> int:
    order = {
        "recon": 0,
        "initial_access": 1,
        "access": 1,
        "privilege_escalation": 2,
        "escalate": 2,
        "persistence": 3,
        "persist": 3,
        "data_exfiltration": 4,
    }
    return order.get(str(stage).lower(), 0)


def _skill_rank(skill: str) -> int:
    return {"basic": 0, "intermediate": 1, "advanced": 2}.get(str(skill).lower(), 0)


def _collapse_active_rows_by_ip(rows: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    grouped: Dict[str, Dict[str, Any]] = {}

    for row in rows:
        ip_key = _canonical_ip(row.get("ip", "unknown"))
        row_ip = dict(row)
        row_ip["ip"] = ip_key

        if ip_key not in grouped:
            row_ip["id"] = f"ip:{ip_key}"
            row_ip["session_count"] = 1
            source_id = str(row_ip.get("full_id", "")).strip()
            row_ip["source_session_ids"] = [source_id] if source_id else []
            username = str(row_ip.get("authenticated_username", "")).strip()
            row_ip["authenticated_usernames"] = [username] if username else []
            grouped[ip_key] = row_ip
            continue

        current = grouped[ip_key]
        current["session_count"] = _safe_int(current.get("session_count"), 1) + 1
        source_id = str(row_ip.get("full_id", "")).strip()
        if source_id:
            existing_source_ids = current.setdefault("source_session_ids", [])
            if source_id not in existing_source_ids:
                existing_source_ids.append(source_id)

        incoming_username = str(row_ip.get("authenticated_username", "")).strip()
        if incoming_username:
            existing_usernames = current.setdefault("authenticated_usernames", [])
            if incoming_username not in existing_usernames:
                existing_usernames.append(incoming_username)
            if not str(current.get("authenticated_username", "")).strip():
                current["authenticated_username"] = incoming_username

        incoming_role = str(row_ip.get("authenticated_role", "anonymous")).strip() or "anonymous"
        current_role = str(current.get("authenticated_role", "anonymous")).strip() or "anonymous"
        if current_role == "anonymous" and incoming_role != "anonymous":
            current["authenticated_role"] = incoming_role

        incoming_tier = str(row_ip.get("authenticated_service_tier", "")).strip()
        if incoming_tier and not str(current.get("authenticated_service_tier", "")).strip():
            current["authenticated_service_tier"] = incoming_tier

        current["requests"] = _safe_int(current.get("requests"), 0) + _safe_int(row_ip.get("requests"), 0)
        current["attacks"] = _safe_int(current.get("attacks"), 0) + _safe_int(row_ip.get("attacks"), 0)
        current["asset_requests"] = _safe_int(current.get("asset_requests"), 0) + _safe_int(row_ip.get("asset_requests"), 0)
        current["interaction_requests"] = _safe_int(current.get("interaction_requests"), 0) + _safe_int(row_ip.get("interaction_requests"), 0)

        if _stage_rank(str(row_ip.get("chain_stage", "recon"))) > _stage_rank(str(current.get("chain_stage", "recon"))):
            current["chain_stage"] = row_ip.get("chain_stage", current.get("chain_stage", "recon"))
            current["stage"] = row_ip.get("stage", current.get("stage", "recon"))

        current["chain_progression"] = max(
            float(current.get("chain_progression", 0.0) or 0.0),
            float(row_ip.get("chain_progression", 0.0) or 0.0),
        )
        current["chain_scenarios_completed"] = max(
            _safe_int(current.get("chain_scenarios_completed"), 0),
            _safe_int(row_ip.get("chain_scenarios_completed"), 0),
        )
        current["time_spent_seconds"] = max(
            _safe_int(current.get("time_spent_seconds"), 0),
            _safe_int(row_ip.get("time_spent_seconds"), 0),
        )

        if _skill_rank(str(row_ip.get("skill_level", "basic"))) > _skill_rank(str(current.get("skill_level", "basic"))):
            current["skill_level"] = row_ip.get("skill_level", current.get("skill_level", "basic"))

        attack_union = set(str(v) for v in current.get("attack_types", [])) | set(str(v) for v in row_ip.get("attack_types", []))
        current["attack_types"] = sorted(attack_union)

        current_path = list(current.get("chain_attack_path", []))
        row_path = list(row_ip.get("chain_attack_path", []))
        if len(row_path) > len(current_path):
            current["chain_attack_path"] = row_path

        merged_timeline = list(current.get("chain_timeline", [])) + list(row_ip.get("chain_timeline", []))
        merged_timeline.sort(key=lambda item: str(item.get("timestamp", "")), reverse=True)
        current["chain_timeline"] = merged_timeline[:15]

        merged_actions = list(current.get("recent_actions", [])) + list(row_ip.get("recent_actions", []))
        merged_actions.sort(key=lambda item: str(item.get("timestamp", "")), reverse=True)
        current["recent_actions"] = merged_actions[:8]

        current_last_seen = _safe_parse_iso(str(current.get("last_seen", "")))
        row_last_seen = _safe_parse_iso(str(row_ip.get("last_seen", "")))
        if row_last_seen and (not current_last_seen or row_last_seen > current_last_seen):
            current["last_seen"] = row_ip.get("last_seen", current.get("last_seen", ""))
            current["authenticated_username"] = row_ip.get(
                "authenticated_username", current.get("authenticated_username", "")
            )
            current["authenticated_role"] = row_ip.get(
                "authenticated_role", current.get("authenticated_role", "anonymous")
            )
            current["authenticated_service_tier"] = row_ip.get(
                "authenticated_service_tier", current.get("authenticated_service_tier", "")
            )

        current_first_seen = _safe_parse_iso(str(current.get("first_seen", "")))
        row_first_seen = _safe_parse_iso(str(row_ip.get("first_seen", "")))
        if row_first_seen and (not current_first_seen or row_first_seen < current_first_seen):
            current["first_seen"] = row_ip.get("first_seen", current.get("first_seen", ""))

    now = datetime.now()
    collapsed_rows = list(grouped.values())
    for row in collapsed_rows:
        last_seen_dt = _safe_parse_iso(str(row.get("last_seen", "")))
        first_seen_dt = _safe_parse_iso(str(row.get("first_seen", "")))
        row["seconds_since_seen"] = int((now - last_seen_dt).total_seconds()) if last_seen_dt else None
        row["age_seconds"] = int((now - first_seen_dt).total_seconds()) if first_seen_dt else None
        usernames = [str(v).strip() for v in row.get("authenticated_usernames", []) if str(v).strip()]
        if usernames and not str(row.get("authenticated_username", "")).strip():
            row["authenticated_username"] = usernames[0]

    collapsed_rows.sort(key=lambda x: x.get("last_seen") or "", reverse=True)
    return collapsed_rows


def _session_rows(
    scope: str = "all",
    limit: int = 80,
    ip_filter: str = "",
    stage_filter: str = "",
    attack_type_filter: str = ""
) -> List[Dict[str, Any]]:
    now = datetime.now()
    actions = _build_recent_actions_index()
    rows: List[Dict[str, Any]] = []

    ip_filter = ip_filter.strip().lower()
    stage_filter = stage_filter.strip().lower()
    attack_type_filter = attack_type_filter.strip().lower()

    for sid, data in _sessions.items():
        is_active = _session_is_active(data, now)
        if scope == "active" and not is_active:
            continue
        if scope == "history" and is_active:
            continue

        stage_value = str(data.get("chain_stage") or data.get("stage", "recon")).lower()
        if ip_filter and ip_filter not in str(data.get("ip", "")).lower():
            continue
        if stage_filter and stage_filter != stage_value:
            continue
        if attack_type_filter:
            existing_types = [str(v).lower() for v in data.get("attack_types", [])]
            if not any(attack_type_filter in t for t in existing_types):
                continue

        last_seen_raw = str(data.get("last_seen", ""))
        first_seen_raw = str(data.get("first_seen", ""))
        last_seen_dt = _safe_parse_iso(last_seen_raw)
        first_seen_dt = _safe_parse_iso(first_seen_raw)

        rows.append(
            {
                "id": f"{sid[:16]}...",
                "full_id": sid,
                "ip": _canonical_ip(data.get("ip", "unknown")),
                "authenticated_username": str(data.get("authenticated_username", "")),
                "authenticated_role": str(data.get("authenticated_role", "anonymous")),
                "authenticated_service_tier": str(data.get("authenticated_service_tier", "")),
                "first_seen": first_seen_raw,
                "last_seen": last_seen_raw,
                "requests": _safe_int(data.get("request_count"), 0),
                "attacks": _safe_int(data.get("attacks_detected"), 0),
                "stage": str(data.get("stage", "recon")),
                "chain_stage": str(data.get("chain_stage", data.get("stage", "recon"))),
                "chain_progression": float(data.get("chain_progression", 0.0)),
                "chain_scenarios_completed": _safe_int(data.get("chain_scenarios_completed"), 0),
                "chain_attack_path": list(data.get("chain_attack_path", [str(data.get("stage", "recon"))])),
                "chain_timeline": list(data.get("chain_timeline", []))[-15:],
                "skill_level": str(data.get("skill_level", "basic")),
                "time_spent_seconds": _safe_int(data.get("time_spent_seconds"), 0),
                "attack_types": list(data.get("attack_types", [])),
                "user_agent": str(data.get("user_agent", "")),
                "active": is_active,
                "seconds_since_seen": int((now - last_seen_dt).total_seconds()) if last_seen_dt else None,
                "age_seconds": int((now - first_seen_dt).total_seconds()) if first_seen_dt else None,
                "asset_requests": _safe_int(data.get("asset_requests"), 0),
                "interaction_requests": _safe_int(data.get("interaction_requests"), 0),
                "recent_actions": actions.get(sid, []),
            }
        )

    if scope == "active" and OPERATOR_GROUP_ACTIVE_BY_IP:
        rows = _collapse_active_rows_by_ip(rows)

    rows.sort(key=lambda x: x.get("last_seen") or "", reverse=True)
    return rows[:limit]


def process_event(event: Dict[str, Any]) -> None:
    session_id = str(event.get("session_id", "unknown"))
    endpoint = str(event.get("endpoint", "/"))
    ip_value = _canonical_ip(event.get("ip", "unknown"))
    is_asset_request = _is_asset_endpoint(endpoint)

    if session_id not in _sessions:
        _sessions[session_id] = {
            "id": session_id,
            "ip": ip_value,
            "authenticated_username": str(event.get("authenticated_username", "")).strip(),
            "authenticated_role": str(event.get("authenticated_role", "anonymous")).strip() or "anonymous",
            "authenticated_service_tier": str(event.get("authenticated_service_tier", "")).strip(),
            "first_seen": str(event.get("timestamp", "")),
            "last_seen": str(event.get("timestamp", "")),
            "request_count": 0,
            "attacks_detected": 0,
            "user_agent": str(event.get("user_agent", ""))[:120],
            "stage": str(event.get("stage", "recon")),
            "chain_stage": str(event.get("chain_stage", event.get("stage", "recon"))),
            "chain_progression": float(event.get("chain_progression", 0.0) or 0.0),
            "chain_scenarios_completed": _safe_int(event.get("chain_scenarios_completed"), 0),
            "chain_attack_path": list(event.get("chain_attack_path", [str(event.get("chain_stage", event.get("stage", "recon")))])),
            "chain_timeline": list(event.get("chain_timeline", []))[-20:],
            "skill_level": str(event.get("attacker_skill_level", "basic")),
            "time_spent_seconds": _safe_int(event.get("time_spent_seconds"), 0),
            "attack_types": [],
            "asset_requests": 0,
            "interaction_requests": 0,
        }

    session_data = _sessions[session_id]
    session_data["last_seen"] = str(event.get("timestamp", session_data["last_seen"]))
    session_data["request_count"] += 1
    session_data["stage"] = str(event.get("stage", session_data["stage"]))
    session_data["chain_stage"] = str(event.get("chain_stage", session_data.get("chain_stage", session_data["stage"])))
    try:
        session_data["chain_progression"] = float(event.get("chain_progression", session_data.get("chain_progression", 0.0)))
    except (TypeError, ValueError):
        pass
    session_data["chain_scenarios_completed"] = _safe_int(
        event.get("chain_scenarios_completed", session_data.get("chain_scenarios_completed", 0))
    )
    incoming_username = str(event.get("authenticated_username", "")).strip()
    if incoming_username:
        session_data["authenticated_username"] = incoming_username

    incoming_role = str(event.get("authenticated_role", "anonymous")).strip() or "anonymous"
    if incoming_role != "anonymous" or not str(session_data.get("authenticated_role", "")).strip():
        session_data["authenticated_role"] = incoming_role

    incoming_tier = str(event.get("authenticated_service_tier", "")).strip()
    if incoming_tier:
        session_data["authenticated_service_tier"] = incoming_tier

    session_data["skill_level"] = str(event.get("attacker_skill_level", session_data.get("skill_level", "basic")))
    session_data["time_spent_seconds"] = _safe_int(
        event.get("time_spent_seconds", session_data.get("time_spent_seconds", 0))
    )

    incoming_path = event.get("chain_attack_path", [])
    if isinstance(incoming_path, list) and incoming_path:
        session_data["chain_attack_path"] = list(incoming_path)
    elif "chain_attack_path" not in session_data:
        session_data["chain_attack_path"] = [session_data.get("chain_stage", session_data["stage"])]

    incoming_timeline = event.get("chain_timeline", [])
    if isinstance(incoming_timeline, list) and incoming_timeline:
        session_data["chain_timeline"] = incoming_timeline[-20:]
    if is_asset_request:
        session_data["asset_requests"] += 1
    else:
        session_data["interaction_requests"] += 1

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
                    "session_id_full": session_id,
                    "ip": ip_value,
                    "type": attack_type,
                    "severity": str(attack.get("severity", "UNKNOWN")),
                    "endpoint": endpoint,
                    "timestamp": str(event.get("timestamp", "")),
                }
            )

    _events.append(
        {
            "timestamp": str(event.get("timestamp", "")),
            "session_id": f"{session_id[:16]}...",
            "session_id_full": session_id,
            "ip": ip_value,
            "authenticated_username": str(event.get("authenticated_username", "")).strip(),
            "authenticated_role": str(event.get("authenticated_role", "anonymous")).strip() or "anonymous",
            "method": str(event.get("method", "GET")),
            "endpoint": endpoint,
            "attacks": len(detected) if isinstance(detected, list) else 0,
            "response": _safe_int(event.get("response_code"), 200),
            "is_asset_request": is_asset_request,
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
                        "ip": _canonical_ip(event.get("ip", "unknown")),
                        "authenticated_username": str(event.get("authenticated_username", "")).strip(),
                        "authenticated_role": str(event.get("authenticated_role", "anonymous")).strip() or "anonymous",
                        "authenticated_service_tier": str(event.get("authenticated_service_tier", "")).strip(),
                        "first_seen": str(event.get("timestamp", "")),
                        "last_seen": str(event.get("timestamp", "")),
                        "request_count": 0,
                        "attacks_detected": 0,
                        "user_agent": str(event.get("user_agent", ""))[:120],
                        "stage": str(event.get("stage", "recon")),
                        "chain_stage": str(event.get("chain_stage", event.get("stage", "recon"))),
                        "chain_progression": float(event.get("chain_progression", 0.0) or 0.0),
                        "chain_scenarios_completed": _safe_int(event.get("chain_scenarios_completed"), 0),
                        "chain_attack_path": list(event.get("chain_attack_path", [str(event.get("chain_stage", event.get("stage", "recon")))])),
                        "chain_timeline": list(event.get("chain_timeline", []))[-20:],
                        "skill_level": str(event.get("attacker_skill_level", "basic")),
                        "time_spent_seconds": _safe_int(event.get("time_spent_seconds"), 0),
                        "attack_types": [],
                        "asset_requests": 0,
                        "interaction_requests": 0,
                    }

                session_data = sessions_local[session_id]
                session_data["last_seen"] = str(event.get("timestamp", session_data["last_seen"]))
                session_data["request_count"] += 1
                session_data["stage"] = str(event.get("stage", session_data["stage"]))
                session_data["chain_stage"] = str(event.get("chain_stage", session_data.get("chain_stage", session_data["stage"])))
                try:
                    session_data["chain_progression"] = float(event.get("chain_progression", session_data.get("chain_progression", 0.0)))
                except (TypeError, ValueError):
                    pass
                session_data["chain_scenarios_completed"] = _safe_int(
                    event.get("chain_scenarios_completed", session_data.get("chain_scenarios_completed", 0))
                )
                incoming_username = str(event.get("authenticated_username", "")).strip()
                if incoming_username:
                    session_data["authenticated_username"] = incoming_username
                incoming_role = str(event.get("authenticated_role", "anonymous")).strip() or "anonymous"
                if incoming_role != "anonymous" or not str(session_data.get("authenticated_role", "")).strip():
                    session_data["authenticated_role"] = incoming_role
                incoming_tier = str(event.get("authenticated_service_tier", "")).strip()
                if incoming_tier:
                    session_data["authenticated_service_tier"] = incoming_tier
                session_data["skill_level"] = str(event.get("attacker_skill_level", session_data.get("skill_level", "basic")))
                session_data["time_spent_seconds"] = _safe_int(
                    event.get("time_spent_seconds", session_data.get("time_spent_seconds", 0))
                )
                incoming_path = event.get("chain_attack_path", [])
                if isinstance(incoming_path, list) and incoming_path:
                    session_data["chain_attack_path"] = list(incoming_path)
                incoming_timeline = event.get("chain_timeline", [])
                if isinstance(incoming_timeline, list) and incoming_timeline:
                    session_data["chain_timeline"] = incoming_timeline[-20:]
                endpoint = str(event.get("endpoint", "/"))
                is_asset_request = _is_asset_endpoint(endpoint)
                if is_asset_request:
                    session_data["asset_requests"] += 1
                else:
                    session_data["interaction_requests"] += 1

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
                                "session_id_full": session_id,
                                "ip": _canonical_ip(event.get("ip", "unknown")),
                                "type": attack_type,
                                "severity": str(attack.get("severity", "UNKNOWN")),
                                "endpoint": endpoint,
                                "timestamp": str(event.get("timestamp", "")),
                            }
                        )

                events_local.append(
                    {
                        "timestamp": str(event.get("timestamp", "")),
                        "session_id": f"{session_id[:16]}...",
                        "session_id_full": session_id,
                        "ip": _canonical_ip(event.get("ip", "unknown")),
                        "authenticated_username": str(event.get("authenticated_username", "")).strip(),
                        "authenticated_role": str(event.get("authenticated_role", "anonymous")).strip() or "anonymous",
                        "method": str(event.get("method", "GET")),
                        "endpoint": endpoint,
                        "attacks": len(detected) if isinstance(detected, list) else 0,
                        "response": _safe_int(event.get("response_code"), 200),
                        "is_asset_request": is_asset_request,
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
    active = sum(1 for sess in _sessions.values() if _session_is_active(sess, now))

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
                body {
                        font-family: Consolas, Monaco, monospace;
                        background: radial-gradient(circle at 12% 20%, #151f2a 0%, #0a1118 45%, #05080d 100%);
                        color: #d2f7ee;
                        min-height: 100vh;
                        padding: 1rem;
                }
                .shell {
                        border: 1px solid #223140;
                        border-radius: 14px;
                        background: rgba(6, 12, 18, 0.86);
                        padding: 1rem;
                        box-shadow: 0 18px 40px rgba(0, 0, 0, 0.45);
                }
                .top {
                        display: flex;
                        justify-content: space-between;
                        align-items: center;
                        gap: 1rem;
                        padding-bottom: .8rem;
                        border-bottom: 1px solid #223140;
                        margin-bottom: 1rem;
                }
                .top h2 { color: #87f1ff; font-size: 1.1rem; letter-spacing: .03em; }
                .subtitle { color: #8ba3b8; font-size: .78rem; margin-top: .15rem; }
                .actions { display:flex; gap:.5rem; align-items:center; }
                .btn {
                        color: #031216;
                        background: linear-gradient(135deg, #6ff5c7, #45d6ff);
                        text-decoration: none;
                        padding: .35rem .6rem;
                        border-radius: 7px;
                        font-weight: 700;
                }
                .badge-user {
                        color: #b9d8e8;
                        border: 1px solid #2c4559;
                        border-radius: 7px;
                        padding: .3rem .5rem;
                        font-size: .78rem;
                }
                .warn {
                        margin-bottom: .9rem;
                        color: #ffb8b8;
                        border: 1px dashed #62333d;
                        border-radius: 8px;
                        padding: .45rem .6rem;
                        background: rgba(93, 33, 42, .14);
                        font-size: .78rem;
                }
                .stats {
                        display: grid;
                        grid-template-columns: repeat(4, minmax(0, 1fr));
                        gap: .65rem;
                        margin-bottom: .9rem;
                }
                .stat {
                        background: linear-gradient(180deg, rgba(22, 33, 44, .8), rgba(14, 22, 31, .8));
                        border: 1px solid #213242;
                        border-radius: 10px;
                        padding: .75rem;
                }
                .big { font-size: 1.75rem; color: #6cfad3; font-weight: 700; }
                .label { color: #91a6b8; font-size: .72rem; margin-top: .2rem; letter-spacing: .04em; }
                .filters {
                    display: grid;
                    grid-template-columns: 1.2fr 1fr 1fr auto;
                    gap: .5rem;
                    margin-bottom: .9rem;
                }
                .f-input, .f-select {
                    width: 100%;
                    background: #0c1620;
                    border: 1px solid #284153;
                    border-radius: 8px;
                    color: #c3d8e8;
                    padding: .45rem .55rem;
                    font-size: .76rem;
                }
                .f-btn {
                    border: 1px solid #3b5d74;
                    background: #102131;
                    color: #b6d7ee;
                    border-radius: 8px;
                    padding: .45rem .6rem;
                    cursor: pointer;
                    font-size: .76rem;
                }
                .grid {
                        display: grid;
                        grid-template-columns: 2fr 1.1fr;
                        gap: .7rem;
                }
                .panel {
                        background: rgba(8, 15, 22, .88);
                        border: 1px solid #1d2d3b;
                        border-radius: 10px;
                        min-height: 320px;
                        display: flex;
                        flex-direction: column;
                        overflow: hidden;
                }
                .ph {
                        padding: .62rem .78rem;
                        border-bottom: 1px solid #1d2d3b;
                        color: #b6cfdf;
                        display: flex;
                        justify-content: space-between;
                        align-items: center;
                        font-size: .82rem;
                }
                .pc { padding: .55rem; overflow: auto; flex: 1; }
                .active-wall {
                        display: grid;
                        grid-template-columns: repeat(auto-fill, minmax(280px, 1fr));
                        gap: .55rem;
                }
                .session-card {
                        border: 1px solid #27465b;
                        background: linear-gradient(180deg, rgba(20, 37, 51, .62), rgba(11, 20, 30, .62));
                        border-radius: 9px;
                        padding: .6rem;
                }
                .session-head {
                        display: flex;
                        justify-content: space-between;
                        gap: .5rem;
                        margin-bottom: .4rem;
                        color: #a8ddff;
                        font-size: .82rem;
                }
                .mono { font-family: Consolas, Monaco, monospace; }
                .stage {
                        text-transform: uppercase;
                        font-size: .67rem;
                        letter-spacing: .08em;
                        color: #9ce9ff;
                        background: rgba(47, 96, 121, .32);
                        border-radius: 999px;
                        padding: .16rem .44rem;
                }
                .metrics {
                        display: grid;
                        grid-template-columns: repeat(2, minmax(0, 1fr));
                        gap: .35rem;
                        margin-bottom: .45rem;
                }
                .metric {
                        border: 1px solid #1e3648;
                        border-radius: 7px;
                        padding: .3rem .42rem;
                        font-size: .73rem;
                        color: #9cb4c5;
                }
                .metric b { color: #d7ffef; }
                .types {
                        margin-bottom: .45rem;
                        display: flex;
                        flex-wrap: wrap;
                        gap: .25rem;
                }
                .chip {
                        border: 1px solid #3a5366;
                        color: #b5d5ea;
                        border-radius: 999px;
                        padding: .1rem .45rem;
                        font-size: .64rem;
                }
                .actions-feed {
                        border-top: 1px dashed #2b4153;
                        padding-top: .35rem;
                        font-size: .72rem;
                }
                .chain {
                    border-top: 1px dashed #2b4153;
                    border-bottom: 1px dashed #2b4153;
                    margin: .42rem 0;
                    padding: .32rem 0;
                    color: #9bc8e6;
                    font-size: .69rem;
                }
                .timeline {
                    margin-top: .35rem;
                    font-size: .68rem;
                    color: #a3bdd0;
                }
                .tl-item {
                    border-left: 2px solid #274761;
                    padding-left: .35rem;
                    margin: .2rem 0;
                    white-space: nowrap;
                    overflow: hidden;
                    text-overflow: ellipsis;
                }
                .act {
                        display: flex;
                        justify-content: space-between;
                        gap: .5rem;
                        border-bottom: 1px solid rgba(35, 52, 66, .55);
                        padding: .18rem 0;
                }
                .act:last-child { border-bottom: none; }
                .act-left { color: #c4d8e8; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
                .act-right { color: #92aabc; }
                .asset { color: #738ca1; }
                .sev-CRITICAL { color:#ff6666; font-weight:700; }
                .sev-HIGH { color:#ff9f66; }
                .sev-MEDIUM { color:#ffd66e; }
                .sev-LOW { color:#89efb6; }
                table { width: 100%; border-collapse: collapse; font-size: .76rem; }
                th, td { text-align: left; padding: .38rem; border-bottom: 1px solid #1a2935; }
                th { color: #8ea5b8; font-size: .7rem; letter-spacing: .03em; }
                .events { font-size: .72rem; }
                .event {
                        border-bottom: 1px solid #1a2a36;
                        padding: .26rem 0;
                        color: #bfd4e3;
                        display: flex;
                        justify-content: space-between;
                        gap: .8rem;
                }
                .event:last-child { border-bottom: none; }
                .event-main { white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
                .muted { color: #7f93a4; }
                .danger { color: #ff8f8f; }
                .ok { color: #97f7c3; }
                .empty {
                        color: #7f93a4;
                        border: 1px dashed #2a3d4d;
                        border-radius: 8px;
                        padding: .7rem;
                        text-align: center;
                        margin: .2rem;
                        font-size: .78rem;
                }

                @media (max-width: 1020px) {
                        .stats { grid-template-columns: repeat(2, minmax(0, 1fr)); }
                    .filters { grid-template-columns: 1fr 1fr; }
                        .grid { grid-template-columns: 1fr; }
                }

                @media (max-width: 640px) {
                        body { padding: .5rem; }
                        .shell { padding: .7rem; }
                        .top { flex-direction: column; align-items: flex-start; }
                        .actions { width: 100%; justify-content: space-between; }
                        .stats { grid-template-columns: 1fr; }
                        .filters { grid-template-columns: 1fr; }
                        .active-wall { grid-template-columns: 1fr; }
                }
    </style>
</head>
<body>
    <div class="shell">
        <div class="warn">Private operator console (localhost only). Tunnel example: local 6001 -> VM 127.0.0.1:5001</div>
        <div class="top">
            <div>
                <h2>Honeypot Operator Matrix</h2>
                <div class="subtitle">Live sessions, actions, and historical traffic from real event logs</div>
            </div>
            <div class="actions">
                <span class="badge-user">User: {{ username }}</span>
                <a class="btn" href="/logout">Logout</a>
            </div>
    </div>

        <div class="stats">
            <div class="stat"><div id="s-active" class="big">0</div><div class="label">ACTIVE SESSIONS (15M)</div></div>
            <div class="stat"><div id="s-total" class="big">0</div><div class="label">TOTAL SESSIONS</div></div>
            <div class="stat"><div id="s-req" class="big">0</div><div class="label">TOTAL REQUESTS</div></div>
            <div class="stat"><div id="s-att" class="big">0</div><div class="label">TOTAL ATTACKS</div></div>
        </div>

        <div class="filters">
            <input id="f-ip" class="f-input" placeholder="Filter by IP (contains)" />
            <select id="f-stage" class="f-select">
                <option value="">All stages</option>
                <option value="recon">recon</option>
                <option value="initial_access">initial_access</option>
                <option value="privilege_escalation">privilege_escalation</option>
                <option value="persistence">persistence</option>
                <option value="data_exfiltration">data_exfiltration</option>
            </select>
            <input id="f-attack" class="f-input" placeholder="Filter by attack type" />
            <button id="f-clear" class="f-btn" type="button">Clear Filters</button>
        </div>

        <div class="grid">
            <div class="panel">
                <div class="ph"><span>Active Users</span><span id="active-count" class="muted">0</span></div>
                <div class="pc">
                    <div id="active-wall" class="active-wall"></div>
                </div>
      </div>

            <div class="panel">
                <div class="ph"><span>Recent Attacks</span><span id="attack-count" class="muted">0</span></div>
                <div class="pc">
                    <table>
                        <thead><tr><th>Time</th><th>IP</th><th>Type</th><th>Severity</th></tr></thead>
                        <tbody id="attacks"></tbody>
                    </table>
                </div>
      </div>
    </div>

        <div class="panel" style="margin-top:.7rem; min-height: 240px;">
            <div class="ph"><span>Historical Sessions</span><span id="history-count" class="muted">0</span></div>
            <div class="pc">
                <table>
                    <thead><tr><th>Last Seen</th><th>IP</th><th>User</th><th>Req</th><th>Interactive</th><th>Assets</th><th>Attacks</th><th>Stage</th></tr></thead>
                    <tbody id="history"></tbody>
                </table>
            </div>
        </div>

        <div class="panel" style="margin-top:.7rem; min-height: 250px;">
            <div class="ph"><span>Live Event Stream</span><span id="event-count" class="muted">0</span></div>
            <div id="events" class="pc events"></div>
        </div>
    </div>

  <script>
        function t(ts){ try{ return new Date(ts).toLocaleTimeString(); }catch{ return '-'; } }
        function esc(v){ return String(v ?? '').replace(/[&<>"]/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c])); }
        function ago(sec){
            const s = Number(sec);
            if (!Number.isFinite(s) || s < 0) return '-';
            if (s < 60) return s + 's ago';
            if (s < 3600) return Math.floor(s / 60) + 'm ago';
            return Math.floor(s / 3600) + 'h ago';
        }

    async function j(u){
      const r = await fetch(u, { credentials: 'same-origin' });
      if (r.status === 401) { window.location = '/login'; return null; }
      return r.json();
    }

        function renderActive(sessions){
            const wall = document.getElementById('active-wall');
            document.getElementById('active-count').textContent = sessions.length;
            if(!sessions.length){
                wall.innerHTML = '<div class="empty">No active sessions in the last 15 minutes.</div>';
                return;
            }

            wall.innerHTML = sessions.map(s => {
                const identityName = String(s.authenticated_username || '').trim();
                const identityRole = String(s.authenticated_role || 'anonymous').trim() || 'anonymous';
                const identityTier = String(s.authenticated_service_tier || '').trim();
                const identityLabel = identityName ? (identityName + ' [' + identityRole + ']') : identityRole;

                const actionHtml = (s.recent_actions || []).slice(0, 6).map(a => {
                    const cls = a.is_asset_request ? 'asset' : '';
                    const attackInfo = a.attacks > 0 ? (' [' + a.attacks + ' atk]') : '';
                    return '<div class="act">'
                        + '<span class="act-left ' + cls + '">' + esc(a.method) + ' ' + esc(a.endpoint) + attackInfo + '</span>'
                        + '<span class="act-right">' + t(a.timestamp) + ' [' + esc(a.response) + ']</span>'
                        + '</div>';
                }).join('') || '<div class="muted">No recent actions captured.</div>';

                const typeHtml = (s.attack_types || []).slice(0, 5).map(v => '<span class="chip">' + esc(v) + '</span>').join('')
                    || '<span class="chip">none</span>';

                const chainPath = (s.chain_attack_path || [s.chain_stage || s.stage]).join(' -> ');
                const attackViz = ['User'].concat((s.attack_types || []).slice(0, 4)).concat([s.chain_stage || s.stage]).join(' -> ');
                const timeline = (s.chain_timeline || []).slice(-4).map(it =>
                    '<div class="tl-item">' + esc(t(it.timestamp)) + ' ' + esc(it.label || it.event_type || 'event') + '</div>'
                ).join('') || '<div class="tl-item">No chain events yet</div>';

                return '<div class="session-card">'
                    + '<div class="session-head"><span class="mono">' + esc(s.ip) + '</span><span class="stage">' + esc(s.chain_stage || s.stage) + '</span></div>'
                    + '<div class="metrics">'
                    + '<div class="metric">Requests: <b>' + esc(s.requests) + '</b></div>'
                    + '<div class="metric">Attacks: <b>' + esc(s.attacks) + '</b></div>'
                    + '<div class="metric">Interactive: <b>' + esc(s.interaction_requests) + '</b></div>'
                    + '<div class="metric">Assets: <b>' + esc(s.asset_requests) + '</b></div>'
                    + '</div>'
                    + '<div class="metrics">'
                    + '<div class="metric">Last seen: <b>' + esc(ago(s.seconds_since_seen)) + '</b></div>'
                    + '<div class="metric">Session age: <b>' + esc(ago(s.age_seconds)) + '</b></div>'
                    + '<div class="metric">Skill: <b>' + esc(s.skill_level || 'basic') + '</b></div>'
                    + '<div class="metric">Chain score: <b>' + esc(Math.round((Number(s.chain_progression || 0)) * 100) + '%') + '</b></div>'
                    + '</div>'
                    + '<div class="chain">' + esc(chainPath) + '</div>'
                    + '<div class="chain">' + esc(attackViz) + '</div>'
                        + '<div class="chain">Identity: ' + esc(identityLabel) + (identityTier ? (' | Tier: ' + esc(identityTier)) : '') + '</div>'
                    + '<div class="types">' + typeHtml + '</div>'
                    + '<div class="actions-feed">' + actionHtml + '</div>'
                    + '<div class="timeline">' + timeline + '</div>'
                    + '</div>';
            }).join('');
        }

        function renderHistory(sessions){
            const h = document.getElementById('history');
            document.getElementById('history-count').textContent = sessions.length;
            if(!sessions.length){
                h.innerHTML = '<tr><td colspan="8" class="empty">No historical sessions yet.</td></tr>';
                return;
            }
            h.innerHTML = sessions.slice(0, 120).map(s =>
                '<tr>'
                + '<td>' + esc(t(s.last_seen)) + '</td>'
                + '<td class="mono">' + esc(s.ip) + '</td>'
                + '<td>' + esc(s.authenticated_username || '-') + '</td>'
                + '<td>' + esc(s.requests) + '</td>'
                + '<td>' + esc(s.interaction_requests) + '</td>'
                + '<td>' + esc(s.asset_requests) + '</td>'
                + '<td>' + esc(s.attacks) + '</td>'
                + '<td>' + esc(s.stage) + '</td>'
                + '</tr>'
            ).join('');
        }

        function renderAttacks(attacks){
            const a = document.getElementById('attacks');
            document.getElementById('attack-count').textContent = attacks.length;
            if(!attacks.length){
                a.innerHTML = '<tr><td colspan="4" class="empty">No attacks detected yet.</td></tr>';
                return;
            }
            a.innerHTML = attacks.slice(0, 120).map(x =>
                '<tr>'
                + '<td>' + t(x.timestamp) + '</td>'
                + '<td class="mono">' + esc(x.ip) + '</td>'
                + '<td>' + esc(x.type) + '</td>'
                + '<td class="sev-' + esc(x.severity) + '">' + esc(x.severity) + '</td>'
                + '</tr>'
            ).join('');
        }

        function renderEvents(events){
            const e = document.getElementById('events');
            document.getElementById('event-count').textContent = events.length;
            if(!events.length){
                e.innerHTML = '<div class="empty">No events captured yet.</div>';
                return;
            }

            e.innerHTML = events.slice(0, 220).map(x => {
                const statusClass = Number(x.response) >= 400 ? 'danger' : 'ok';
                const assetClass = x.is_asset_request ? 'asset' : '';
                const attackInfo = x.attacks > 0 ? (' [' + x.attacks + ' atk]') : '';
                const identityLabel = x.authenticated_username
                    ? (x.authenticated_username + ' [' + (x.authenticated_role || 'user') + ']')
                    : (x.authenticated_role || 'anonymous');
                return '<div class="event">'
                    + '<span class="event-main ' + assetClass + '">' + t(x.timestamp) + ' <span class="muted mono">' + esc(x.ip) + '</span> <span class="muted">(' + esc(identityLabel) + ')</span> ' + esc(x.method) + ' ' + esc(x.endpoint) + attackInfo + '</span>'
                    + '<span class="' + statusClass + '">[' + esc(x.response) + ']</span>'
                    + '</div>';
            }).join('');
        }

    async function refresh(){
            const ip = encodeURIComponent(document.getElementById('f-ip').value || '');
            const stage = encodeURIComponent(document.getElementById('f-stage').value || '');
            const attackType = encodeURIComponent(document.getElementById('f-attack').value || '');
            const query = `ip=${ip}&stage=${stage}&attack_type=${attackType}`;

            const [stats, activeSessions, historySessions, attacks, events] = await Promise.all([
                j('/api/stats'),
                j('/api/sessions?scope=active&' + query),
                j('/api/sessions?scope=history&' + query),
                j('/api/attacks?limit=300'),
                j('/api/events?limit=800')
            ]);
            if(!stats || !activeSessions || !historySessions || !attacks || !events) return;

      document.getElementById('s-active').textContent = stats.active_sessions;
      document.getElementById('s-total').textContent = stats.total_sessions;
      document.getElementById('s-req').textContent = stats.total_requests;
      document.getElementById('s-att').textContent = stats.total_attacks;

            renderActive(activeSessions);
            renderHistory(historySessions);
            renderAttacks(attacks);
            renderEvents(events);
    }

    refresh();
        document.getElementById('f-ip').addEventListener('input', () => refresh());
        document.getElementById('f-stage').addEventListener('change', () => refresh());
        document.getElementById('f-attack').addEventListener('input', () => refresh());
        document.getElementById('f-clear').addEventListener('click', () => {
            document.getElementById('f-ip').value = '';
            document.getElementById('f-stage').value = '';
            document.getElementById('f-attack').value = '';
            refresh();
        });
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
        scope = request.args.get("scope", "active").strip().lower()
        if scope not in {"active", "history", "all"}:
            scope = "active"
        ip_filter = request.args.get("ip", "")
        stage_filter = request.args.get("stage", "")
        attack_type_filter = request.args.get("attack_type", "")
        return jsonify(
            _session_rows(
                scope=scope,
                limit=120,
                ip_filter=ip_filter,
                stage_filter=stage_filter,
                attack_type_filter=attack_type_filter,
            )
        )


@app.route("/api/sessions/active")
@api_login_required
def api_sessions_active():
    with _lock:
        return jsonify(_session_rows(scope="active", limit=120))


@app.route("/api/sessions/history")
@api_login_required
def api_sessions_history():
    with _lock:
        return jsonify(_session_rows(scope="history", limit=120))


@app.route("/api/attacks")
@api_login_required
def api_attacks():
    with _lock:
        requested = _safe_int(request.args.get("limit"), 120)
        limit = max(10, min(requested, 800))
        return jsonify(list(reversed(_attacks[-limit:])))


@app.route("/api/events")
@api_login_required
def api_events():
    with _lock:
        requested = _safe_int(request.args.get("limit"), 300)
        limit = max(20, min(requested, 2000))
        return jsonify(list(reversed(_events[-limit:])))


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
