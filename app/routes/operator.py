"""
Operator Dashboard - Real Monitoring Interface

THIS IS THE REAL ADMIN PANEL FOR HONEYPOT OPERATORS.
It shows live attacker sessions, detected attacks, and logs.

SECURITY: This route should be protected and NOT exposed publicly!
In production, access only from localhost or via VPN.
"""

from flask import Blueprint, render_template, jsonify, request
from datetime import datetime, timedelta
import json
import os

operator_bp = Blueprint('operator', __name__)

# In-memory storage for demo (in production, read from log files/database)
# This gets populated by the logging service
_active_sessions = {}
_recent_attacks = []
_event_log = []


def record_session_activity(session_id: str, data: dict):
    """Called by logging interface to track sessions."""
    global _active_sessions, _recent_attacks, _event_log
    
    now = datetime.now()
    
    # Update or create session
    if session_id not in _active_sessions:
        _active_sessions[session_id] = {
            'id': session_id,
            'ip': data.get('ip', 'unknown'),
            'first_seen': now.isoformat(),
            'last_seen': now.isoformat(),
            'request_count': 0,
            'attacks_detected': 0,
            'user_agent': data.get('user_agent', 'unknown')[:100],
            'stage': 'recon',
            'attack_types': set()
        }
    
    session = _active_sessions[session_id]
    session['last_seen'] = now.isoformat()
    session['request_count'] += 1
    
    # Track attacks
    detected = data.get('detected_attacks', [])
    if detected:
        session['attacks_detected'] += len(detected)
        for attack in detected:
            attack_type = attack.get('type', 'unknown')
            session['attack_types'].add(attack_type)
            
            # Add to recent attacks
            _recent_attacks.append({
                'session_id': session_id[:16] + '...',
                'ip': data.get('ip', 'unknown'),
                'type': attack_type,
                'severity': attack.get('severity', 'UNKNOWN'),
                'endpoint': data.get('endpoint', '/'),
                'timestamp': now.isoformat()
            })
    
    # Update stage
    session['stage'] = data.get('stage', session['stage'])
    
    # Add to event log
    _event_log.append({
        'timestamp': now.isoformat(),
        'session_id': session_id[:16] + '...',
        'ip': data.get('ip', 'unknown'),
        'method': data.get('method', 'GET'),
        'endpoint': data.get('endpoint', '/'),
        'attacks': len(detected),
        'response': data.get('response_code', 200)
    })
    
    # Keep only last 1000 events
    if len(_recent_attacks) > 500:
        _recent_attacks = _recent_attacks[-500:]
    if len(_event_log) > 1000:
        _event_log = _event_log[-1000:]


def get_stats():
    """Get current statistics."""
    now = datetime.now()
    cutoff = now - timedelta(minutes=15)
    
    # Count active sessions (seen in last 15 minutes)
    active_count = 0
    for session in _active_sessions.values():
        try:
            last_seen = datetime.fromisoformat(session['last_seen'])
            if last_seen > cutoff:
                active_count += 1
        except:
            pass
    
    # Count attacks by type
    attack_counts = {}
    for attack in _recent_attacks[-100:]:  # Last 100 attacks
        t = attack['type']
        attack_counts[t] = attack_counts.get(t, 0) + 1
    
    return {
        'active_sessions': active_count,
        'total_sessions': len(_active_sessions),
        'total_requests': sum(s['request_count'] for s in _active_sessions.values()),
        'total_attacks': sum(s['attacks_detected'] for s in _active_sessions.values()),
        'attack_types': attack_counts
    }


@operator_bp.route('/')
def dashboard():
    """Main operator dashboard."""
    stats = get_stats()
    return render_template('operator/dashboard.html', stats=stats)


@operator_bp.route('/api/sessions')
def api_sessions():
    """Get all tracked sessions."""
    sessions = []
    for sid, data in _active_sessions.items():
        sessions.append({
            'id': sid[:16] + '...',
            'ip': data['ip'],
            'first_seen': data['first_seen'],
            'last_seen': data['last_seen'],
            'requests': data['request_count'],
            'attacks': data['attacks_detected'],
            'stage': data['stage'],
            'user_agent': data['user_agent'],
            'attack_types': list(data.get('attack_types', set()))
        })
    
    # Sort by last_seen descending
    sessions.sort(key=lambda x: x['last_seen'], reverse=True)
    return jsonify(sessions[:50])  # Return latest 50


@operator_bp.route('/api/attacks')
def api_attacks():
    """Get recent attacks."""
    return jsonify(_recent_attacks[-100:][::-1])  # Latest 100, newest first


@operator_bp.route('/api/events')
def api_events():
    """Get event log."""
    return jsonify(_event_log[-200:][::-1])  # Latest 200, newest first


@operator_bp.route('/api/stats')
def api_stats():
    """Get current stats."""
    return jsonify(get_stats())


@operator_bp.route('/session/<session_id>')
def session_detail(session_id):
    """View details for a specific session."""
    # Find session by prefix match
    for sid, data in _active_sessions.items():
        if sid.startswith(session_id.replace('...', '')):
            return render_template('operator/session.html', session=data, full_id=sid)
    return "Session not found", 404
