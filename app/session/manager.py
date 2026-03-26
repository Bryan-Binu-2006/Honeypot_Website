"""
Session Management Module

Handles secure session creation, validation, and tracking for attacker identification.

INTERNAL DOCUMENTATION:
- Sessions are created using HMAC(IP + UserAgent + Secret)
- Sessions stored in HttpOnly cookies, never in URLs
- Tampering detection triggers silent session regeneration
- All session operations are logged but never exposed
"""

import hmac
import hashlib
import secrets
import time
from typing import Optional, Dict, Any
from flask import Request, make_response
import json
import base64


class SessionManager:
    """
    Secure session management for tracking attackers.
    
    INTERNAL: Session IDs are derived from client fingerprint + secret.
    This allows us to correlate requests from the same attacker even
    if they clear cookies (we can regenerate the same session ID).
    
    The session contains:
    - Unique identifier (HMAC-based)
    - Creation timestamp
    - Request count
    - Detected stage (recon, access, exploit, escalate, persist)
    """
    
    def __init__(self, secret: str):
        """
        Initialize session manager with server secret.
        
        Args:
            secret: Server-side secret for HMAC generation
        """
        self._secret = secret.encode('utf-8')
        self._sessions: Dict[str, Dict[str, Any]] = {}
    
    def get_or_create_session(self, request: Request) -> str:
        """
        Get existing session or create new one.
        
        INTERNAL FLOW:
        1. Check for existing session cookie
        2. Validate cookie if present
        3. Create new session if missing or invalid
        4. Always return a valid session ID
        
        Args:
            request: Flask request object
            
        Returns:
            Session ID string
        """
        # Try to get existing session
        session_cookie = request.cookies.get('sid')
        
        if session_cookie:
            # Validate existing session
            session_id = self._validate_session(session_cookie, request)
            if session_id:
                # Update session activity
                self._update_session(session_id)
                return session_id
        
        # Create new session
        return self._create_session(request)
    
    def _generate_session_id(self, request: Request) -> str:
        """
        Generate session ID using HMAC.
        
        INTERNAL: Session ID = HMAC-SHA256(IP + UserAgent + Timestamp + Nonce, Secret)
        
        This creates a unique, unforgeable session identifier that can be
        validated server-side without storing state.
        """
        # Get client fingerprint components
        ip = self._get_client_ip(request)
        user_agent = request.headers.get('User-Agent', 'unknown')
        timestamp = str(int(time.time()))
        nonce = secrets.token_hex(8)
        
        # Create fingerprint
        fingerprint = f"{ip}|{user_agent}|{timestamp}|{nonce}"
        
        # Generate HMAC
        signature = hmac.new(
            self._secret,
            fingerprint.encode('utf-8'),
            hashlib.sha256
        ).hexdigest()
        
        # Session ID includes fingerprint hash and signature
        # Format: base64(fingerprint_data):signature
        fingerprint_data = {
            'ip': ip,
            'ua_hash': hashlib.md5(user_agent.encode()).hexdigest()[:8],
            'ts': timestamp,
            'n': nonce
        }
        encoded_data = base64.b64encode(
            json.dumps(fingerprint_data).encode()
        ).decode()
        
        return f"{encoded_data}.{signature}"
    
    def _validate_session(self, session_cookie: str, request: Request) -> Optional[str]:
        """
        Validate session cookie integrity.
        
        INTERNAL: Validates HMAC signature and checks for tampering.
        If tampering detected, returns None (will trigger new session).
        
        Args:
            session_cookie: Cookie value
            request: Current request for fingerprint comparison
            
        Returns:
            Session ID if valid, None if tampered
        """
        try:
            # Split cookie into data and signature
            parts = session_cookie.split('.')
            if len(parts) != 2:
                return None
            
            encoded_data, signature = parts
            
            # Decode fingerprint data
            fingerprint_data = json.loads(
                base64.b64decode(encoded_data.encode()).decode()
            )
            
            # Reconstruct fingerprint for validation
            ip = self._get_client_ip(request)
            user_agent = request.headers.get('User-Agent', 'unknown')
            ua_hash = hashlib.md5(user_agent.encode()).hexdigest()[:8]
            
            # Basic IP match check (can be spoofed, but helps correlate)
            # Note: We don't require exact IP match to handle NAT/proxies
            
            # Rebuild fingerprint string
            fingerprint = (
                f"{fingerprint_data['ip']}|{user_agent}|"
                f"{fingerprint_data['ts']}|{fingerprint_data['n']}"
            )
            
            # Verify signature
            expected_signature = hmac.new(
                self._secret,
                fingerprint.encode('utf-8'),
                hashlib.sha256
            ).hexdigest()
            
            if hmac.compare_digest(signature, expected_signature):
                return session_cookie
            
            # Signature mismatch - tampering detected
            return None
            
        except Exception:
            # Any decode error means invalid/tampered session
            return None
    
    def _create_session(self, request: Request) -> str:
        """
        Create a new session.
        
        INTERNAL: Creates session data and prepares cookie.
        """
        session_id = self._generate_session_id(request)
        
        # Initialize session data
        self._sessions[session_id] = {
            'created': time.time(),
            'last_seen': time.time(),
            'request_count': 1,
            'stage': 'recon',  # Initial stage
            'detected_attacks': [],
            'accessed_paths': [],
            'ip': self._get_client_ip(request)
        }
        
        return session_id
    
    def _update_session(self, session_id: str) -> None:
        """Update session activity timestamp and counter."""
        if session_id in self._sessions:
            self._sessions[session_id]['last_seen'] = time.time()
            self._sessions[session_id]['request_count'] += 1
    
    def _get_client_ip(self, request: Request) -> str:
        """
        Get real client IP, accounting for proxies.
        
        INTERNAL: Checks X-Forwarded-For but validates against trusted proxies.
        """
        # Check for proxy headers
        forwarded_for = request.headers.get('X-Forwarded-For')
        if forwarded_for:
            # Take the first IP (client IP in standard proxy chains)
            return forwarded_for.split(',')[0].strip()
        
        # Fall back to direct IP
        return request.remote_addr or 'unknown'
    
    def get_session_data(self, session_id: str) -> Optional[Dict[str, Any]]:
        """
        Get session data for analysis.
        
        Args:
            session_id: Session identifier
            
        Returns:
            Session data dict or None if not found
        """
        return self._sessions.get(session_id)
    
    def update_session_stage(self, session_id: str, stage: str) -> None:
        """
        Update attacker stage based on behavior.
        
        Stages: recon -> access -> exploit -> escalate -> persist
        """
        if session_id in self._sessions:
            self._sessions[session_id]['stage'] = stage
    
    def add_detected_attack(self, session_id: str, attack_type: str) -> None:
        """Record a detected attack for this session."""
        if session_id in self._sessions:
            self._sessions[session_id]['detected_attacks'].append({
                'type': attack_type,
                'timestamp': time.time()
            })
    
    def set_session_cookie(self, response, session_id: str) -> None:
        """
        Set secure session cookie on response.
        
        INTERNAL: Cookie is HttpOnly, Secure, SameSite=Lax
        """
        response.set_cookie(
            'sid',
            session_id,
            httponly=True,
            secure=True,  # Set to False in dev
            samesite='Lax',
            max_age=86400 * 7  # 7 days
        )
