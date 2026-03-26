"""
Middleware - Request Interceptor

Intercepts all incoming requests for analysis by the detection engine.

INTERNAL DOCUMENTATION:
- This is the first point of contact for all requests
- Extracts all request data for analysis
- Triggers detection engine
- Results are stored in request context
"""

from typing import Dict, Any, Optional
from flask import Request, g
import time

from ..detection.engine import get_detection_engine, AnalysisResult
from ..session.tracker import SessionTracker
from ..behavior.attack_chain_engine import get_attack_chain_engine
from ..integrations import get_integration_manager


class RequestInterceptor:
    """
    Intercepts and analyzes all incoming requests.
    
    INTERNAL: This class is the bridge between Flask's request handling
    and our detection engine. It:
    
    1. Extracts all request components (URL, params, body, headers)
    2. Passes data to the detection engine
    3. Stores results for the response engine to use
    4. Updates session tracking
    
    The interception is completely transparent to the attacker.
    """
    
    def __init__(self):
        """Initialize interceptor with detection engine."""
        self._detection_engine = get_detection_engine()
        self._session_tracker = SessionTracker()
        self._attack_chain_engine = get_attack_chain_engine()
        self._integration_manager = get_integration_manager()
    
    def analyze(self, request: Request, session_id: str) -> Dict[str, Any]:
        """
        Analyze an incoming request.
        
        Args:
            request: Flask request object
            session_id: Session identifier for the attacker
            
        Returns:
            Analysis result dictionary containing:
            - detected_attacks: List of detected attack patterns
            - stage: Current attacker stage
            - progression: Progression score
            - recommended_response: Response type recommendation
            - raw_request: Sanitized request data
        """
        # Extract request data
        request_data = self._extract_request_data(request)

        # Register/update session for external integration correlation.
        try:
            self._integration_manager.register_session(
                session_id=session_id,
                ip=request_data.get('ip', 'unknown'),
                timestamp=time.time()
            )
        except Exception:
            pass
        
        # Run detection engine
        analysis = self._detection_engine.analyze(session_id, request_data)
        
        # Update session tracking
        tracking_result = self._session_tracker.track_request(
            session_id=session_id,
            endpoint=request_data['url'],
            detected_attacks=[a['type'] for a in analysis.detected_attacks],
            request_data=request_data
        )

        # Attack-chain progression model for multi-stage deception.
        chain_result = self._attack_chain_engine.track_event(
            session_id=session_id,
            request_data=request_data,
            detected_attacks=analysis.detected_attacks
        )
        self._session_tracker.set_chain_state(
            session_id=session_id,
            chain_stage=chain_result['stage'],
            chain_progression=chain_result['progression'],
            timeline=chain_result['timeline'],
            attack_path=chain_result['attack_path'],
            skill_level=chain_result['skill_level'],
            scenarios_completed=chain_result['scenarios_completed'],
            next_hints=chain_result.get('next_hints', [])
        )
        
        # Combine results
        return {
            'detected_attacks': analysis.detected_attacks,
            'stage': tracking_result['stage'],
            'progression': tracking_result['progression_score'],
            'chain_stage': chain_result['stage'],
            'chain_progression': chain_result['progression'],
            'chain_scenarios_completed': chain_result['scenarios_completed'],
            'chain_newly_unlocked': chain_result.get('newly_unlocked', []),
            'chain_timeline': chain_result.get('timeline', []),
            'chain_attack_path': chain_result.get('attack_path', []),
            'chain_next_hints': chain_result.get('next_hints', []),
            'attacker_skill_level': chain_result.get('skill_level', 'basic'),
            'time_spent_seconds': chain_result.get('time_spent_seconds', 0),
            'techniques_used': chain_result.get('techniques_used', []),
            'recommended_response': analysis.recommended_response,
            'stage_indicator': chain_result['stage'],
            'detection_stage_indicator': analysis.stage_indicator,
            'attack_count': analysis.attack_count,
            'highest_severity': analysis.highest_severity,
            'timestamp': analysis.timestamp,
            'raw_request': analysis.raw_request
        }
    
    def _extract_request_data(self, request: Request) -> Dict[str, Any]:
        """
        Extract all relevant data from the request.
        
        Captures everything an attacker might use to probe
        for vulnerabilities.
        """
        # Get body data safely
        body = ''
        try:
            if request.is_json:
                body = request.get_json(silent=True) or {}
            else:
                body = request.get_data(as_text=True)
        except Exception:
            body = ''
        
        # Get form data
        form_data = {}
        try:
            form_data = dict(request.form)
        except Exception:
            pass
        
        # Combine body data
        if isinstance(body, dict):
            body_str = str(body)
        else:
            body_str = str(body)
        
        # Get all parameters
        params = {}
        try:
            params = dict(request.args)
            params.update(form_data)
        except Exception:
            pass
        
        # Get headers (sanitized)
        headers = {}
        try:
            headers = dict(request.headers)
        except Exception:
            pass
        
        return {
            'url': request.path,
            'full_url': request.url,
            'method': request.method,
            'params': params,
            'body': body_str,
            'headers': headers,
            'ip': self._get_client_ip(request),
            'cookies': dict(request.cookies),
            'content_type': request.content_type or ''
        }
    
    def _get_client_ip(self, request: Request) -> str:
        """
        Get the real client IP, accounting for proxies.
        """
        # Check proxy headers
        forwarded_for = request.headers.get('X-Forwarded-For')
        if forwarded_for:
            return forwarded_for.split(',')[0].strip()
        
        real_ip = request.headers.get('X-Real-IP')
        if real_ip:
            return real_ip
        
        return request.remote_addr or 'unknown'
    
    def get_session_profile(self, session_id: str) -> Dict[str, Any]:
        """Get complete profile for a session."""
        return self._session_tracker.get_session_profile(session_id)
