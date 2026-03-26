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
        
        # Run detection engine
        analysis = self._detection_engine.analyze(session_id, request_data)
        
        # Update session tracking
        tracking_result = self._session_tracker.track_request(
            session_id=session_id,
            endpoint=request_data['url'],
            detected_attacks=[a['type'] for a in analysis.detected_attacks],
            request_data=request_data
        )
        
        # Combine results
        return {
            'detected_attacks': analysis.detected_attacks,
            'stage': tracking_result['stage'],
            'progression': tracking_result['progression_score'],
            'recommended_response': analysis.recommended_response,
            'stage_indicator': analysis.stage_indicator,
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
