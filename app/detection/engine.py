"""
Attack Detection Engine - Main Coordinator

This module coordinates all detection activities and provides the main interface
for analyzing requests.

INTERNAL DOCUMENTATION:
- Entry point for all request analysis
- Combines pattern matching and heuristic analysis
- Provides unified results for logging and response generation
"""

import time
from typing import Dict, List, Any, Optional
from dataclasses import dataclass, asdict

from .classifiers import AttackClassifier, HeuristicAnalyzer, DetectionResult
from .patterns import Severity


@dataclass
class AnalysisResult:
    """
    Complete analysis result for a request.
    
    Contains all detection results, behavioral analysis,
    and recommended response strategy.
    """
    session_id: str
    timestamp: float
    detected_attacks: List[Dict[str, Any]]
    highest_severity: Optional[str]
    attack_count: int
    recommended_response: str
    stage_indicator: str
    raw_request: Dict[str, Any]


class DetectionEngine:
    """
    Main detection engine coordinator.
    
    INTERNAL: This is the primary interface for the middleware to analyze
    requests. It combines:
    1. Pattern-based attack detection
    2. Heuristic behavioral analysis
    3. Response recommendation
    
    The engine is designed to be:
    - Fast (compiled patterns, minimal overhead)
    - Comprehensive (30+ attack types)
    - Non-blocking (async-compatible)
    """
    
    def __init__(self):
        """Initialize detection engine with classifiers."""
        self._classifier = AttackClassifier()
        self._heuristic = HeuristicAnalyzer()
    
    def analyze(
        self,
        session_id: str,
        request_data: Dict[str, Any]
    ) -> AnalysisResult:
        """
        Perform complete analysis of a request.
        
        Args:
            session_id: Attacker session identifier
            request_data: Request data containing:
                - url: Request URL path
                - method: HTTP method
                - params: Query parameters
                - body: Request body
                - headers: Request headers
                
        Returns:
            AnalysisResult with all detection data
            
        INTERNAL FLOW:
        1. Run pattern-based classification
        2. Run heuristic analysis
        3. Combine results
        4. Determine response strategy
        5. Return unified result
        """
        timestamp = time.time()
        
        # Pattern-based detection
        pattern_results = self._classifier.classify(request_data)
        
        # Heuristic analysis
        heuristic_results = self._heuristic.analyze(
            session_id,
            request_data,
            timestamp
        )
        
        # Combine all results
        all_results = pattern_results + heuristic_results
        
        # Convert to serializable format
        detected_attacks = [
            {
                'type': r.attack_type,
                'severity': r.severity.name,
                'confidence': r.confidence,
                'matched_pattern': r.matched_pattern,
                'matched_value': r.matched_value,
                'field': r.field
            }
            for r in all_results
        ]
        
        # Determine highest severity
        highest_severity = None
        if all_results:
            max_severity = max(r.severity for r in all_results)
            highest_severity = max_severity.name
        
        # Determine recommended response
        recommended_response = self._get_recommended_response(all_results)
        
        # Determine stage indicator
        stage_indicator = self._determine_stage(all_results, request_data)
        
        return AnalysisResult(
            session_id=session_id,
            timestamp=timestamp,
            detected_attacks=detected_attacks,
            highest_severity=highest_severity,
            attack_count=len(all_results),
            recommended_response=recommended_response,
            stage_indicator=stage_indicator,
            raw_request=self._sanitize_request(request_data)
        )
    
    def _get_recommended_response(
        self,
        results: List[DetectionResult]
    ) -> str:
        """
        Determine recommended response type based on detections.
        
        INTERNAL: Response types guide the response engine:
        - 'normal': Return normal application response
        - 'fake_success': Simulate successful attack
        - 'fake_error': Simulate promising error
        - 'progressive': Escalate deception level
        - 'delay': Add artificial delay
        """
        if not results:
            return 'normal'
        
        # Get attack types
        attack_types = {r.attack_type for r in results}
        highest_severity = max(r.severity for r in results)
        
        # High-value attacks get fake success
        if any(t in attack_types for t in [
            'sqli_classic', 'sqli_blind', 'command_injection',
            'lfi', 'ssrf', 'jwt_tampering'
        ]):
            return 'fake_success'
        
        # Recon gets normal (don't tip them off)
        if all(r.severity == Severity.LOW for r in results):
            return 'normal'
        
        # XSS and template injection get fake error (tantalizing)
        if any(t in attack_types for t in [
            'xss_reflected', 'ssti_jinja2', 'ssti_generic'
        ]):
            return 'fake_error'
        
        # Scanning behavior gets delay
        if 'rate_scanning' in attack_types:
            return 'delay'
        
        return 'progressive'
    
    def _determine_stage(
        self,
        results: List[DetectionResult],
        request_data: Dict[str, Any]
    ) -> str:
        """
        Determine attacker stage based on current request.
        
        Stages: recon, access, exploit, escalate, persist
        """
        url = request_data.get('url', '')
        attack_types = {r.attack_type for r in results}
        
        # Check URL indicators
        if any(p in url for p in ['/robots.txt', '/sitemap', '/.well-known']):
            return 'recon'
        if any(p in url for p in ['/login', '/signin', '/auth']):
            return 'access'
        if any(p in url for p in ['/admin', '/api/internal', '/debug']):
            return 'exploit'
        if any(p in url for p in ['/internal', '/admin/config', '/admin/users']):
            return 'escalate'
        if any(p in url for p in ['/admin/keys', '/admin/wallet', '/api/keys']):
            return 'persist'
        
        # Check attack types
        if any(t in attack_types for t in ['recon_robots', 'directory_fuzzing']):
            return 'recon'
        if any(t in attack_types for t in ['sqli_classic', 'credential_bruteforce']):
            return 'access'
        if any(t in attack_types for t in ['lfi', 'command_injection', 'ssrf']):
            return 'exploit'
        if any(t in attack_types for t in ['jwt_tampering', 'privilege_escalation']):
            return 'escalate'
        
        return 'recon'  # Default to recon
    
    def _sanitize_request(self, request_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Sanitize request data for safe storage.
        
        Truncates large values and removes potentially dangerous content.
        """
        sanitized = {}
        
        for key, value in request_data.items():
            if isinstance(value, str):
                # Truncate long strings
                sanitized[key] = value[:5000] if len(value) > 5000 else value
            elif isinstance(value, dict):
                # Recursively sanitize dicts
                sanitized[key] = {
                    k: str(v)[:1000] for k, v in list(value.items())[:50]
                }
            else:
                sanitized[key] = str(value)[:1000]
        
        return sanitized
    
    def get_attack_summary(
        self,
        results: List[DetectionResult]
    ) -> Dict[str, Any]:
        """
        Get a summary of detected attacks for logging.
        
        Returns aggregated statistics useful for analysis.
        """
        if not results:
            return {'total': 0, 'types': [], 'max_severity': None}
        
        return {
            'total': len(results),
            'types': list(set(r.attack_type for r in results)),
            'max_severity': max(r.severity.name for r in results),
            'by_severity': {
                'low': sum(1 for r in results if r.severity == Severity.LOW),
                'medium': sum(1 for r in results if r.severity == Severity.MEDIUM),
                'high': sum(1 for r in results if r.severity == Severity.HIGH),
                'critical': sum(1 for r in results if r.severity == Severity.CRITICAL)
            }
        }


# Singleton instance for app-wide use
_engine_instance: Optional[DetectionEngine] = None


def get_detection_engine() -> DetectionEngine:
    """Get or create the detection engine singleton."""
    global _engine_instance
    if _engine_instance is None:
        _engine_instance = DetectionEngine()
    return _engine_instance
