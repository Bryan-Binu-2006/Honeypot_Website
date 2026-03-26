"""
Attack Detection Engine - Core Classifier

This module performs attack classification by matching request data against patterns.

INTERNAL DOCUMENTATION:
- Uses compiled regex for performance
- Matches against URL, params, body, and headers
- Returns normalized attack labels with confidence scores
"""

import re
from typing import Dict, List, Any, Optional, Set
from dataclasses import dataclass
from functools import lru_cache

from .patterns import get_all_patterns, AttackPattern, Severity


@dataclass
class DetectionResult:
    """Result of attack detection analysis."""
    attack_type: str
    severity: Severity
    confidence: float
    matched_pattern: str
    matched_value: str
    field: str


class AttackClassifier:
    """
    Classifies requests by matching against attack patterns.
    
    INTERNAL: This classifier is the core of the detection engine.
    It compiles all patterns at initialization for performance and
    matches each request against the full pattern set.
    
    Detection results are used by:
    1. Response engine (to craft appropriate fake responses)
    2. Logging service (to record attack attempts)
    3. Behavior engine (to track attacker progression)
    """
    
    def __init__(self):
        """Initialize classifier with compiled patterns."""
        self._patterns = get_all_patterns()
        self._compiled_patterns: Dict[str, List[re.Pattern]] = {}
        self._compile_patterns()
    
    def _compile_patterns(self) -> None:
        """
        Compile all regex patterns for efficient matching.
        
        Pre-compilation significantly improves performance when
        checking many requests.
        """
        for pattern in self._patterns:
            compiled = []
            for regex_str in pattern.patterns:
                try:
                    compiled.append(re.compile(regex_str, re.IGNORECASE))
                except re.error:
                    # Skip invalid patterns (shouldn't happen with tested patterns)
                    continue
            self._compiled_patterns[pattern.name] = compiled
    
    def classify(self, request_data: Dict[str, Any]) -> List[DetectionResult]:
        """
        Classify a request for attack patterns.
        
        Args:
            request_data: Dictionary containing:
                - url: Request URL path
                - params: Query parameters (dict)
                - body: Request body (string)
                - headers: Request headers (dict)
                
        Returns:
            List of DetectionResult objects for each matched attack
            
        INTERNAL: This method is called for every request by the interceptor.
        Results are stored in request context for the response engine.
        """
        results = []
        detected_types: Set[str] = set()  # Avoid duplicate types
        
        # Prepare searchable content
        content = self._prepare_content(request_data)
        
        for pattern in self._patterns:
            # Skip if already detected this type
            if pattern.name in detected_types:
                continue
            
            # Check each field specified for this pattern
            for field in pattern.check_fields:
                field_content = content.get(field, '')
                if not field_content:
                    continue
                
                # Match against compiled patterns
                for compiled_regex in self._compiled_patterns.get(pattern.name, []):
                    match = compiled_regex.search(field_content)
                    if match:
                        results.append(DetectionResult(
                            attack_type=pattern.name,
                            severity=pattern.severity,
                            confidence=self._calculate_confidence(pattern, match),
                            matched_pattern=compiled_regex.pattern,
                            matched_value=match.group(0)[:100],  # Truncate for safety
                            field=field
                        ))
                        detected_types.add(pattern.name)
                        break  # Move to next pattern after first match
                
                if pattern.name in detected_types:
                    break  # Pattern matched, move to next
        
        return results
    
    def _prepare_content(self, request_data: Dict[str, Any]) -> Dict[str, str]:
        """
        Prepare request data for pattern matching.
        
        Converts all request components to searchable strings.
        """
        content = {
            'url': request_data.get('url', ''),
            'params': '',
            'body': request_data.get('body', ''),
            'headers': ''
        }
        
        # Flatten params to string
        params = request_data.get('params', {})
        if isinstance(params, dict):
            content['params'] = '&'.join(
                f"{k}={v}" for k, v in params.items()
            )
        elif isinstance(params, str):
            content['params'] = params
        
        # Flatten headers to string
        headers = request_data.get('headers', {})
        if isinstance(headers, dict):
            content['headers'] = '\n'.join(
                f"{k}: {v}" for k, v in headers.items()
            )
        
        return content
    
    def _calculate_confidence(self, pattern: AttackPattern, match: re.Match) -> float:
        """
        Calculate confidence score for a match.
        
        Confidence is based on:
        - Pattern severity (higher severity = more confident)
        - Match length (longer matches = more confident)
        - Pattern specificity (more specific = more confident)
        """
        base_confidence = {
            Severity.LOW: 0.5,
            Severity.MEDIUM: 0.7,
            Severity.HIGH: 0.85,
            Severity.CRITICAL: 0.95
        }.get(pattern.severity, 0.5)
        
        # Adjust based on match length
        match_len = len(match.group(0))
        length_factor = min(match_len / 20, 0.1)  # Up to 10% bonus
        
        return min(base_confidence + length_factor, 1.0)
    
    def get_attack_types(self, results: List[DetectionResult]) -> List[str]:
        """Extract unique attack type names from results."""
        return list(set(r.attack_type for r in results))
    
    def get_highest_severity(self, results: List[DetectionResult]) -> Optional[Severity]:
        """Get the highest severity level from results."""
        if not results:
            return None
        return max(r.severity for r in results)


class HeuristicAnalyzer:
    """
    Performs heuristic analysis beyond pattern matching.
    
    INTERNAL: Detects behavioral patterns that can't be caught by regex:
    - Request rate anomalies
    - Payload mutation attempts
    - Progressive exploitation patterns
    """
    
    def __init__(self):
        """Initialize heuristic analyzer."""
        self._request_history: Dict[str, List[float]] = {}
    
    def analyze(
        self,
        session_id: str,
        request_data: Dict[str, Any],
        timestamp: float
    ) -> List[DetectionResult]:
        """
        Perform heuristic analysis on request.
        
        Args:
            session_id: Attacker session identifier
            request_data: Request data dictionary
            timestamp: Request timestamp
            
        Returns:
            List of heuristic detection results
        """
        results = []
        
        # Check request rate
        rate_result = self._check_request_rate(session_id, timestamp)
        if rate_result:
            results.append(rate_result)
        
        # Check for payload mutations
        mutation_results = self._check_payload_mutations(request_data)
        results.extend(mutation_results)
        
        return results
    
    def _check_request_rate(
        self,
        session_id: str,
        timestamp: float
    ) -> Optional[DetectionResult]:
        """
        Detect high-rate scanning behavior.
        
        Triggers if more than 60 requests per minute from same session.
        """
        if session_id not in self._request_history:
            self._request_history[session_id] = []
        
        history = self._request_history[session_id]
        
        # Remove timestamps older than 60 seconds
        history[:] = [t for t in history if timestamp - t < 60]
        history.append(timestamp)
        
        # Check rate
        if len(history) > 60:  # More than 60 requests/minute
            return DetectionResult(
                attack_type='rate_scanning',
                severity=Severity.MEDIUM,
                confidence=min(len(history) / 100, 0.95),
                matched_pattern='High request rate',
                matched_value=f'{len(history)} requests/minute',
                field='behavior'
            )
        
        return None
    
    def _check_payload_mutations(
        self,
        request_data: Dict[str, Any]
    ) -> List[DetectionResult]:
        """
        Detect payload mutation attempts.
        
        Looks for encoding variations and case mutations that
        suggest automated testing or evasion attempts.
        """
        results = []
        
        # Combine all request data
        all_content = ' '.join([
            str(request_data.get('url', '')),
            str(request_data.get('params', '')),
            str(request_data.get('body', ''))
        ])
        
        # Check for multiple encoding layers
        encoding_count = 0
        if '%25' in all_content:  # Double URL encoding
            encoding_count += 1
        if '&#' in all_content:  # HTML entities
            encoding_count += 1
        if '\\x' in all_content or '\\u' in all_content:  # Hex/Unicode
            encoding_count += 1
        
        if encoding_count >= 2:
            results.append(DetectionResult(
                attack_type='multi_encoding_evasion',
                severity=Severity.MEDIUM,
                confidence=0.8,
                matched_pattern='Multiple encoding layers',
                matched_value=f'{encoding_count} encoding types',
                field='behavior'
            ))
        
        return results
