"""
Response Engine - Main Coordinator

Generates appropriate fake responses based on detected attacks and attacker progression.

INTERNAL DOCUMENTATION:
- Coordinates response generation based on detection results
- Implements progressive deception (responses evolve with attacker stage)
- Adds realistic delays and headers
"""

import time
import random
from typing import Dict, List, Any, Optional, Tuple
from flask import Response, jsonify, make_response

from .templates import (
    get_response_for_attack,
    get_progressive_response,
    ResponseTemplate,
    LFI_RESPONSES,
    SSRF_RESPONSES,
    COMMAND_INJECTION_RESPONSES
)


class ResponseEngine:
    """
    Generates contextually appropriate fake responses.
    
    INTERNAL: This engine is the counterpart to the detection engine.
    While detection identifies what the attacker is trying, this engine
    crafts believable responses that:
    
    1. Simulate successful exploitation
    2. Encourage deeper exploration
    3. Never reveal the deception
    4. Evolve based on attacker progression
    
    The goal is to maximize attacker engagement time while logging
    all their actions.
    """
    
    def __init__(self):
        """Initialize response engine."""
        self._response_cache: Dict[str, ResponseTemplate] = {}
    
    def generate_response(
        self,
        detected_attacks: List[Dict[str, Any]],
        progression_score: float,
        request_data: Dict[str, Any],
        recommendation: str,
        chain_context: Optional[Dict[str, Any]] = None
    ) -> Tuple[Response, Dict[str, Any]]:
        """
        Generate appropriate fake response.
        
        Args:
            detected_attacks: List of detected attack dictionaries
            progression_score: Attacker progression (0.0 to 1.0)
            request_data: Original request data
            recommendation: Recommended response type from detection engine
            
        Returns:
            Tuple of (Flask Response, metadata dict)
            
        INTERNAL FLOW:
        1. Check if specific attack response is needed
        2. Apply progression-based modifications
        3. Add realistic delays
        4. Return crafted response
        """
        metadata = {
            'response_type': 'normal',
            'template_used': None,
            'delay_applied': 0,
            'behavior_mode': 'stable'
        }

        chain_context = chain_context or {}
        chain_stage = str(chain_context.get('stage', 'recon'))
        
        # No attacks detected - return None to allow normal processing
        if not detected_attacks or recommendation == 'normal':
            return None, metadata
        
        # Get primary attack type (highest severity)
        primary_attack = self._get_primary_attack(detected_attacks)
        attack_type = primary_attack.get('type', 'unknown')
        
        # Get appropriate response template
        if recommendation == 'fake_success':
            template = self._get_success_response(
                attack_type,
                progression_score,
                request_data,
                chain_stage
            )
        elif recommendation == 'fake_error':
            template = self._get_error_response(attack_type, request_data)
        elif recommendation == 'progressive':
            template = get_progressive_response(attack_type, progression_score)
        elif recommendation == 'delay':
            template = self._get_delayed_response()
        else:
            template = get_response_for_attack(attack_type)

        template, behavior_mode = self._apply_context_variation(
            template=template,
            attack_type=attack_type,
            progression_score=progression_score,
            chain_stage=chain_stage
        )
        metadata['behavior_mode'] = behavior_mode
        
        # Apply delay for realism
        if template.delay_ms > 0:
            actual_delay = template.delay_ms + random.randint(-50, 100)
            time.sleep(actual_delay / 1000.0)
            metadata['delay_applied'] = actual_delay
        
        # Build Flask response
        response = make_response(template.body, template.status_code)
        
        # Apply headers
        for header, value in template.headers.items():
            response.headers[header] = value
        
        metadata['response_type'] = recommendation
        metadata['template_used'] = template.attack_type
        
        return response, metadata
    
    def _get_primary_attack(self, attacks: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Get the highest severity attack from the list."""
        if not attacks:
            return {'type': 'unknown'}
        
        severity_order = {'CRITICAL': 4, 'HIGH': 3, 'MEDIUM': 2, 'LOW': 1}
        return max(
            attacks,
            key=lambda a: severity_order.get(a.get('severity', 'LOW'), 0)
        )
    
    def _get_success_response(
        self,
        attack_type: str,
        progression: float,
        request_data: Dict[str, Any],
        chain_stage: str = 'recon'
    ) -> ResponseTemplate:
        """
        Generate a "successful" attack response.
        
        Makes the attacker believe their exploit worked.
        """
        url = request_data.get('url', '')
        params = request_data.get('params', {})
        body = request_data.get('body', '')
        
        # LFI-specific responses
        if attack_type == 'lfi':
            return self._get_lfi_response(url, params)
        
        # SSRF-specific responses
        if attack_type == 'ssrf':
            return self._get_ssrf_response(params, body)
        
        # Command injection responses
        if attack_type == 'command_injection':
            return self._get_command_response(params, body)

        # Stage-aware progression: reward deeper chain stages with richer data.
        if chain_stage in {'privilege_escalation', 'persistence', 'data_exfiltration'}:
            boosted = min(1.0, progression + 0.15)
            return get_progressive_response(attack_type, boosted)
        
        # Default success
        return get_progressive_response(attack_type, progression)

    def _apply_context_variation(
        self,
        template: ResponseTemplate,
        attack_type: str,
        progression_score: float,
        chain_stage: str
    ) -> Tuple[ResponseTemplate, str]:
        """
        Apply realistic response variability.

        Behavior modes:
        - stable: deterministic response
        - jitter: minor timing variance
        - partial_failure: intermittent error despite valid chain
        """
        behavior_mode = 'stable'
        staged_bonus = {
            'recon': 0.0,
            'initial_access': 0.05,
            'privilege_escalation': 0.08,
            'persistence': 0.12,
            'data_exfiltration': 0.15,
        }
        variance = random.random()
        partial_failure_threshold = 0.05 if progression_score < 0.5 else 0.12
        partial_failure_threshold += staged_bonus.get(chain_stage, 0.0)

        if variance < partial_failure_threshold:
            behavior_mode = 'partial_failure'
            return (
                ResponseTemplate(
                    attack_type=template.attack_type,
                    status_code=503,
                    headers={'Content-Type': 'application/json'},
                    body='{"status":"error","message":"backend shard timeout, retry shortly"}',
                    delay_ms=max(template.delay_ms, 800) + random.randint(100, 900)
                ),
                behavior_mode
            )

        if variance < 0.75:
            behavior_mode = 'jitter'
            return (
                ResponseTemplate(
                    attack_type=template.attack_type,
                    status_code=template.status_code,
                    headers=template.headers,
                    body=template.body,
                    delay_ms=max(0, template.delay_ms + random.randint(-80, 220))
                ),
                behavior_mode
            )

        return template, behavior_mode
    
    def _get_lfi_response(
        self,
        url: str,
        params: Dict[str, Any]
    ) -> ResponseTemplate:
        """
        Generate LFI-specific response based on requested file.
        """
        # Check what file they're trying to access
        all_params = str(params) + url
        
        if '/etc/passwd' in all_params or 'passwd' in all_params:
            return LFI_RESPONSES['passwd']
        if '/etc/shadow' in all_params or 'shadow' in all_params:
            return LFI_RESPONSES['shadow']
        if '.env' in all_params or 'env' in url:
            return LFI_RESPONSES['env']
        if 'config' in all_params:
            return LFI_RESPONSES['config']
        if '/proc/' in all_params:
            return LFI_RESPONSES['proc_self']
        
        # Default to passwd for path traversal
        return LFI_RESPONSES['passwd']
    
    def _get_ssrf_response(
        self,
        params: Dict[str, Any],
        body: str
    ) -> ResponseTemplate:
        """
        Generate SSRF-specific response based on target.
        """
        all_content = str(params) + body
        
        if '169.254.169.254' in all_content:
            return SSRF_RESPONSES['aws_metadata']
        if 'metadata.google' in all_content:
            return SSRF_RESPONSES['gcp_metadata']
        
        # Default to AWS metadata (most common target)
        return SSRF_RESPONSES['aws_metadata']
    
    def _get_command_response(
        self,
        params: Dict[str, Any],
        body: str
    ) -> ResponseTemplate:
        """
        Generate command injection response based on command.
        """
        all_content = str(params) + body
        
        if 'passwd' in all_content:
            return random.choice(COMMAND_INJECTION_RESPONSES['fake_passwd'])
        
        return random.choice(COMMAND_INJECTION_RESPONSES['fake_shell_output'])
    
    def _get_error_response(
        self,
        attack_type: str,
        request_data: Dict[str, Any]
    ) -> ResponseTemplate:
        """
        Generate a tantalizing error response.
        
        Shows just enough to suggest the vulnerability exists.
        """
        return get_response_for_attack(attack_type, 'error_revealing')
    
    def _get_delayed_response(self) -> ResponseTemplate:
        """
        Generate a delayed response for rate-limited attackers.
        """
        return ResponseTemplate(
            attack_type='rate_limited',
            status_code=200,
            headers={'Content-Type': 'application/json'},
            body='{"status": "processing", "message": "Request queued"}',
            delay_ms=3000  # 3 second delay
        )


class ProgressionManager:
    """
    Manages response progression based on attacker behavior.
    
    INTERNAL: Implements the "progressive deception" strategy:
    - New attackers get minimal responses
    - Persistent attackers get more "interesting" data
    - The goal is to keep them engaged
    """
    
    # Progression thresholds for different response levels
    THRESHOLDS = {
        'basic': 0.0,       # Default responses
        'teasing': 0.25,    # Show hints of vulnerabilities
        'success': 0.5,     # Show successful exploitation
        'sensitive': 0.75,  # Show fake sensitive data
        'full': 0.9         # Full access to fake system
    }
    
    def get_response_level(self, progression: float) -> str:
        """
        Determine response level based on progression score.
        """
        if progression >= self.THRESHOLDS['full']:
            return 'full'
        elif progression >= self.THRESHOLDS['sensitive']:
            return 'sensitive'
        elif progression >= self.THRESHOLDS['success']:
            return 'success'
        elif progression >= self.THRESHOLDS['teasing']:
            return 'teasing'
        return 'basic'
    
    def should_escalate(
        self,
        current_level: str,
        attack_severity: str,
        request_count: int
    ) -> bool:
        """
        Determine if we should escalate response level.
        
        Escalation happens when:
        - Attacker uses high-severity techniques
        - Attacker is persistent (many requests)
        """
        if attack_severity in ['CRITICAL', 'HIGH']:
            return True
        if request_count > 10:
            return True
        return False


# Singleton instances
_response_engine: Optional[ResponseEngine] = None
_progression_manager: Optional[ProgressionManager] = None


def get_response_engine() -> ResponseEngine:
    """Get or create response engine singleton."""
    global _response_engine
    if _response_engine is None:
        _response_engine = ResponseEngine()
    return _response_engine


def get_progression_manager() -> ProgressionManager:
    """Get or create progression manager singleton."""
    global _progression_manager
    if _progression_manager is None:
        _progression_manager = ProgressionManager()
    return _progression_manager
