"""
Behavior Engine - Main Coordinator

Manages attacker behavior tracking and progressive deception.

INTERNAL DOCUMENTATION:
- Tracks attacker progression through stages
- Coordinates response escalation
- Maintains attacker profiles across sessions
"""

from typing import Dict, Any, Optional, List
from dataclasses import dataclass
import time
from collections import defaultdict


@dataclass
class AttackerProfile:
    """Profile data for an attacker session."""
    session_id: str
    first_seen: float
    last_seen: float
    stage: str
    progression: float
    techniques_used: List[str]
    endpoints_accessed: List[str]
    success_count: int
    behavior_pattern: str


class BehaviorEngine:
    """
    Coordinates attacker behavior tracking and response adaptation.
    
    INTERNAL: The behavior engine is responsible for:
    
    1. Tracking attacker progression through attack stages:
       - Recon: Initial reconnaissance (robots.txt, scanning)
       - Access: Attempting authentication bypass
       - Exploit: Active exploitation attempts
       - Escalate: Privilege escalation
       - Persist: Establishing persistence
    
    2. Adapting responses based on progression:
       - New attackers get minimal responses
       - Persistent attackers get more "interesting" data
       - Goal: Maximize engagement time
    
    3. Building attacker profiles for analysis:
       - Technique fingerprinting
       - Behavior pattern detection (automated vs manual)
       - Session correlation
    """
    
    # Stage definitions with their indicators
    STAGES = {
        'recon': {
            'order': 0,
            'description': 'Initial reconnaissance',
            'indicators': ['robots.txt', 'sitemap', '.well-known', 'version', 'health']
        },
        'access': {
            'order': 1,
            'description': 'Authentication attempts',
            'indicators': ['login', 'auth', 'signin', 'register', 'forgot']
        },
        'exploit': {
            'order': 2,
            'description': 'Active exploitation',
            'indicators': ['admin', 'api/internal', 'debug', 'files', 'upload']
        },
        'escalate': {
            'order': 3,
            'description': 'Privilege escalation',
            'indicators': ['terminal', 'exec', 'config', 'users', 'roles']
        },
        'persist': {
            'order': 4,
            'description': 'Establishing persistence',
            'indicators': ['keys', 'wallet', 'webhook', 'cron', 'ssh']
        }
    }
    
    # Attack technique to stage mapping
    TECHNIQUE_STAGES = {
        'recon_robots': 'recon',
        'directory_fuzzing': 'recon',
        'endpoint_scanning': 'recon',
        'sqli_classic': 'access',
        'nosql_injection': 'access',
        'credential_bruteforce': 'access',
        'sqli_blind': 'exploit',
        'command_injection': 'exploit',
        'lfi': 'exploit',
        'rfi': 'exploit',
        'ssrf': 'exploit',
        'xxe': 'exploit',
        'ssti_jinja2': 'exploit',
        'jwt_tampering': 'escalate',
        'idor': 'escalate',
        'session_fixation': 'persist',
        'file_upload_bypass': 'persist',
    }
    
    def __init__(self):
        """Initialize behavior engine."""
        self._profiles: Dict[str, AttackerProfile] = {}
        self._request_counts: Dict[str, int] = defaultdict(int)
    
    def track_behavior(
        self,
        session_id: str,
        endpoint: str,
        detected_attacks: List[Dict[str, Any]],
        request_data: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Track attacker behavior and update profile.
        
        Args:
            session_id: Attacker session identifier
            endpoint: Requested endpoint
            detected_attacks: List of detected attacks
            request_data: Request data
            
        Returns:
            Updated behavior analysis
        """
        # Get or create profile
        profile = self._get_or_create_profile(session_id)
        
        # Update timestamps
        profile.last_seen = time.time()
        
        # Track endpoint
        if endpoint not in profile.endpoints_accessed:
            profile.endpoints_accessed.append(endpoint)
        
        # Track techniques
        for attack in detected_attacks:
            attack_type = attack.get('type', '')
            if attack_type and attack_type not in profile.techniques_used:
                profile.techniques_used.append(attack_type)
        
        # Update stage
        new_stage = self._determine_stage(profile, endpoint, detected_attacks)
        if self._should_advance_stage(profile.stage, new_stage):
            profile.stage = new_stage
        
        # Update progression
        profile.progression = self._calculate_progression(profile)
        
        # Detect behavior pattern
        profile.behavior_pattern = self._detect_behavior_pattern(session_id)
        
        # Update request count
        self._request_counts[session_id] += 1
        
        return {
            'stage': profile.stage,
            'progression': profile.progression,
            'techniques_count': len(profile.techniques_used),
            'behavior_pattern': profile.behavior_pattern,
            'session_duration': profile.last_seen - profile.first_seen,
            'request_count': self._request_counts[session_id]
        }
    
    def _get_or_create_profile(self, session_id: str) -> AttackerProfile:
        """Get existing profile or create new one."""
        if session_id not in self._profiles:
            self._profiles[session_id] = AttackerProfile(
                session_id=session_id,
                first_seen=time.time(),
                last_seen=time.time(),
                stage='recon',
                progression=0.0,
                techniques_used=[],
                endpoints_accessed=[],
                success_count=0,
                behavior_pattern='unknown'
            )
        return self._profiles[session_id]
    
    def _determine_stage(
        self,
        profile: AttackerProfile,
        endpoint: str,
        attacks: List[Dict[str, Any]]
    ) -> str:
        """Determine current attack stage."""
        # Check endpoint indicators
        for stage, config in self.STAGES.items():
            for indicator in config['indicators']:
                if indicator in endpoint.lower():
                    return stage
        
        # Check attack techniques
        for attack in attacks:
            attack_type = attack.get('type', '')
            if attack_type in self.TECHNIQUE_STAGES:
                return self.TECHNIQUE_STAGES[attack_type]
        
        return profile.stage
    
    def _should_advance_stage(self, current: str, new: str) -> bool:
        """Check if stage should advance (never go backwards)."""
        current_order = self.STAGES.get(current, {}).get('order', 0)
        new_order = self.STAGES.get(new, {}).get('order', 0)
        return new_order >= current_order
    
    def _calculate_progression(self, profile: AttackerProfile) -> float:
        """
        Calculate attacker progression score (0.0 to 1.0).
        """
        score = 0.0
        
        # Stage contribution (0-40%)
        stage_order = self.STAGES.get(profile.stage, {}).get('order', 0)
        score += (stage_order / 4) * 0.4
        
        # Technique diversity (0-30%)
        technique_score = min(len(profile.techniques_used) / 10, 1.0)
        score += technique_score * 0.3
        
        # Endpoint coverage (0-20%)
        endpoint_score = min(len(profile.endpoints_accessed) / 20, 1.0)
        score += endpoint_score * 0.2
        
        # Success count (0-10%)
        success_score = min(profile.success_count / 5, 1.0)
        score += success_score * 0.1
        
        return min(score, 1.0)
    
    def _detect_behavior_pattern(self, session_id: str) -> str:
        """
        Detect if attacker is automated tool or manual.
        """
        profile = self._profiles.get(session_id)
        if not profile:
            return 'unknown'
        
        request_count = self._request_counts[session_id]
        duration = profile.last_seen - profile.first_seen
        
        if duration < 1:
            return 'unknown'
        
        rate = request_count / duration  # requests per second
        
        if rate > 5:  # More than 5 req/s
            return 'automated'
        elif rate < 0.1:  # Less than 1 req per 10 seconds
            return 'manual'
        else:
            return 'hybrid'
    
    def record_success(self, session_id: str) -> None:
        """Record a successful exploit for the session."""
        if session_id in self._profiles:
            self._profiles[session_id].success_count += 1
    
    def get_profile(self, session_id: str) -> Optional[Dict[str, Any]]:
        """Get profile data for a session."""
        profile = self._profiles.get(session_id)
        if not profile:
            return None
        
        return {
            'session_id': profile.session_id,
            'first_seen': profile.first_seen,
            'last_seen': profile.last_seen,
            'stage': profile.stage,
            'progression': profile.progression,
            'techniques_used': profile.techniques_used,
            'endpoints_accessed': profile.endpoints_accessed,
            'success_count': profile.success_count,
            'behavior_pattern': profile.behavior_pattern,
            'request_count': self._request_counts[session_id],
            'duration': profile.last_seen - profile.first_seen
        }
    
    def get_response_level(self, session_id: str) -> str:
        """
        Get appropriate response level for the session.
        
        Returns: 'basic', 'teasing', 'success', 'sensitive', 'full'
        """
        profile = self._profiles.get(session_id)
        if not profile:
            return 'basic'
        
        progression = profile.progression
        
        if progression >= 0.9:
            return 'full'
        elif progression >= 0.75:
            return 'sensitive'
        elif progression >= 0.5:
            return 'success'
        elif progression >= 0.25:
            return 'teasing'
        return 'basic'


# Singleton instance
_engine: Optional[BehaviorEngine] = None


def get_behavior_engine() -> BehaviorEngine:
    """Get or create behavior engine singleton."""
    global _engine
    if _engine is None:
        _engine = BehaviorEngine()
    return _engine
