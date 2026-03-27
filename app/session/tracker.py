"""
Session Tracker Module

Tracks attacker behavior patterns within sessions for profiling and stage detection.

INTERNAL DOCUMENTATION:
- Maintains behavioral state per session
- Detects progression through attack stages
- Used by response engine to tailor fake responses
"""

from typing import Dict, List, Any, Optional
import time
from collections import defaultdict


class SessionTracker:
    """
    Tracks and analyzes attacker behavior patterns.
    
    INTERNAL: This class maintains detailed behavioral state:
    - Endpoints accessed
    - Attack techniques used
    - Time between requests
    - Progression through attack stages
    
    This data is used to:
    1. Detect attacker stage (recon, access, exploit, escalate)
    2. Tailor responses to encourage deeper exploration
    3. Build attacker profile for logging
    """
    
    # Attack stage definitions
    STAGES = {
        'recon': 0,      # Initial reconnaissance
        'access': 1,     # Attempting to gain access
        'exploit': 2,    # Active exploitation
        'escalate': 3,   # Privilege escalation
        'persist': 4     # Establishing persistence
    }
    
    # Endpoints that indicate specific stages
    STAGE_INDICATORS = {
        'recon': [
            '/robots.txt', '/.well-known/', '/sitemap.xml',
            '/api/health', '/api/version'
        ],
        'access': [
            '/login', '/admin', '/admin/login', '/api/auth',
            '/api/login', '/signin'
        ],
        'exploit': [
            '/api/internal', '/debug', '/files', '/api/users',
            '/api/config', '/admin/api', '/internal'
        ],
        'escalate': [
            '/admin/config', '/admin/users', '/api/admin',
            '/internal/logs', '/admin/database'
        ],
        'persist': [
            '/admin/keys', '/admin/wallet', '/api/keys',
            '/admin/users/create', '/api/webhooks'
        ]
    }
    
    def __init__(self):
        """Initialize session tracker with empty state."""
        self._sessions: Dict[str, Dict[str, Any]] = defaultdict(lambda: {
            'created': time.time(),
            'last_seen': time.time(),
            'stage': 'recon',
            'chain_stage': 'recon',
            'chain_progression': 0.0,
            'chain_timeline': [],
            'chain_path': ['recon'],
            'chain_skill_level': 'basic',
            'chain_scenarios_completed': 0,
            'chain_next_hints': [],
            'stage_confidence': 0.0,
            'endpoints': [],
            'attacks': [],
            'request_times': [],
            'techniques_used': set(),
            'payload_patterns': [],
            'success_count': 0,  # Number of "successful" exploits
            'progression_score': 0.0
        })
    
    def track_request(
        self,
        session_id: str,
        endpoint: str,
        detected_attacks: List[str],
        request_data: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Track a request and update session state.
        
        Args:
            session_id: Session identifier
            endpoint: Requested endpoint path
            detected_attacks: List of detected attack types
            request_data: Raw request data for pattern analysis
            
        Returns:
            Updated session analysis
        """
        session = self._sessions[session_id]
        current_time = time.time()
        
        # Update timestamps
        session['last_seen'] = current_time
        session['request_times'].append(current_time)
        
        # Track endpoint
        session['endpoints'].append({
            'path': endpoint,
            'time': current_time
        })
        
        # Track attacks
        for attack in detected_attacks:
            session['attacks'].append({
                'type': attack,
                'time': current_time,
                'endpoint': endpoint
            })
            session['techniques_used'].add(attack)
        
        # Update stage based on behavior
        new_stage = self._determine_stage(session, endpoint, detected_attacks)
        if new_stage != session['stage']:
            session['stage'] = new_stage
        
        # Calculate progression score
        session['progression_score'] = self._calculate_progression(session)
        
        return {
            'stage': session['stage'],
            'progression_score': session['progression_score'],
            'chain_stage': session.get('chain_stage', session['stage']),
            'chain_progression': session.get('chain_progression', 0.0),
            'techniques_count': len(session['techniques_used']),
            'request_count': len(session['endpoints'])
        }

    def set_chain_state(
        self,
        session_id: str,
        chain_stage: str,
        chain_progression: float,
        timeline: List[Dict[str, Any]],
        attack_path: List[str],
        skill_level: str,
        scenarios_completed: int,
        next_hints: Optional[List[str]] = None
    ) -> None:
        """Attach attack-chain context to a tracked session."""
        session = self._sessions[session_id]
        session['chain_stage'] = chain_stage
        session['chain_progression'] = max(0.0, min(float(chain_progression), 1.0))
        session['chain_timeline'] = list(timeline)[-40:]
        session['chain_path'] = list(attack_path) if attack_path else [chain_stage]
        session['chain_skill_level'] = skill_level
        session['chain_scenarios_completed'] = int(scenarios_completed)
        session['chain_next_hints'] = list(next_hints or [])[:8]

        # Keep legacy stage moving forward with chain progression for compatibility.
        legacy_stage_map = {
            'recon': 'recon',
            'initial_access': 'access',
            'privilege_escalation': 'escalate',
            'persistence': 'persist',
            'data_exfiltration': 'persist'
        }
        mapped_stage = legacy_stage_map.get(chain_stage)
        if mapped_stage and self.STAGES[mapped_stage] >= self.STAGES.get(session['stage'], 0):
            session['stage'] = mapped_stage
    
    def _determine_stage(
        self,
        session: Dict[str, Any],
        endpoint: str,
        attacks: List[str]
    ) -> str:
        """
        Determine attacker stage based on behavior.
        
        INTERNAL: Stage detection uses:
        1. Endpoint patterns
        2. Attack techniques used
        3. Time patterns
        4. Historical behavior
        """
        current_stage = session['stage']
        current_stage_num = self.STAGES.get(current_stage, 0)
        
        # Check endpoint indicators
        for stage, indicators in self.STAGE_INDICATORS.items():
            stage_num = self.STAGES[stage]
            if any(endpoint.startswith(ind) for ind in indicators):
                if stage_num >= current_stage_num:
                    return stage
        
        # Check attack types
        attack_stage_map = {
            'directory_fuzzing': 'recon',
            'endpoint_scanning': 'recon',
            'sqli': 'access',
            'credential_bruteforce': 'access',
            'sqli_blind': 'exploit',
            'command_injection': 'exploit',
            'lfi': 'exploit',
            'ssrf': 'exploit',
            'privilege_escalation': 'escalate',
            'jwt_tampering': 'escalate',
            'persistence_attempt': 'persist'
        }
        
        for attack in attacks:
            if attack in attack_stage_map:
                attack_stage = attack_stage_map[attack]
                attack_stage_num = self.STAGES[attack_stage]
                if attack_stage_num > current_stage_num:
                    return attack_stage
        
        return current_stage
    
    def _calculate_progression(self, session: Dict[str, Any]) -> float:
        """
        Calculate attacker progression score (0.0 to 1.0).
        
        Used by response engine to determine response complexity.
        """
        score = 0.0
        
        # Stage contribution (0-40%)
        stage_num = self.STAGES.get(session['stage'], 0)
        score += (stage_num / 4) * 0.4
        
        # Technique diversity contribution (0-30%)
        techniques = len(session['techniques_used'])
        score += min(techniques / 10, 1.0) * 0.3
        
        # Endpoint coverage contribution (0-20%)
        unique_endpoints = len(set(e['path'] for e in session['endpoints']))
        score += min(unique_endpoints / 20, 1.0) * 0.2
        
        # Success count contribution (0-10%)
        score += min(session['success_count'] / 5, 1.0) * 0.1
        
        return min(score, 1.0)
    
    def get_session_profile(self, session_id: str) -> Dict[str, Any]:
        """
        Get complete session profile for logging.
        
        Returns comprehensive attacker profile data.
        """
        session = self._sessions[session_id]
        
        return {
            'session_id': session_id,
            'duration': time.time() - session['created'],
            'stage': session['stage'],
            'chain_stage': session.get('chain_stage', session['stage']),
            'chain_progression': session.get('chain_progression', session['progression_score']),
            'chain_timeline': session.get('chain_timeline', []),
            'chain_path': session.get('chain_path', [session['stage']]),
            'chain_skill_level': session.get('chain_skill_level', 'basic'),
            'chain_scenarios_completed': session.get('chain_scenarios_completed', 0),
            'chain_next_hints': session.get('chain_next_hints', []),
            'progression': session['progression_score'],
            'techniques': list(session['techniques_used']),
            'endpoint_count': len(session['endpoints']),
            'attack_count': len(session['attacks']),
            'avg_request_interval': self._avg_request_interval(session),
            'behavior_pattern': self._detect_behavior_pattern(session)
        }
    
    def _avg_request_interval(self, session: Dict[str, Any]) -> float:
        """Calculate average time between requests."""
        times = session['request_times']
        if len(times) < 2:
            return 0.0
        
        intervals = [times[i+1] - times[i] for i in range(len(times)-1)]
        return sum(intervals) / len(intervals)
    
    def _detect_behavior_pattern(self, session: Dict[str, Any]) -> str:
        """
        Detect behavioral pattern type.
        
        Returns: 'automated', 'manual', 'hybrid', 'unknown'
        """
        avg_interval = self._avg_request_interval(session)
        technique_count = len(session['techniques_used'])
        
        if avg_interval < 0.5 and technique_count > 3:
            return 'automated'
        elif avg_interval > 5.0 and technique_count <= 3:
            return 'manual'
        elif technique_count > 2:
            return 'hybrid'
        return 'unknown'
    
    def record_success(self, session_id: str) -> None:
        """Record a successful exploit for progression tracking."""
        if session_id in self._sessions:
            self._sessions[session_id]['success_count'] += 1
