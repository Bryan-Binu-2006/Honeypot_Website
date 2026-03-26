"""
Integration Layer - Base Classes and Event Normalization

Provides the plug-and-play integration framework for external honeypot tools.

INTERNAL DOCUMENTATION:
- External tools (Cowrie, Wazuh, OpenCanary) send logs here
- Events are normalized to a unified schema
- Events are matched to existing sessions by IP + timestamp
"""

from abc import ABC, abstractmethod
from typing import Dict, Any, List, Optional
from dataclasses import dataclass
from datetime import datetime
import json


@dataclass
class NormalizedEvent:
    """
    Unified event schema for all integrations.
    
    All external events are converted to this format
    before being attached to attacker profiles.
    """
    source: str              # Integration source (cowrie, wazuh, etc.)
    event_type: str          # Normalized event type
    timestamp: float         # Unix timestamp
    source_ip: str           # Attacker IP
    destination_ip: str      # Target IP (this honeypot)
    destination_port: int    # Target port
    protocol: str            # Protocol (tcp, udp, ssh, http, etc.)
    raw_event: Dict[str, Any]  # Original event data
    severity: str            # Normalized severity (low, medium, high, critical)
    description: str         # Human-readable description
    indicators: List[str]    # IoCs (indicators of compromise)
    session_id: Optional[str] = None  # Matched session ID (if found)


class BaseIntegration(ABC):
    """
    Abstract base class for honeypot integrations.
    
    INTERNAL: All integrations must implement:
    1. parse_event() - Convert raw log to NormalizedEvent
    2. get_source_name() - Return integration identifier
    
    Optional overrides:
    - validate_event() - Custom validation
    - enrich_event() - Add additional context
    """
    
    def __init__(self, config: Dict[str, Any] = None):
        """
        Initialize integration with configuration.
        
        Args:
            config: Integration-specific configuration
        """
        self.config = config or {}
        self._enabled = True
    
    @abstractmethod
    def get_source_name(self) -> str:
        """Return the integration source identifier."""
        pass
    
    @abstractmethod
    def parse_event(self, raw_event: Dict[str, Any]) -> Optional[NormalizedEvent]:
        """
        Parse raw event into normalized format.
        
        Args:
            raw_event: Raw event data from the integration
            
        Returns:
            NormalizedEvent or None if parsing fails
        """
        pass
    
    def validate_event(self, event: Dict[str, Any]) -> bool:
        """
        Validate that an event has required fields.
        
        Can be overridden for custom validation.
        """
        return True
    
    def enrich_event(self, event: NormalizedEvent) -> NormalizedEvent:
        """
        Enrich event with additional context.
        
        Can be overridden to add integration-specific enrichment.
        """
        return event
    
    def process_event(self, raw_event: Dict[str, Any]) -> Optional[NormalizedEvent]:
        """
        Full event processing pipeline.
        
        1. Validate
        2. Parse
        3. Enrich
        """
        if not self.validate_event(raw_event):
            return None
        
        event = self.parse_event(raw_event)
        if event is None:
            return None
        
        return self.enrich_event(event)
    
    def enable(self) -> None:
        """Enable the integration."""
        self._enabled = True
    
    def disable(self) -> None:
        """Disable the integration."""
        self._enabled = False
    
    @property
    def is_enabled(self) -> bool:
        """Check if integration is enabled."""
        return self._enabled


class EventNormalizer:
    """
    Normalizes events from various sources into unified format.
    
    INTERNAL: This class handles:
    1. Event type mapping (ssh_login -> auth_attempt)
    2. Severity normalization
    3. Timestamp conversion
    4. IP extraction
    """
    
    # Event type mapping to normalized types
    EVENT_TYPE_MAP = {
        # SSH events
        'ssh.login.success': 'auth_success',
        'ssh.login.failed': 'auth_failed',
        'ssh.command': 'command_execution',
        'ssh.session.start': 'session_start',
        'ssh.session.end': 'session_end',
        
        # HTTP events
        'http.request': 'http_request',
        'http.attack': 'attack_detected',
        'http.scan': 'scanning',
        
        # Network events
        'connection.new': 'connection',
        'port.scan': 'port_scan',
        'brute.force': 'brute_force',
        
        # File events
        'file.download': 'file_access',
        'file.upload': 'file_upload',
        
        # Generic
        'alert': 'alert',
        'info': 'info',
    }
    
    # Severity mapping
    SEVERITY_MAP = {
        'informational': 'low',
        'info': 'low',
        'low': 'low',
        'warning': 'medium',
        'medium': 'medium',
        'high': 'high',
        'critical': 'critical',
        'severe': 'critical',
    }
    
    def normalize_event_type(self, event_type: str) -> str:
        """Normalize event type to standard format."""
        return self.EVENT_TYPE_MAP.get(event_type.lower(), event_type)
    
    def normalize_severity(self, severity: str) -> str:
        """Normalize severity level."""
        return self.SEVERITY_MAP.get(severity.lower(), 'medium')
    
    def normalize_timestamp(self, timestamp: Any) -> float:
        """
        Convert various timestamp formats to Unix timestamp.
        """
        if isinstance(timestamp, (int, float)):
            return float(timestamp)
        
        if isinstance(timestamp, str):
            # Try common formats
            formats = [
                '%Y-%m-%dT%H:%M:%S.%fZ',
                '%Y-%m-%dT%H:%M:%SZ',
                '%Y-%m-%d %H:%M:%S',
                '%Y/%m/%d %H:%M:%S',
            ]
            
            for fmt in formats:
                try:
                    dt = datetime.strptime(timestamp, fmt)
                    return dt.timestamp()
                except ValueError:
                    continue
        
        # Default to current time
        return datetime.now().timestamp()
    
    def extract_ip(self, event: Dict[str, Any], fields: List[str]) -> str:
        """
        Extract IP address from event using multiple possible field names.
        """
        for field in fields:
            if field in event:
                return str(event[field])
            
            # Handle nested fields (e.g., 'src.ip')
            if '.' in field:
                parts = field.split('.')
                value = event
                for part in parts:
                    if isinstance(value, dict) and part in value:
                        value = value[part]
                    else:
                        value = None
                        break
                if value:
                    return str(value)
        
        return 'unknown'


class SessionMatcher:
    """
    Matches external events to existing honeypot sessions.
    
    INTERNAL: Uses IP address and timestamp window to correlate
    events from external tools with web honeypot sessions.
    """
    
    def __init__(self, time_window: int = 300):
        """
        Initialize session matcher.
        
        Args:
            time_window: Time window in seconds for matching (default 5 minutes)
        """
        self.time_window = time_window
        self._sessions: Dict[str, Dict[str, Any]] = {}
    
    def register_session(
        self,
        session_id: str,
        ip: str,
        timestamp: float
    ) -> None:
        """
        Register a session for matching.
        """
        self._sessions[session_id] = {
            'ip': ip,
            'start_time': timestamp,
            'last_seen': timestamp
        }
    
    def update_session(self, session_id: str, timestamp: float) -> None:
        """Update session last seen time."""
        if session_id in self._sessions:
            self._sessions[session_id]['last_seen'] = timestamp
    
    def find_session(self, ip: str, timestamp: float) -> Optional[str]:
        """
        Find matching session for an event.
        
        Matches by IP and checks if event timestamp falls within
        the session's active time window.
        """
        best_match = None
        best_score = float('inf')
        
        for session_id, session_data in self._sessions.items():
            if session_data['ip'] != ip:
                continue
            
            # Check if timestamp is within session window
            start = session_data['start_time'] - self.time_window
            end = session_data['last_seen'] + self.time_window
            
            if start <= timestamp <= end:
                # Score by how close to last_seen
                score = abs(timestamp - session_data['last_seen'])
                if score < best_score:
                    best_score = score
                    best_match = session_id
        
        return best_match
    
    def attach_event_to_session(
        self,
        event: NormalizedEvent,
        session_id: str
    ) -> NormalizedEvent:
        """Attach session ID to event."""
        event.session_id = session_id
        return event


class IntegrationManager:
    """
    Manages all registered integrations.
    
    INTERNAL: Central manager for:
    1. Registering integrations
    2. Processing events from all sources
    3. Matching events to sessions
    4. Forwarding to logging system
    """
    
    def __init__(self):
        """Initialize integration manager."""
        self._integrations: Dict[str, BaseIntegration] = {}
        self._normalizer = EventNormalizer()
        self._matcher = SessionMatcher()
    
    def register(self, integration: BaseIntegration) -> None:
        """
        Register an integration.
        
        Args:
            integration: Integration instance to register
        """
        name = integration.get_source_name()
        self._integrations[name] = integration
    
    def unregister(self, name: str) -> None:
        """
        Unregister an integration.
        
        Args:
            name: Integration source name
        """
        if name in self._integrations:
            del self._integrations[name]
    
    def process_event(
        self,
        source: str,
        raw_event: Dict[str, Any]
    ) -> Optional[NormalizedEvent]:
        """
        Process an event from a specific source.
        
        Args:
            source: Integration source name
            raw_event: Raw event data
            
        Returns:
            Normalized event or None
        """
        integration = self._integrations.get(source)
        if not integration or not integration.is_enabled:
            return None
        
        event = integration.process_event(raw_event)
        if event is None:
            return None
        
        # Try to match to session
        session_id = self._matcher.find_session(
            event.source_ip,
            event.timestamp
        )
        
        if session_id:
            event = self._matcher.attach_event_to_session(event, session_id)
        
        return event
    
    def get_integrations(self) -> Dict[str, bool]:
        """Get list of integrations and their status."""
        return {
            name: integration.is_enabled
            for name, integration in self._integrations.items()
        }
    
    def register_session(
        self,
        session_id: str,
        ip: str,
        timestamp: float
    ) -> None:
        """Register a session for event matching."""
        self._matcher.register_session(session_id, ip, timestamp)


# Singleton instance
_manager: Optional[IntegrationManager] = None


def get_integration_manager() -> IntegrationManager:
    """Get or create integration manager singleton."""
    global _manager
    if _manager is None:
        _manager = IntegrationManager()
    return _manager
