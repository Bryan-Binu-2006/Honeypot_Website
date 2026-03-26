"""
Cowrie SSH Honeypot Integration

Parses and normalizes events from Cowrie SSH honeypot.

INTERNAL DOCUMENTATION:
- Cowrie logs SSH login attempts, commands, and file transfers
- Events are matched to web sessions by IP
- Provides detailed attacker command history
"""

from typing import Dict, Any, Optional, List
import json

from .base import BaseIntegration, NormalizedEvent, EventNormalizer


class CowrieIntegration(BaseIntegration):
    """
    Integration for Cowrie SSH honeypot.
    
    Cowrie is a medium-interaction SSH honeypot that logs:
    - Login attempts (username/password)
    - Commands executed
    - Files downloaded/uploaded
    - TTY sessions
    
    This integration normalizes these events to our standard format.
    """
    
    def __init__(self, config: Dict[str, Any] = None):
        """
        Initialize Cowrie integration.
        
        Config options:
        - log_path: Path to Cowrie JSON log file
        - include_commands: Whether to include command details
        """
        super().__init__(config)
        self._normalizer = EventNormalizer()
    
    def get_source_name(self) -> str:
        """Return integration source name."""
        return 'cowrie'
    
    def validate_event(self, event: Dict[str, Any]) -> bool:
        """
        Validate Cowrie event structure.
        """
        required_fields = ['eventid', 'timestamp', 'src_ip']
        return all(field in event for field in required_fields)
    
    def parse_event(self, raw_event: Dict[str, Any]) -> Optional[NormalizedEvent]:
        """
        Parse Cowrie event into normalized format.
        """
        try:
            event_id = raw_event.get('eventid', '')
            timestamp = self._normalizer.normalize_timestamp(
                raw_event.get('timestamp', '')
            )
            
            # Extract IPs
            source_ip = raw_event.get('src_ip', 'unknown')
            dest_ip = raw_event.get('dst_ip', '0.0.0.0')
            dest_port = raw_event.get('dst_port', 22)
            
            # Map Cowrie event to normalized type
            event_type = self._map_event_type(event_id)
            severity = self._determine_severity(event_id, raw_event)
            description = self._generate_description(event_id, raw_event)
            indicators = self._extract_indicators(raw_event)
            
            return NormalizedEvent(
                source='cowrie',
                event_type=event_type,
                timestamp=timestamp,
                source_ip=source_ip,
                destination_ip=dest_ip,
                destination_port=dest_port,
                protocol='ssh',
                raw_event=raw_event,
                severity=severity,
                description=description,
                indicators=indicators
            )
        
        except Exception:
            return None
    
    def _map_event_type(self, event_id: str) -> str:
        """Map Cowrie event ID to normalized type."""
        type_map = {
            'cowrie.login.success': 'auth_success',
            'cowrie.login.failed': 'auth_failed',
            'cowrie.command.input': 'command_execution',
            'cowrie.command.failed': 'command_failed',
            'cowrie.session.connect': 'session_start',
            'cowrie.session.closed': 'session_end',
            'cowrie.session.file_download': 'file_download',
            'cowrie.session.file_upload': 'file_upload',
            'cowrie.client.version': 'client_info',
            'cowrie.client.size': 'client_info',
            'cowrie.direct-tcpip.request': 'tunnel_request',
        }
        return type_map.get(event_id, 'unknown')
    
    def _determine_severity(
        self,
        event_id: str,
        event: Dict[str, Any]
    ) -> str:
        """Determine event severity."""
        # Successful logins are high severity
        if event_id == 'cowrie.login.success':
            return 'high'
        
        # Command execution is high
        if 'command' in event_id:
            command = event.get('input', '').lower()
            # Certain commands are critical
            if any(cmd in command for cmd in ['wget', 'curl', 'chmod', 'nc', 'bash -i']):
                return 'critical'
            return 'high'
        
        # File transfers are high
        if 'file_download' in event_id or 'file_upload' in event_id:
            return 'high'
        
        # Failed logins are medium
        if 'failed' in event_id:
            return 'medium'
        
        return 'low'
    
    def _generate_description(
        self,
        event_id: str,
        event: Dict[str, Any]
    ) -> str:
        """Generate human-readable description."""
        if event_id == 'cowrie.login.success':
            user = event.get('username', 'unknown')
            return f'Successful SSH login as {user}'
        
        if event_id == 'cowrie.login.failed':
            user = event.get('username', 'unknown')
            return f'Failed SSH login attempt as {user}'
        
        if event_id == 'cowrie.command.input':
            cmd = event.get('input', '')[:100]
            return f'Command executed: {cmd}'
        
        if event_id == 'cowrie.session.file_download':
            url = event.get('url', event.get('outfile', 'unknown'))
            return f'File download attempt: {url}'
        
        if event_id == 'cowrie.session.connect':
            return f'SSH session started from {event.get("src_ip", "unknown")}'
        
        if event_id == 'cowrie.session.closed':
            return f'SSH session ended'
        
        return f'Cowrie event: {event_id}'
    
    def _extract_indicators(self, event: Dict[str, Any]) -> List[str]:
        """Extract indicators of compromise from event."""
        indicators = []
        
        # Username/password
        if 'username' in event:
            indicators.append(f'username:{event["username"]}')
        if 'password' in event:
            # Hash the password for the indicator
            indicators.append(f'password_attempted')
        
        # Commands
        if 'input' in event:
            cmd = event['input']
            indicators.append(f'command:{cmd[:50]}')
            
            # Extract URLs from commands
            if 'http' in cmd:
                indicators.append('url_in_command')
        
        # Files
        if 'url' in event:
            indicators.append(f'download_url:{event["url"]}')
        if 'shasum' in event:
            indicators.append(f'sha256:{event["shasum"]}')
        
        # Client info
        if 'version' in event:
            indicators.append(f'ssh_client:{event["version"]}')
        
        return indicators
    
    def enrich_event(self, event: NormalizedEvent) -> NormalizedEvent:
        """
        Enrich event with Cowrie-specific context.
        """
        raw = event.raw_event
        
        # Add session ID if present
        if 'session' in raw:
            event.raw_event['cowrie_session'] = raw['session']
        
        return event


def parse_cowrie_log_line(line: str) -> Optional[Dict[str, Any]]:
    """
    Parse a single line from Cowrie JSON log.
    
    Cowrie logs one JSON object per line.
    """
    try:
        return json.loads(line.strip())
    except json.JSONDecodeError:
        return None
