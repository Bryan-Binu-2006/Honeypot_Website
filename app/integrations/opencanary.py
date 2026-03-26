"""
OpenCanary Integration

Parses and normalizes events from OpenCanary honeypot.

INTERNAL DOCUMENTATION:
- OpenCanary simulates multiple services (FTP, HTTP, SSH, etc.)
- Provides alerts when services are accessed
- Complements web honeypot with additional service coverage
"""

from typing import Dict, Any, Optional, List
import json

from .base import BaseIntegration, NormalizedEvent, EventNormalizer


class OpenCanaryIntegration(BaseIntegration):
    """
    Integration for OpenCanary honeypot.
    
    OpenCanary is a multi-service honeypot that can simulate:
    - FTP
    - HTTP/HTTPS
    - SSH
    - Telnet
    - MySQL
    - MSSQL
    - RDP
    - VNC
    - SIP
    - SNMP
    - NTP
    - TFTP
    - And more...
    
    This integration normalizes these alerts to our standard format.
    """
    
    def __init__(self, config: Dict[str, Any] = None):
        """
        Initialize OpenCanary integration.
        
        Config options:
        - log_path: Path to OpenCanary log file
        """
        super().__init__(config)
        self._normalizer = EventNormalizer()
    
    def get_source_name(self) -> str:
        """Return integration source name."""
        return 'opencanary'
    
    def validate_event(self, event: Dict[str, Any]) -> bool:
        """
        Validate OpenCanary event structure.
        """
        required = ['dst_host', 'dst_port', 'src_host']
        return all(field in event for field in required)
    
    def parse_event(self, raw_event: Dict[str, Any]) -> Optional[NormalizedEvent]:
        """
        Parse OpenCanary event into normalized format.
        """
        try:
            # Extract basic fields
            timestamp = self._normalizer.normalize_timestamp(
                raw_event.get('local_time', raw_event.get('utc_time', ''))
            )
            
            source_ip = raw_event.get('src_host', 'unknown')
            source_port = raw_event.get('src_port', 0)
            dest_ip = raw_event.get('dst_host', '0.0.0.0')
            dest_port = raw_event.get('dst_port', 0)
            
            # Get log type for event mapping
            logtype = raw_event.get('logtype', 0)
            logdata = raw_event.get('logdata', {})
            
            # Map to normalized event type
            event_type, protocol = self._map_logtype(logtype)
            severity = self._determine_severity(logtype, logdata)
            description = self._generate_description(logtype, logdata)
            indicators = self._extract_indicators(raw_event)
            
            return NormalizedEvent(
                source='opencanary',
                event_type=event_type,
                timestamp=timestamp,
                source_ip=source_ip,
                destination_ip=dest_ip,
                destination_port=dest_port,
                protocol=protocol,
                raw_event=raw_event,
                severity=severity,
                description=description,
                indicators=indicators
            )
        
        except Exception:
            return None
    
    def _map_logtype(self, logtype: int) -> tuple:
        """
        Map OpenCanary logtype to event type and protocol.
        
        OpenCanary logtypes:
        1000 - Boot
        2000 - SSH login attempt
        3000 - FTP login attempt
        4000 - HTTP request
        5000 - HTTP login attempt
        6000 - Telnet login attempt
        7000 - MySQL login attempt
        8000 - MSSQL login attempt
        9000 - RDP login attempt
        10000 - VNC login attempt
        11000 - SIP request
        12000 - NTP monlist
        13000 - SNMP request
        14000 - TFTP request
        15000 - HTTPPROXY request
        16000 - GIT clone
        17000 - SMB file open
        """
        type_map = {
            1000: ('system_boot', 'system'),
            2000: ('ssh_login_attempt', 'ssh'),
            3000: ('ftp_login_attempt', 'ftp'),
            4000: ('http_request', 'http'),
            5000: ('http_login_attempt', 'http'),
            6000: ('telnet_login_attempt', 'telnet'),
            7000: ('mysql_login_attempt', 'mysql'),
            8000: ('mssql_login_attempt', 'mssql'),
            9000: ('rdp_login_attempt', 'rdp'),
            10000: ('vnc_login_attempt', 'vnc'),
            11000: ('sip_request', 'sip'),
            12000: ('ntp_monlist', 'ntp'),
            13000: ('snmp_request', 'snmp'),
            14000: ('tftp_request', 'tftp'),
            15000: ('http_proxy_request', 'http'),
            16000: ('git_clone', 'git'),
            17000: ('smb_file_open', 'smb'),
        }
        
        return type_map.get(logtype, ('unknown', 'unknown'))
    
    def _determine_severity(
        self,
        logtype: int,
        logdata: Dict[str, Any]
    ) -> str:
        """Determine event severity."""
        # Login attempts are high severity
        if logtype in [2000, 3000, 5000, 6000, 7000, 8000, 9000, 10000]:
            # Successful logins are critical
            if logdata.get('RESULT', '') == 'SUCCESS':
                return 'critical'
            return 'high'
        
        # RDP and VNC are high (potential remote access)
        if logtype in [9000, 10000]:
            return 'high'
        
        # HTTP requests are medium
        if logtype in [4000, 15000]:
            return 'medium'
        
        # Network reconnaissance is medium
        if logtype in [12000, 13000]:
            return 'medium'
        
        return 'low'
    
    def _generate_description(
        self,
        logtype: int,
        logdata: Dict[str, Any]
    ) -> str:
        """Generate human-readable description."""
        descriptions = {
            2000: f"SSH login attempt with username '{logdata.get('USERNAME', 'unknown')}'",
            3000: f"FTP login attempt with username '{logdata.get('USERNAME', 'unknown')}'",
            4000: f"HTTP request: {logdata.get('METHOD', 'GET')} {logdata.get('PATH', '/')[:50]}",
            5000: f"HTTP login attempt with username '{logdata.get('USERNAME', 'unknown')}'",
            6000: f"Telnet login attempt",
            7000: f"MySQL login attempt with username '{logdata.get('USERNAME', 'unknown')}'",
            8000: f"MSSQL login attempt with username '{logdata.get('USERNAME', 'unknown')}'",
            9000: f"RDP connection attempt",
            10000: f"VNC connection attempt",
            11000: f"SIP request: {logdata.get('METHOD', 'unknown')}",
            12000: f"NTP monlist request (potential amplification attack)",
            13000: f"SNMP request: {logdata.get('OID', 'unknown')}",
            14000: f"TFTP file request: {logdata.get('FILENAME', 'unknown')}",
            15000: f"HTTP proxy request to {logdata.get('HOST', 'unknown')}",
            16000: f"Git clone attempt: {logdata.get('REPO', 'unknown')}",
            17000: f"SMB file access: {logdata.get('FILENAME', 'unknown')}",
        }
        
        return descriptions.get(logtype, f'OpenCanary event type {logtype}')
    
    def _extract_indicators(self, event: Dict[str, Any]) -> List[str]:
        """Extract indicators from OpenCanary event."""
        indicators = []
        logdata = event.get('logdata', {})
        
        # Service type
        indicators.append(f'service_port:{event.get("dst_port", 0)}')
        
        # Username
        if 'USERNAME' in logdata:
            indicators.append(f'username:{logdata["USERNAME"]}')
        
        # Password (hashed indicator only)
        if 'PASSWORD' in logdata:
            indicators.append('password_captured')
        
        # HTTP specific
        if 'PATH' in logdata:
            indicators.append(f'http_path:{logdata["PATH"][:50]}')
        if 'USERAGENT' in logdata:
            indicators.append(f'user_agent:{logdata["USERAGENT"][:50]}')
        
        # File access
        if 'FILENAME' in logdata:
            indicators.append(f'filename:{logdata["FILENAME"]}')
        
        return indicators


def parse_opencanary_log_line(line: str) -> Optional[Dict[str, Any]]:
    """
    Parse a single line from OpenCanary log.
    """
    try:
        return json.loads(line.strip())
    except json.JSONDecodeError:
        return None
