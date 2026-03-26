"""
Wazuh SIEM Integration

Parses and normalizes alerts from Wazuh SIEM.

INTERNAL DOCUMENTATION:
- Wazuh provides security alerts and compliance data
- Events include intrusion detection, file integrity, etc.
- Enriches honeypot data with broader context
"""

from typing import Dict, Any, Optional, List

from .base import BaseIntegration, NormalizedEvent, EventNormalizer


class WazuhIntegration(BaseIntegration):
    """
    Integration for Wazuh SIEM/XDR platform.
    
    Wazuh provides:
    - Security analytics
    - Intrusion detection
    - Log data analysis
    - File integrity monitoring
    - Vulnerability detection
    
    This integration normalizes Wazuh alerts to our standard format.
    """
    
    def __init__(self, config: Dict[str, Any] = None):
        """
        Initialize Wazuh integration.
        
        Config options:
        - api_url: Wazuh API URL
        - api_user: API username
        - api_password: API password
        """
        super().__init__(config)
        self._normalizer = EventNormalizer()
    
    def get_source_name(self) -> str:
        """Return integration source name."""
        return 'wazuh'
    
    def validate_event(self, event: Dict[str, Any]) -> bool:
        """
        Validate Wazuh event structure.
        """
        # Wazuh alerts have different structures
        # Accept if it has basic identification
        return 'rule' in event or '_source' in event or 'id' in event
    
    def parse_event(self, raw_event: Dict[str, Any]) -> Optional[NormalizedEvent]:
        """
        Parse Wazuh alert into normalized format.
        """
        try:
            # Handle Elasticsearch wrapped events
            if '_source' in raw_event:
                raw_event = raw_event['_source']
            
            # Extract rule information
            rule = raw_event.get('rule', {})
            rule_id = rule.get('id', 'unknown')
            rule_description = rule.get('description', '')
            rule_level = rule.get('level', 3)
            
            # Extract timestamp
            timestamp = self._normalizer.normalize_timestamp(
                raw_event.get('timestamp', raw_event.get('@timestamp', ''))
            )
            
            # Extract network information
            agent = raw_event.get('agent', {})
            data = raw_event.get('data', {})
            
            source_ip = (
                data.get('srcip') or
                data.get('src_ip') or
                data.get('srcUser', {}).get('ip') or
                'unknown'
            )
            
            dest_ip = (
                data.get('dstip') or
                data.get('dst_ip') or
                agent.get('ip') or
                '0.0.0.0'
            )
            
            dest_port = int(data.get('dstport', data.get('dst_port', 0)))
            
            # Map to normalized event type
            event_type = self._map_event_type(rule_id, rule)
            severity = self._level_to_severity(rule_level)
            indicators = self._extract_indicators(raw_event)
            
            return NormalizedEvent(
                source='wazuh',
                event_type=event_type,
                timestamp=timestamp,
                source_ip=source_ip,
                destination_ip=dest_ip,
                destination_port=dest_port,
                protocol=data.get('protocol', 'unknown'),
                raw_event=raw_event,
                severity=severity,
                description=rule_description,
                indicators=indicators
            )
        
        except Exception:
            return None
    
    def _map_event_type(self, rule_id: str, rule: Dict[str, Any]) -> str:
        """Map Wazuh rule to normalized event type."""
        groups = rule.get('groups', [])
        
        # Check groups for event type
        if 'authentication_failed' in groups:
            return 'auth_failed'
        if 'authentication_success' in groups:
            return 'auth_success'
        if 'web-attack' in groups or 'attack' in groups:
            return 'attack_detected'
        if 'sshd' in groups:
            return 'ssh_event'
        if 'syslog' in groups:
            return 'system_event'
        if 'web' in groups:
            return 'http_request'
        if 'scan' in groups or 'recon' in groups:
            return 'scanning'
        if 'exploit' in groups:
            return 'exploit_attempt'
        
        # Default based on rule level
        level = rule.get('level', 0)
        if level >= 12:
            return 'critical_alert'
        if level >= 8:
            return 'high_alert'
        if level >= 4:
            return 'alert'
        
        return 'info'
    
    def _level_to_severity(self, level: int) -> str:
        """Convert Wazuh rule level to severity."""
        if level >= 12:
            return 'critical'
        if level >= 8:
            return 'high'
        if level >= 4:
            return 'medium'
        return 'low'
    
    def _extract_indicators(self, event: Dict[str, Any]) -> List[str]:
        """Extract indicators from Wazuh event."""
        indicators = []
        data = event.get('data', {})
        rule = event.get('rule', {})
        
        # Rule information
        if 'id' in rule:
            indicators.append(f'wazuh_rule:{rule["id"]}')
        
        # MITRE ATT&CK
        mitre = rule.get('mitre', {})
        if 'technique' in mitre:
            for technique in mitre['technique']:
                indicators.append(f'mitre:{technique}')
        
        # Network indicators
        if 'srcip' in data:
            indicators.append(f'src_ip:{data["srcip"]}')
        if 'url' in data:
            indicators.append(f'url:{data["url"][:100]}')
        
        # File indicators
        if 'sha256' in data:
            indicators.append(f'sha256:{data["sha256"]}')
        if 'md5' in data:
            indicators.append(f'md5:{data["md5"]}')
        
        # User information
        if 'srcuser' in data:
            indicators.append(f'username:{data["srcuser"]}')
        
        return indicators
