"""
Logging Service - Input Sanitization

Provides sanitization functions for log data to prevent log injection attacks.

INTERNAL DOCUMENTATION:
- All log data must pass through sanitization
- Prevents SQL injection in log queries
- Prevents log forging and injection
- Preserves data integrity for analysis
"""

import re
import html
from typing import Any, Dict, List, Optional
import json


class LogSanitizer:
    """
    Sanitizes input data for safe logging.
    
    INTERNAL: This sanitizer is used by the logging interface
    to clean all data before it enters the logging pipeline.
    
    Security considerations:
    1. Log injection: Malicious data that corrupts log files
    2. SQL injection: If logs are queried
    3. XSS: If logs are displayed in a web interface
    4. Data exfiltration: Large payloads designed to fill storage
    """
    
    # Maximum lengths for various fields
    MAX_LENGTHS = {
        'string': 5000,
        'url': 2000,
        'ip': 45,  # IPv6 max length
        'method': 10,
        'user_agent': 500,
        'session_id': 100,
        'payload': 50000,
    }
    
    # Characters that could be used for log injection
    DANGEROUS_CHARS = re.compile(r'[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]')
    
    # Patterns that might indicate log injection attempts
    INJECTION_PATTERNS = [
        r'\n\d{4}-\d{2}-\d{2}',  # Fake timestamp injection
        r'\n\[ERROR\]|\n\[INFO\]|\n\[WARN\]',  # Fake log level
        r'%0[aAdD]',  # URL-encoded newlines
        r'\\r\\n|\\n|\\r',  # Escaped newlines in input
    ]
    
    def __init__(self):
        """Initialize sanitizer with compiled patterns."""
        self._injection_regex = re.compile(
            '|'.join(self.INJECTION_PATTERNS),
            re.IGNORECASE
        )
    
    def sanitize_string(
        self,
        value: Any,
        max_length: Optional[int] = None,
        field_name: str = 'string'
    ) -> str:
        """
        Sanitize a string value.
        
        Args:
            value: Value to sanitize
            max_length: Maximum allowed length
            field_name: Field name for length lookup
            
        Returns:
            Sanitized string
        """
        # Convert to string
        if not isinstance(value, str):
            try:
                value = str(value)
            except Exception:
                return ''
        
        # Determine max length
        if max_length is None:
            max_length = self.MAX_LENGTHS.get(field_name, self.MAX_LENGTHS['string'])
        
        # Remove dangerous characters
        value = self.DANGEROUS_CHARS.sub('', value)
        
        # Replace injection patterns
        if self._injection_regex.search(value):
            value = self._injection_regex.sub('[SANITIZED]', value)
        
        # Normalize newlines
        value = value.replace('\r\n', '\\n').replace('\r', '\\n').replace('\n', '\\n')
        
        # Truncate
        if len(value) > max_length:
            value = value[:max_length] + '...[TRUNCATED]'
        
        return value
    
    def sanitize_ip(self, ip: str) -> str:
        """
        Sanitize and validate IP address.
        
        Returns the IP if valid, 'invalid' otherwise.
        """
        ip = self.sanitize_string(ip, self.MAX_LENGTHS['ip'], 'ip')
        
        # Basic validation (not strict - just format check)
        ipv4_pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
        ipv6_pattern = r'^([0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}$'
        
        if re.match(ipv4_pattern, ip) or re.match(ipv6_pattern, ip):
            return ip
        
        # Could be proxied - accept if alphanumeric with dots/colons
        if re.match(r'^[\w\.:,\s]+$', ip):
            return ip
        
        return 'invalid'
    
    def sanitize_url(self, url: str) -> str:
        """
        Sanitize URL/path.
        
        Preserves structure but removes dangerous content.
        """
        url = self.sanitize_string(url, self.MAX_LENGTHS['url'], 'url')
        
        # URL-decode common sequences for logging clarity
        url = url.replace('%2F', '/').replace('%3F', '?').replace('%3D', '=')
        
        return url
    
    def sanitize_headers(self, headers: Dict[str, str]) -> Dict[str, str]:
        """
        Sanitize HTTP headers.
        
        Removes sensitive headers and sanitizes values.
        """
        # Headers to remove entirely
        sensitive_headers = {
            'cookie', 'authorization', 'x-api-key', 'api-key',
            'x-auth-token', 'proxy-authorization'
        }
        
        sanitized = {}
        for key, value in headers.items():
            key_lower = key.lower()
            
            # Skip sensitive headers
            if key_lower in sensitive_headers:
                sanitized[key] = '[REDACTED]'
                continue
            
            # Sanitize key and value
            sanitized[self.sanitize_string(key, 100)] = self.sanitize_string(value, 500)
        
        return sanitized
    
    def sanitize_payload(self, payload: Any) -> str:
        """
        Sanitize request payload for logging.
        
        Handles various payload types (form data, JSON, raw).
        """
        if payload is None:
            return ''
        
        if isinstance(payload, dict):
            return self.sanitize_dict(payload)
        
        if isinstance(payload, (list, tuple)):
            return json.dumps([
                self.sanitize_string(str(item), 1000)
                for item in payload[:100]
            ])
        
        return self.sanitize_string(str(payload), self.MAX_LENGTHS['payload'])
    
    def sanitize_dict(self, data: Dict[str, Any], depth: int = 0) -> str:
        """
        Sanitize a dictionary and return as JSON string.
        
        Handles nested structures with depth limiting.
        """
        if depth > 5:  # Prevent deep recursion
            return '"[MAX_DEPTH]"'
        
        sanitized = {}
        
        for key, value in list(data.items())[:100]:  # Limit keys
            key = self.sanitize_string(str(key), 100)
            
            if isinstance(value, dict):
                sanitized[key] = json.loads(self.sanitize_dict(value, depth + 1))
            elif isinstance(value, (list, tuple)):
                sanitized[key] = [
                    self.sanitize_string(str(v), 500)
                    for v in value[:50]
                ]
            else:
                sanitized[key] = self.sanitize_string(str(value), 1000)
        
        try:
            return json.dumps(sanitized, ensure_ascii=True)
        except Exception:
            return '{}'
    
    def sanitize_attack_data(self, attacks: List[Dict[str, Any]]) -> str:
        """
        Sanitize detected attack data for logging.
        """
        sanitized = []
        
        for attack in attacks[:50]:  # Limit number of attacks
            sanitized.append({
                'type': self.sanitize_string(attack.get('type', ''), 50),
                'severity': self.sanitize_string(attack.get('severity', ''), 20),
                'confidence': min(float(attack.get('confidence', 0)), 1.0),
                'pattern': self.sanitize_string(attack.get('matched_pattern', ''), 200),
                'value': self.sanitize_string(attack.get('matched_value', ''), 200),
                'field': self.sanitize_string(attack.get('field', ''), 20)
            })
        
        return json.dumps(sanitized)


# Singleton instance
_sanitizer: Optional[LogSanitizer] = None


def get_sanitizer() -> LogSanitizer:
    """Get or create sanitizer singleton."""
    global _sanitizer
    if _sanitizer is None:
        _sanitizer = LogSanitizer()
    return _sanitizer
