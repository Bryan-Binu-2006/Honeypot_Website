"""
Attack Detection Engine - Pattern Definitions

This module defines 30+ attack patterns for detection.
Patterns use regex-based matching with normalized attack type labels.

INTERNAL DOCUMENTATION:
- Patterns are organized by attack category
- Each pattern has: name, regex, severity, description
- Patterns are matched against URL, headers, body, and params
- Multiple patterns can match a single request
"""

import re
from typing import Dict, List, NamedTuple
from enum import Enum


class Severity(Enum):
    """Attack severity levels - ordered for comparison."""
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4
    
    def __lt__(self, other):
        if self.__class__ is other.__class__:
            return self.value < other.value
        return NotImplemented
    
    def __le__(self, other):
        if self.__class__ is other.__class__:
            return self.value <= other.value
        return NotImplemented
    
    def __gt__(self, other):
        if self.__class__ is other.__class__:
            return self.value > other.value
        return NotImplemented
    
    def __ge__(self, other):
        if self.__class__ is other.__class__:
            return self.value >= other.value
        return NotImplemented


class AttackPattern(NamedTuple):
    """Definition of an attack pattern."""
    name: str
    patterns: List[str]  # Regex patterns
    severity: Severity
    description: str
    check_fields: List[str]  # Which request fields to check


# =============================================================================
# SQL INJECTION PATTERNS
# =============================================================================

SQLI_PATTERNS = [
    AttackPattern(
        name='sqli_classic',
        patterns=[
            r"('|\"|;|\s)(or|and)\s+[\d\w]+=[\d\w]+",  # ' OR 1=1
            r"union\s+(all\s+)?select",  # UNION SELECT
            r"select\s+.+\s+from\s+",  # SELECT ... FROM
            r"insert\s+into\s+\w+",  # INSERT INTO
            r"delete\s+from\s+\w+",  # DELETE FROM
            r"update\s+\w+\s+set",  # UPDATE ... SET
            r"drop\s+(table|database)",  # DROP TABLE
            r"--\s*$",  # SQL comment
            r"/\*.*\*/",  # Block comment
            r";\s*(select|insert|update|delete|drop)",  # Stacked queries
        ],
        severity=Severity.HIGH,
        description='Classic SQL injection attempt',
        check_fields=['params', 'body', 'url']
    ),
    AttackPattern(
        name='sqli_blind',
        patterns=[
            r"sleep\s*\(\s*\d+\s*\)",  # Time-based: sleep(5)
            r"benchmark\s*\(",  # MySQL benchmark
            r"pg_sleep\s*\(",  # PostgreSQL sleep
            r"waitfor\s+delay",  # MSSQL delay
            r"if\s*\(.+\)\s*select",  # Conditional SELECT
            r"case\s+when\s+.+\s+then",  # CASE WHEN
            r"(\d+\s*=\s*\d+|\w+\s*=\s*\w+)\s+and\s+",  # Boolean-based
            r"order\s+by\s+\d{2,}",  # Column enumeration
            r"having\s+\d+\s*=\s*\d+",  # HAVING clause injection
        ],
        severity=Severity.HIGH,
        description='Blind SQL injection attempt (time/boolean-based)',
        check_fields=['params', 'body']
    ),
]

# =============================================================================
# NOSQL INJECTION PATTERNS
# =============================================================================

NOSQL_PATTERNS = [
    AttackPattern(
        name='nosql_injection',
        patterns=[
            r'\$ne|\$gt|\$lt|\$gte|\$lte|\$in|\$nin|\$or|\$and|\$not|\$nor',  # MongoDB operators
            r'\{\s*"\$',  # JSON with MongoDB operator
            r"'\s*\}\s*,\s*'\$",  # Injection breaking syntax
            r'\$where\s*:',  # $where injection
            r'\$regex\s*:',  # Regex injection
            r'\.find\s*\(',  # Method injection
            r'\.aggregate\s*\(',  # Aggregation injection
            r'{\s*password\s*:\s*{\s*\$',  # Auth bypass pattern
        ],
        severity=Severity.HIGH,
        description='NoSQL injection attempt',
        check_fields=['params', 'body']
    ),
]

# =============================================================================
# COMMAND INJECTION PATTERNS
# =============================================================================

COMMAND_INJECTION_PATTERNS = [
    AttackPattern(
        name='command_injection',
        patterns=[
            r';\s*(ls|cat|id|whoami|uname|pwd|wget|curl|nc|bash|sh|python|perl|ruby)',
            r'\|\s*(ls|cat|id|whoami|uname|pwd|wget|curl|nc|bash|sh)',  # Pipe
            r'`[^`]+`',  # Backticks
            r'\$\([^)]+\)',  # $() subshell
            r'&&\s*(ls|cat|id|whoami|uname)',  # AND operator
            r'\|\|\s*(ls|cat|id|whoami)',  # OR operator
            r'/bin/(bash|sh|cat|ls|nc)',  # Direct bin paths
            r'/etc/passwd',  # passwd file access
            r'/etc/shadow',  # shadow file access
            r'>\s*/dev/',  # Output redirection to /dev
            r'2>&1',  # stderr redirect
            r'\bnc\s+-[elp]',  # netcat reverse shell
            r'bash\s+-[ic]',  # bash interactive
            r'python\s+-c\s*["\']',  # python one-liner
            r'perl\s+-e\s*["\']',  # perl one-liner
        ],
        severity=Severity.CRITICAL,
        description='Command injection attempt',
        check_fields=['params', 'body', 'url']
    ),
]

# =============================================================================
# LDAP/XPATH INJECTION PATTERNS
# =============================================================================

LDAP_XPATH_PATTERNS = [
    AttackPattern(
        name='ldap_injection',
        patterns=[
            r'\)\s*\(\s*[\w&|!=<>]',  # LDAP filter injection
            r'\*\)\s*\(',  # Wildcard filter
            r'\)\s*\(\s*\|',  # OR injection
            r'\)\s*\(\s*&',  # AND injection
            r'admin\s*\)\s*\(\s*\|',  # Admin bypass
            r'\x00|\x0a|\x0d',  # Null byte / newlines
        ],
        severity=Severity.HIGH,
        description='LDAP injection attempt',
        check_fields=['params', 'body']
    ),
    AttackPattern(
        name='xpath_injection',
        patterns=[
            r"'\s*or\s+'[^']*'\s*=\s*'",  # XPath OR
            r"'\s*]\s*/\s*\*",  # XPath traversal
            r'\[\s*@\w+\s*=\s*',  # Attribute selection
            r'count\s*\(',  # XPath function
            r'substring\s*\(',  # XPath substring
            r'contains\s*\(',  # XPath contains
        ],
        severity=Severity.HIGH,
        description='XPath injection attempt',
        check_fields=['params', 'body']
    ),
]

# =============================================================================
# XSS PATTERNS
# =============================================================================

XSS_PATTERNS = [
    AttackPattern(
        name='xss_reflected',
        patterns=[
            r'<\s*script[^>]*>',  # Script tag
            r'javascript\s*:',  # javascript: URI
            r'on\w+\s*=',  # Event handlers (onclick, onerror, etc.)
            r'<\s*img[^>]+onerror',  # img onerror
            r'<\s*svg[^>]+onload',  # svg onload
            r'<\s*iframe',  # iframe
            r'<\s*embed',  # embed
            r'<\s*object',  # object
            r'expression\s*\(',  # CSS expression
            r'url\s*\(\s*["\']?javascript',  # CSS url()
            r'document\.(cookie|location|write)',  # DOM access
            r'window\.(location|open)',  # Window manipulation
            r'eval\s*\(',  # eval
            r'atob\s*\(|btoa\s*\(',  # Base64 encoding
            r'String\.fromCharCode',  # Character code obfuscation
        ],
        severity=Severity.MEDIUM,
        description='Cross-site scripting (XSS) attempt',
        check_fields=['params', 'body', 'url', 'headers']
    ),
    AttackPattern(
        name='xss_dom',
        patterns=[
            r'location\.(hash|search|href)',  # DOM sources
            r'document\.(referrer|URL|documentURI)',  # Document sources
            r'innerHTML\s*=',  # innerHTML sink
            r'outerHTML\s*=',  # outerHTML sink
            r'document\.write\s*\(',  # document.write sink
            r'\$\s*\(\s*["\'][^"\']+["\']',  # jQuery selector
        ],
        severity=Severity.MEDIUM,
        description='DOM-based XSS attempt',
        check_fields=['params', 'url']
    ),
]

# =============================================================================
# TEMPLATE INJECTION PATTERNS
# =============================================================================

TEMPLATE_INJECTION_PATTERNS = [
    AttackPattern(
        name='ssti_jinja2',
        patterns=[
            r'\{\{\s*[^}]+\}\}',  # {{ expression }}
            r'\{%\s*[^%]+%\}',  # {% statement %}
            r'\{\{\s*config\s*\}\}',  # config access
            r"\{\{\s*['\"][^'\"]+['\"]\.__class__",  # Class access
            r'__mro__|__subclasses__|__globals__|__builtins__',  # Magic attrs
            r'lipsum\.__globals__',  # Jinja2 lipsum exploit
            r"request\.(environ|application)",  # Flask request access
        ],
        severity=Severity.CRITICAL,
        description='Server-side template injection (Jinja2)',
        check_fields=['params', 'body']
    ),
    AttackPattern(
        name='ssti_generic',
        patterns=[
            r'\$\{\s*[^}]+\}',  # ${expression}
            r'#\{\s*[^}]+\}',  # #{expression}
            r'@\{\s*[^}]+\}',  # @{expression}
            r'\*\{\s*[^}]+\}',  # *{expression}
            r'<%[^%]+%>',  # <% expression %>
        ],
        severity=Severity.HIGH,
        description='Server-side template injection attempt',
        check_fields=['params', 'body']
    ),
]

# =============================================================================
# LFI/RFI PATTERNS
# =============================================================================

LFI_RFI_PATTERNS = [
    AttackPattern(
        name='lfi',
        patterns=[
            r'\.\./|\.\.\%2[fF]',  # Directory traversal
            r'/etc/(passwd|shadow|hosts|group)',  # Linux system files
            r'/proc/(self|version|cmdline)',  # proc filesystem
            r'/var/log/',  # Log files
            r'c:\\windows\\',  # Windows paths
            r'file:///',  # file:// protocol
            r'php://(input|filter|data)',  # PHP wrappers
            r'expect://',  # expect wrapper
            r'zip://',  # zip wrapper
            r'data://text/plain',  # data wrapper
            r'\.htaccess|\.htpasswd',  # Apache configs
            r'web\.config',  # IIS config
        ],
        severity=Severity.HIGH,
        description='Local file inclusion attempt',
        check_fields=['params', 'url']
    ),
    AttackPattern(
        name='rfi',
        patterns=[
            r'https?://[^\s]+\.(php|txt|inc)',  # Remote PHP include
            r'//[^\s]+\.(php|txt)',  # Protocol-relative
            r'ftp://[^\s]+',  # FTP inclusion
            r'gopher://[^\s]+',  # Gopher protocol
        ],
        severity=Severity.CRITICAL,
        description='Remote file inclusion attempt',
        check_fields=['params', 'body']
    ),
]

# =============================================================================
# FILE UPLOAD BYPASS PATTERNS
# =============================================================================

FILE_UPLOAD_PATTERNS = [
    AttackPattern(
        name='file_upload_bypass',
        patterns=[
            r'\.php\.(jpg|png|gif)',  # Double extension
            r'\.asp\.(jpg|png)',  # ASP double extension
            r'\.jsp\.(jpg|png)',  # JSP double extension
            r'%00\.(jpg|png)',  # Null byte injection
            r'\.phtml|\.phar',  # Alternative PHP extensions
            r'Content-Type:\s*image/[^;]+;.*\.php',  # MIME spoofing
        ],
        severity=Severity.HIGH,
        description='File upload bypass attempt',
        check_fields=['body', 'headers']
    ),
]

# =============================================================================
# IDOR PATTERNS
# =============================================================================

IDOR_PATTERNS = [
    AttackPattern(
        name='idor',
        patterns=[
            r'user_?id\s*=\s*[\d]+',  # user_id parameter
            r'account_?id\s*=\s*[\d]+',  # account_id
            r'doc_?id\s*=\s*[\d]+',  # doc_id
            r'file_?id\s*=\s*[\d]+',  # file_id
            r'/users?/[\d]+',  # /user/123
            r'/accounts?/[\d]+',  # /account/123
            r'/files?/[\d]+',  # /file/123
            r'/documents?/[\d]+',  # /document/123
        ],
        severity=Severity.MEDIUM,
        description='Potential IDOR attempt',
        check_fields=['params', 'url']
    ),
]

# =============================================================================
# JWT TAMPERING PATTERNS
# =============================================================================

JWT_PATTERNS = [
    AttackPattern(
        name='jwt_tampering',
        patterns=[
            r'"alg"\s*:\s*"[Nn]one"',  # alg:none attack
            r'"alg"\s*:\s*"[Hh][Ss]',  # Algorithm confusion
            r'eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.',  # JWT pattern
            r'"kid"\s*:\s*"(\.\./|/)',  # kid path traversal
            r'"jku"\s*:\s*"https?://',  # JKU injection
            r'"x5u"\s*:\s*"https?://',  # x5u injection
        ],
        severity=Severity.HIGH,
        description='JWT tampering attempt',
        check_fields=['headers', 'body', 'params']
    ),
]

# =============================================================================
# SESSION ATTACK PATTERNS
# =============================================================================

SESSION_PATTERNS = [
    AttackPattern(
        name='session_fixation',
        patterns=[
            r'[?&;]session_?id\s*=',  # Session ID in URL
            r'[?&;]sess\s*=',  # sess parameter
            r'[?&;]PHPSESSID\s*=',  # PHP session
            r'[?&;]JSESSIONID\s*=',  # Java session
            r'[?&;]ASP\.NET_SessionId\s*=',  # ASP.NET session
        ],
        severity=Severity.MEDIUM,
        description='Session fixation attempt',
        check_fields=['url', 'params']
    ),
]

# =============================================================================
# SSRF PATTERNS
# =============================================================================

SSRF_PATTERNS = [
    AttackPattern(
        name='ssrf',
        patterns=[
            r'169\.254\.169\.254',  # AWS metadata
            r'metadata\.google\.internal',  # GCP metadata
            r'100\.100\.100\.200',  # Alibaba metadata
            r'127\.0\.0\.1|localhost',  # Local access
            r'0\.0\.0\.0',  # All interfaces
            r'::1',  # IPv6 localhost
            r'10\.\d+\.\d+\.\d+',  # Private IP
            r'172\.(1[6-9]|2[0-9]|3[0-1])\.',  # Private IP
            r'192\.168\.',  # Private IP
            r'file:///',  # File protocol
            r'gopher://',  # Gopher protocol
            r'dict://',  # Dict protocol
        ],
        severity=Severity.CRITICAL,
        description='Server-side request forgery attempt',
        check_fields=['params', 'body', 'url']
    ),
]

# =============================================================================
# XXE PATTERNS
# =============================================================================

XXE_PATTERNS = [
    AttackPattern(
        name='xxe',
        patterns=[
            r'<!DOCTYPE[^>]+SYSTEM',  # DOCTYPE with SYSTEM
            r'<!ENTITY[^>]+SYSTEM',  # External entity
            r'<!ENTITY[^>]+PUBLIC',  # Public entity
            r'ENTITY[^>]+file://',  # File entity
            r'ENTITY[^>]+https?://',  # Remote entity
            r'ENTITY[^>]+php://',  # PHP wrapper entity
            r'ENTITY[^>]+expect://',  # Expect wrapper
            r'<!ENTITY\s+%\s+\w+',  # Parameter entity
        ],
        severity=Severity.CRITICAL,
        description='XML external entity (XXE) attack',
        check_fields=['body']
    ),
]

# =============================================================================
# DESERIALIZATION PATTERNS
# =============================================================================

DESERIALIZATION_PATTERNS = [
    AttackPattern(
        name='deserialization',
        patterns=[
            r'O:\d+:"[^"]+":\d+:',  # PHP serialized object
            r'rO0ABX',  # Java serialized (base64)
            r'aced0005',  # Java serialized (hex)
            r'{"@type"\s*:',  # Fastjson
            r'_class\s*:\s*["\']',  # Python pickle marker
            r'__reduce__',  # Python pickle
            r'yaml\.load\s*\(',  # YAML unsafe load
            r'!!python/object',  # PyYAML object
        ],
        severity=Severity.CRITICAL,
        description='Deserialization attack attempt',
        check_fields=['body', 'params']
    ),
]

# =============================================================================
# PROTOTYPE POLLUTION PATTERNS
# =============================================================================

PROTOTYPE_POLLUTION_PATTERNS = [
    AttackPattern(
        name='prototype_pollution',
        patterns=[
            r'__proto__',  # Direct proto access
            r'constructor\[.?prototype',  # Constructor prototype
            r'prototype\[',  # Prototype bracket
            r'Object\.prototype',  # Object.prototype
            r'\["__proto__"\]',  # Bracket notation
            r'\.prototype\.constructor',  # Prototype chain
        ],
        severity=Severity.HIGH,
        description='Prototype pollution attempt',
        check_fields=['body', 'params']
    ),
]

# =============================================================================
# GRAPHQL ABUSE PATTERNS
# =============================================================================

GRAPHQL_PATTERNS = [
    AttackPattern(
        name='graphql_introspection',
        patterns=[
            r'__schema\s*\{',  # Schema introspection
            r'__type\s*\{',  # Type introspection
            r'__typename',  # Typename query
            r'query\s+IntrospectionQuery',  # Named introspection
        ],
        severity=Severity.LOW,
        description='GraphQL introspection attempt',
        check_fields=['body']
    ),
    AttackPattern(
        name='graphql_dos',
        patterns=[
            r'(\{\s*\w+\s*\{){5,}',  # Deeply nested query
            r'fragment\s+\w+\s+on\s+\w+\s*\{[^}]+\.\.\.\w+',  # Circular fragment
        ],
        severity=Severity.MEDIUM,
        description='GraphQL DoS attempt',
        check_fields=['body']
    ),
]

# =============================================================================
# DIRECTORY/API FUZZING PATTERNS
# =============================================================================

FUZZING_PATTERNS = [
    AttackPattern(
        name='directory_fuzzing',
        patterns=[
            r'/\.(git|svn|env|htaccess|htpasswd|DS_Store)',  # Hidden files
            r'/(backup|bak|old|copy|tmp|temp)/',  # Backup directories
            r'/wp-(admin|content|includes)',  # WordPress
            r'/(phpmyadmin|pma|mysql|db)',  # Database tools
            r'/(admin|administrator|manager|console)',  # Admin panels
            r'/\.(php|asp|jsp|cgi)$',  # Script extensions
        ],
        severity=Severity.LOW,
        description='Directory fuzzing detected',
        check_fields=['url']
    ),
    AttackPattern(
        name='api_fuzzing',
        patterns=[
            r'/api/v\d+/(users|admin|config|debug)',  # API endpoints
            r'/api/(internal|private|hidden)',  # Internal APIs
            r'/api/.+\?.*FUZZ',  # FUZZ parameter
            r'/(swagger|api-docs|openapi)',  # API documentation
        ],
        severity=Severity.LOW,
        description='API fuzzing detected',
        check_fields=['url']
    ),
]

# =============================================================================
# HEADER MANIPULATION PATTERNS
# =============================================================================

HEADER_MANIPULATION_PATTERNS = [
    AttackPattern(
        name='header_injection',
        patterns=[
            r'X-Forwarded-For:\s*127\.0\.0\.1',  # IP spoofing
            r'X-Forwarded-Host:\s*.+',  # Host header injection
            r'X-Original-URL:',  # URL override
            r'X-Rewrite-URL:',  # Rewrite override
            r'X-Custom-IP-Authorization:',  # Custom header bypass
        ],
        severity=Severity.MEDIUM,
        description='Header manipulation attempt',
        check_fields=['headers']
    ),
]

# =============================================================================
# RECON PATTERNS
# =============================================================================

RECON_PATTERNS = [
    AttackPattern(
        name='recon_robots',
        patterns=[
            r'^/robots\.txt$',  # robots.txt access
            r'^/sitemap\.xml$',  # sitemap access
            r'^/\.well-known/',  # well-known paths
        ],
        severity=Severity.LOW,
        description='Reconnaissance: robots.txt/sitemap access',
        check_fields=['url']
    ),
    AttackPattern(
        name='endpoint_scanning',
        patterns=[
            r'^/[a-z]{3,10}$',  # Short path probing
            r'^/[a-z]+\d+$',  # Path with numbers
        ],
        severity=Severity.LOW,
        description='Endpoint scanning behavior',
        check_fields=['url']
    ),
]

# =============================================================================
# RATE-BASED SCANNING (checked differently - by request frequency)
# =============================================================================

RATE_BASED_PATTERNS = [
    AttackPattern(
        name='rate_scanning',
        patterns=[],  # No regex - checked by rate
        severity=Severity.MEDIUM,
        description='High-rate scanning behavior detected',
        check_fields=[]  # Special handling
    ),
]

# =============================================================================
# PAYLOAD MUTATION PATTERNS
# =============================================================================

PAYLOAD_MUTATION_PATTERNS = [
    AttackPattern(
        name='encoding_evasion',
        patterns=[
            r'%25[0-9a-fA-F]{2}',  # Double URL encoding
            r'%u[0-9a-fA-F]{4}',  # Unicode encoding
            r'\\x[0-9a-fA-F]{2}',  # Hex encoding
            r'&#x?[0-9a-fA-F]+;',  # HTML entities
            r'\\u[0-9a-fA-F]{4}',  # Unicode escape
        ],
        severity=Severity.MEDIUM,
        description='Encoding-based evasion attempt',
        check_fields=['params', 'body', 'url']
    ),
    AttackPattern(
        name='case_mutation',
        patterns=[
            r'SeLeCt|sElEcT|SELECT',  # Mixed case SQL
            r'ScRiPt|sCrIpT',  # Mixed case XSS
            r'UnIoN|uNiOn',  # Mixed case UNION
        ],
        severity=Severity.LOW,
        description='Case mutation evasion attempt',
        check_fields=['params', 'body']
    ),
]


# =============================================================================
# ALL PATTERNS AGGREGATED
# =============================================================================

ALL_PATTERNS = (
    SQLI_PATTERNS +
    NOSQL_PATTERNS +
    COMMAND_INJECTION_PATTERNS +
    LDAP_XPATH_PATTERNS +
    XSS_PATTERNS +
    TEMPLATE_INJECTION_PATTERNS +
    LFI_RFI_PATTERNS +
    FILE_UPLOAD_PATTERNS +
    IDOR_PATTERNS +
    JWT_PATTERNS +
    SESSION_PATTERNS +
    SSRF_PATTERNS +
    XXE_PATTERNS +
    DESERIALIZATION_PATTERNS +
    PROTOTYPE_POLLUTION_PATTERNS +
    GRAPHQL_PATTERNS +
    FUZZING_PATTERNS +
    HEADER_MANIPULATION_PATTERNS +
    RECON_PATTERNS +
    PAYLOAD_MUTATION_PATTERNS
)


def get_all_patterns() -> List[AttackPattern]:
    """Return all defined attack patterns."""
    return ALL_PATTERNS


def get_patterns_by_category(category: str) -> List[AttackPattern]:
    """
    Get patterns by category name.
    
    Categories: sqli, nosql, command, xss, lfi, ssrf, etc.
    """
    category_map = {
        'sqli': SQLI_PATTERNS,
        'nosql': NOSQL_PATTERNS,
        'command': COMMAND_INJECTION_PATTERNS,
        'ldap': LDAP_XPATH_PATTERNS,
        'xss': XSS_PATTERNS,
        'template': TEMPLATE_INJECTION_PATTERNS,
        'lfi': LFI_RFI_PATTERNS,
        'upload': FILE_UPLOAD_PATTERNS,
        'idor': IDOR_PATTERNS,
        'jwt': JWT_PATTERNS,
        'session': SESSION_PATTERNS,
        'ssrf': SSRF_PATTERNS,
        'xxe': XXE_PATTERNS,
        'deserialization': DESERIALIZATION_PATTERNS,
        'prototype': PROTOTYPE_POLLUTION_PATTERNS,
        'graphql': GRAPHQL_PATTERNS,
        'fuzzing': FUZZING_PATTERNS,
        'headers': HEADER_MANIPULATION_PATTERNS,
        'recon': RECON_PATTERNS,
        'mutation': PAYLOAD_MUTATION_PATTERNS,
    }
    return category_map.get(category, [])
