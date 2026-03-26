"""
Middleware - Security Headers and Response Hardening

Applies security headers and ensures responses don't leak internal information.

INTERNAL DOCUMENTATION:
- Adds standard security headers to all responses
- Removes any headers that might reveal internal structure
- Adds deception headers to appear like a normal application
"""

from flask import Response, request
from typing import Dict, Any


class SecurityMiddleware:
    """
    Applies security measures to all responses.
    
    INTERNAL: This middleware ensures that:
    1. Standard security headers are applied
    2. No internal information leaks through headers
    3. Responses appear to come from a normal web application
    
    The headers are designed to look like a typical production
    application, not a honeypot.
    """
    
    # Headers to add to all responses
    SECURITY_HEADERS = {
        'X-Content-Type-Options': 'nosniff',
        'X-Frame-Options': 'SAMEORIGIN',
        'X-XSS-Protection': '1; mode=block',
        'Referrer-Policy': 'strict-origin-when-cross-origin',
        'Permissions-Policy': 'geolocation=(), microphone=(), camera=()',
    }
    
    # Headers to remove (might reveal internal info)
    HEADERS_TO_REMOVE = [
        'X-Powered-By',
        'Server',
        'X-AspNet-Version',
        'X-AspNetMvc-Version',
    ]
    
    # Deception headers (make it look like a real app)
    DECEPTION_HEADERS = {
        'Server': 'nginx/1.18.0 (Ubuntu)',
        'X-Powered-By': 'PHP/7.4.3',  # Misleading
    }
    
    def __init__(self):
        """Initialize security middleware."""
        pass
    
    def apply_headers(self, response: Response) -> Response:
        """
        Apply security headers to response.
        
        Args:
            response: Flask response object
            
        Returns:
            Response with security headers applied
        """
        # Remove potentially revealing headers
        for header in self.HEADERS_TO_REMOVE:
            if header in response.headers:
                del response.headers[header]
        
        # Add security headers
        for header, value in self.SECURITY_HEADERS.items():
            response.headers[header] = value
        
        # Add deception headers
        for header, value in self.DECEPTION_HEADERS.items():
            response.headers[header] = value
        
        # Add CSP for non-API responses
        if not request.path.startswith('/api/'):
            response.headers['Content-Security-Policy'] = (
                "default-src 'self'; "
                "script-src 'self' 'unsafe-inline' 'unsafe-eval'; "
                "style-src 'self' 'unsafe-inline'; "
                "img-src 'self' data:; "
                "font-src 'self'; "
                "connect-src 'self'"
            )
        
        return response
    
    def apply_cache_headers(
        self,
        response: Response,
        cache_type: str = 'no-store'
    ) -> Response:
        """
        Apply cache control headers.
        
        Args:
            response: Flask response
            cache_type: Type of caching ('no-store', 'private', 'public')
            
        Returns:
            Response with cache headers
        """
        if cache_type == 'no-store':
            response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate'
            response.headers['Pragma'] = 'no-cache'
            response.headers['Expires'] = '0'
        elif cache_type == 'private':
            response.headers['Cache-Control'] = 'private, max-age=300'
        elif cache_type == 'public':
            response.headers['Cache-Control'] = 'public, max-age=3600'
        
        return response


class InputValidator:
    """
    Validates and sanitizes input data.
    
    INTERNAL: Ensures the application doesn't have real vulnerabilities
    while still detecting attack attempts.
    """
    
    # Maximum input lengths
    MAX_LENGTHS = {
        'username': 100,
        'password': 200,
        'email': 254,
        'query': 500,
        'path': 500,
        'body': 50000,
    }
    
    def validate_length(self, value: str, field: str) -> bool:
        """
        Check if input length is within limits.
        
        Returns True if valid, False if too long.
        """
        max_len = self.MAX_LENGTHS.get(field, 1000)
        return len(value) <= max_len
    
    def sanitize_for_response(self, value: str) -> str:
        """
        Sanitize a value that will be included in responses.
        
        Prevents actual XSS while allowing us to detect XSS attempts.
        """
        # HTML-encode dangerous characters
        value = value.replace('&', '&amp;')
        value = value.replace('<', '&lt;')
        value = value.replace('>', '&gt;')
        value = value.replace('"', '&quot;')
        value = value.replace("'", '&#x27;')
        
        return value
