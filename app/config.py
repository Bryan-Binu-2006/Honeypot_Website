"""
Honeypot Web Application - Configuration Module

This module handles all configuration loading and environment variable management.
Configuration is loaded from environment variables with secure defaults.

INTERNAL DOCUMENTATION:
- Never expose configuration values in responses
- All secrets loaded from environment, never hardcoded
- Separate credentials for app vs logging service
"""

import os
from typing import Optional
from functools import lru_cache


def _env_bool(name: str, default: bool) -> bool:
    raw = os.environ.get(name)
    if raw is None:
        return default
    return str(raw).strip().lower() in {'1', 'true', 'yes', 'on'}


class Config:
    """
    Base configuration class with secure defaults.
    
    All sensitive values MUST come from environment variables.
    Default values are only for development and should never be used in production.
    """
    
    # Flask Core
    SECRET_KEY: str = os.environ.get('SECRET_KEY', 'dev-only-change-in-production')
    DEBUG: bool = False
    TESTING: bool = False
    
    # Session Configuration - Used for HMAC session generation
    SESSION_SECRET: str = os.environ.get('SESSION_SECRET', 'session-secret-change-me')
    SESSION_COOKIE_NAME: str = 'sid'
    SESSION_COOKIE_HTTPONLY: bool = True
    SESSION_COOKIE_SECURE: bool = _env_bool('SESSION_COOKIE_SECURE', True)
    SESSION_COOKIE_SAMESITE: str = 'Lax'

    # HTTPS / reverse proxy deployment controls
    FORCE_HTTPS: bool = _env_bool('FORCE_HTTPS', False)
    PREFERRED_URL_SCHEME: str = os.environ.get('PREFERRED_URL_SCHEME', 'https')
    PROXY_FIX_ENABLED: bool = _env_bool('PROXY_FIX_ENABLED', True)
    PROXY_FIX_X_FOR: int = int(os.environ.get('PROXY_FIX_X_FOR', '1'))
    PROXY_FIX_X_PROTO: int = int(os.environ.get('PROXY_FIX_X_PROTO', '1'))
    PROXY_FIX_X_HOST: int = int(os.environ.get('PROXY_FIX_X_HOST', '1'))
    PROXY_FIX_X_PORT: int = int(os.environ.get('PROXY_FIX_X_PORT', '1'))
    
    # Database - Main application (read-only access to necessary tables)
    # IMPORTANT: This should NOT have access to logging tables
    SQLALCHEMY_DATABASE_URI: str = os.environ.get(
        'DATABASE_URL', 
        'postgresql://honeypot_app:password@localhost:5432/honeypot'
    )
    SQLALCHEMY_TRACK_MODIFICATIONS: bool = False
    
    # Logging Database - Separate credentials with INSERT-only privileges
    # This is accessed ONLY by the logging service, never by main app
    LOG_DATABASE_URL: str = os.environ.get(
        'LOG_DATABASE_URL',
        'postgresql://honeypot_logger:password@localhost:5432/honeypot_logs'
    )
    
    # Redis - Internal queue for logging communication
    REDIS_URL: str = os.environ.get('REDIS_URL', 'redis://localhost:6379/0')
    LOG_QUEUE_NAME: str = os.environ.get('LOG_QUEUE_NAME', 'honeypot_logs')
    
    # Rate Limiting - Use memory storage by default (no Redis needed)
    RATELIMIT_DEFAULT: str = os.environ.get('RATE_LIMIT_DEFAULT', '100/minute')
    RATELIMIT_STORAGE_URL: str = os.environ.get('RATELIMIT_STORAGE_URL', 'memory://')
    
    # Server
    HOST: str = os.environ.get('HOST', '0.0.0.0')
    PORT: int = int(os.environ.get('PORT', 5000))
    
    # Security - List of trusted proxy IPs for X-Forwarded-For
    TRUSTED_PROXIES: list = os.environ.get('TRUSTED_PROXIES', '127.0.0.1').split(',')


class DevelopmentConfig(Config):
    """Development configuration - NEVER use in production."""
    DEBUG = True
    SESSION_COOKIE_SECURE = False  # Allow HTTP in dev
    FORCE_HTTPS = False


class ProductionConfig(Config):
    """Production configuration with strict security."""
    DEBUG = False
    TESTING = False
    SESSION_COOKIE_SECURE = True
    
    def __init__(self):
        # Warn about default keys but don't crash for local testing
        if self.SECRET_KEY == 'dev-only-change-in-production':
            import warnings
            warnings.warn("WARNING: Using default SECRET_KEY - change in production!")
        if self.SESSION_SECRET == 'session-secret-change-me':
            import warnings
            warnings.warn("WARNING: Using default SESSION_SECRET - change in production!")


class TestingConfig(Config):
    """Testing configuration."""
    TESTING = True
    DEBUG = True


@lru_cache()
def get_config() -> Config:
    """
    Get the appropriate configuration based on environment.
    
    Uses lru_cache to ensure configuration is only loaded once.
    """
    env = os.environ.get('FLASK_ENV', 'production')
    
    configs = {
        'development': DevelopmentConfig,
        'production': ProductionConfig,
        'testing': TestingConfig
    }
    
    config_class = configs.get(env, ProductionConfig)
    return config_class()
