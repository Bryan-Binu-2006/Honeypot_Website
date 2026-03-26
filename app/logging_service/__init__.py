"""
Logging Service module initialization.

INTERNAL DOCUMENTATION:
This module provides the logging interface used by the main application.
The actual logging daemon runs as a separate process.
"""

from .interface import (
    LoggingInterface,
    LogEvent,
    init_logging_interface,
    queue_event
)
from .sanitizer import LogSanitizer, get_sanitizer

__all__ = [
    'LoggingInterface',
    'LogEvent',
    'init_logging_interface',
    'queue_event',
    'LogSanitizer',
    'get_sanitizer'
]
