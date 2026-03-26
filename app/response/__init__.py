"""
Response module initialization.
"""

from .engine import ResponseEngine, ProgressionManager, get_response_engine, get_progression_manager
from .templates import (
    ResponseTemplate,
    get_response_for_attack,
    get_progressive_response
)

__all__ = [
    'ResponseEngine',
    'ProgressionManager',
    'get_response_engine',
    'get_progression_manager',
    'ResponseTemplate',
    'get_response_for_attack',
    'get_progressive_response'
]
