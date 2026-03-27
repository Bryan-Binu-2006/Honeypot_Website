"""
Routes module initialization.
"""

from .public import public_bp
from .admin import admin_bp
from .api import api_bp
from .files import files_bp
from .internal import internal_bp

__all__ = [
    'public_bp',
    'admin_bp',
    'api_bp',
    'files_bp',
    'internal_bp'
]
