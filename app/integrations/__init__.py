"""
Integrations module initialization.
"""

from .base import (
    BaseIntegration,
    NormalizedEvent,
    EventNormalizer,
    SessionMatcher,
    IntegrationManager,
    get_integration_manager
)
from .cowrie import CowrieIntegration
from .wazuh import WazuhIntegration
from .opencanary import OpenCanaryIntegration

__all__ = [
    'BaseIntegration',
    'NormalizedEvent',
    'EventNormalizer',
    'SessionMatcher',
    'IntegrationManager',
    'get_integration_manager',
    'CowrieIntegration',
    'WazuhIntegration',
    'OpenCanaryIntegration'
]
