"""
Integrations module initialization.
"""

from dataclasses import asdict
from typing import Any, Dict, Optional

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


_defaults_registered = False


def _ensure_default_integrations() -> IntegrationManager:
    """Register built-in integrations once and return manager."""
    global _defaults_registered
    manager = get_integration_manager()
    if not _defaults_registered:
        manager.register(CowrieIntegration())
        manager.register(WazuhIntegration())
        manager.register(OpenCanaryIntegration())
        _defaults_registered = True
    return manager


def ingest_event(source: str, data: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """
    Unified ingestion interface for external integration events.

    This function normalizes incoming events, correlates them to sessions via
    IP + timestamp matching, and attaches them to attack-chain timeline data.
    """
    manager = _ensure_default_integrations()
    normalized = manager.process_event(source, data)
    if not normalized:
        return None

    attached_session = normalized.session_id
    try:
        from ..behavior.attack_chain_engine import get_attack_chain_engine

        chain_engine = get_attack_chain_engine()
        matched = chain_engine.ingest_external_event(
            source=source,
            event_data={
                'timestamp': normalized.timestamp,
                'source_ip': normalized.source_ip,
                'event_type': normalized.event_type,
                'description': normalized.description,
                'endpoint': normalized.destination_port,
            },
            session_id=normalized.session_id,
        )
        if matched:
            attached_session = matched
    except Exception:
        pass

    payload = asdict(normalized)
    payload['matched_session_id'] = attached_session
    return payload

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
    , 'ingest_event'
]
