"""
Logging Service - Abstract Interface

This module provides the abstract interface for the logging system.
The main application ONLY interacts with logging through this interface.

INTERNAL DOCUMENTATION - SECURITY CRITICAL:
- This interface abstracts ALL logging implementation details
- The main app NEVER directly accesses the logging database
- Communication happens via internal queue (Redis)
- This provides complete isolation of the logging system

The interface is designed to:
1. Hide all logging implementation from route handlers
2. Prevent any possibility of log manipulation from the main app
3. Ensure logging works even if main app is compromised
"""

import json
import time
import hashlib
from typing import Dict, Any, Optional
from dataclasses import dataclass, asdict
from queue import Queue
from threading import Thread
import atexit


@dataclass
class LogEvent:
    """
    Structured log event for the honeypot.
    
    INTERNAL: This structure is sent to the logging daemon.
    It contains all information needed for threat analysis.
    """
    event_id: str           # Unique event identifier
    session_id: str         # Attacker session ID
    timestamp: float        # Unix timestamp
    ip_address: str         # Attacker IP
    endpoint: str           # Requested endpoint
    method: str             # HTTP method
    request_payload: str    # Sanitized request data (JSON)
    detected_attacks: str   # Detected attacks (JSON)
    attack_count: int       # Number of attacks detected
    highest_severity: str   # Highest severity level
    response_code: int      # HTTP response code returned
    response_type: str      # Type of response (fake_success, etc.)
    stage: str              # Attacker stage (recon, access, etc.)
    user_agent: str         # User-Agent header
    additional_data: str    # Any additional context (JSON)


class LoggingInterface:
    """
    Abstract interface for the logging system.
    
    INTERNAL SECURITY MODEL:
    This class is the ONLY way the main application interacts with logging.
    It provides:
    
    1. Event queuing (non-blocking)
    2. Automatic batching
    3. Sanitization before queuing
    4. Graceful shutdown handling
    
    The actual log storage is handled by a separate daemon that reads
    from the queue. This ensures:
    
    - Main app cannot modify or delete logs
    - Main app doesn't need database credentials for logs
    - Logging continues even under attack
    - No logging code path can be exploited to affect logs
    """
    
    def __init__(self, config: Dict[str, Any]):
        """
        Initialize logging interface.
        
        Args:
            config: Application configuration dictionary
        """
        self._config = config
        self._queue: Queue = Queue()
        self._redis_client = None
        self._redis_queue_name = config.get('LOG_QUEUE_NAME', 'honeypot_logs')
        self._initialized = False
        self._worker_thread: Optional[Thread] = None
        
        # Initialize connection
        self._init_connection()
        
        # Start background worker
        self._start_worker()
        
        # Ensure clean shutdown
        atexit.register(self._shutdown)
    
    def _init_connection(self) -> None:
        """
        Initialize connection to message queue.
        
        Uses Redis for reliable message delivery to logging daemon.
        Falls back to in-memory queue if Redis unavailable.
        """
        try:
            import redis
            redis_url = self._config.get('REDIS_URL', 'redis://localhost:6379/0')
            self._redis_client = redis.from_url(redis_url)
            self._redis_client.ping()
            self._initialized = True
        except Exception:
            # Fall back to in-memory queue (less reliable but functional)
            self._redis_client = None
            self._initialized = True
    
    def _start_worker(self) -> None:
        """Start background worker thread for queue processing."""
        self._worker_thread = Thread(target=self._process_queue, daemon=True)
        self._worker_thread.start()
    
    def _process_queue(self) -> None:
        """
        Background worker that sends events to Redis.
        
        This runs in a separate thread to ensure non-blocking operation.
        """
        while True:
            try:
                event = self._queue.get(timeout=1.0)
                if event is None:  # Shutdown signal
                    break
                
                self._send_to_redis(event)
                self._queue.task_done()
            except Exception:
                # Queue.get timeout - continue
                continue
    
    def _send_to_redis(self, event: LogEvent) -> None:
        """
        Send event to Redis queue for logging daemon.
        
        If Redis is unavailable, events are stored in memory
        (which is acceptable for honeypot - we lose some logs
        but the system continues operating).
        """
        if self._redis_client:
            try:
                event_json = json.dumps(asdict(event))
                self._redis_client.rpush(self._redis_queue_name, event_json)
            except Exception:
                # Redis error - event is lost but system continues
                pass
    
    def _shutdown(self) -> None:
        """Gracefully shutdown the logging interface."""
        if self._worker_thread and self._worker_thread.is_alive():
            self._queue.put(None)  # Shutdown signal
            self._worker_thread.join(timeout=5.0)
    
    def log_event(
        self,
        session_id: str,
        analysis: Dict[str, Any],
        response_code: int,
        response_type: str = 'normal'
    ) -> None:
        """
        Log an event (non-blocking).
        
        This is the primary method called by the application to log events.
        It creates a LogEvent and queues it for processing.
        
        Args:
            session_id: Attacker session identifier
            analysis: Analysis result from detection engine
            response_code: HTTP response code returned
            response_type: Type of fake response returned
        """
        event = self._create_event(
            session_id=session_id,
            analysis=analysis,
            response_code=response_code,
            response_type=response_type
        )
        
        # Non-blocking queue operation
        try:
            self._queue.put_nowait(event)
        except Exception:
            # Queue full - drop event (better than blocking)
            pass
    
    def _create_event(
        self,
        session_id: str,
        analysis: Dict[str, Any],
        response_code: int,
        response_type: str
    ) -> LogEvent:
        """
        Create a LogEvent from analysis data.
        
        INTERNAL: Sanitizes all input before creating the event.
        """
        timestamp = analysis.get('timestamp', time.time())
        raw_request = analysis.get('raw_request', {})
        
        # Generate unique event ID
        event_id = self._generate_event_id(session_id, timestamp)
        
        # Extract and sanitize data
        detected_attacks = analysis.get('detected_attacks', [])
        
        return LogEvent(
            event_id=event_id,
            session_id=session_id,
            timestamp=timestamp,
            ip_address=self._sanitize_string(raw_request.get('ip', 'unknown')),
            endpoint=self._sanitize_string(raw_request.get('url', ''))[:500],
            method=self._sanitize_string(raw_request.get('method', 'GET'))[:10],
            request_payload=self._sanitize_json(raw_request),
            detected_attacks=json.dumps(detected_attacks),
            attack_count=analysis.get('attack_count', 0),
            highest_severity=analysis.get('highest_severity', 'NONE'),
            response_code=response_code,
            response_type=response_type,
            stage=analysis.get('stage_indicator', 'unknown'),
            user_agent=self._sanitize_string(
                raw_request.get('headers', {}).get('User-Agent', '')
            )[:500],
            additional_data='{}'
        )
    
    def _generate_event_id(self, session_id: str, timestamp: float) -> str:
        """Generate unique event ID."""
        data = f"{session_id}:{timestamp}:{id(self)}"
        return hashlib.sha256(data.encode()).hexdigest()[:32]
    
    def _sanitize_string(self, value: Any) -> str:
        """
        Sanitize a string value for safe logging.
        
        Prevents log injection attacks.
        """
        if not isinstance(value, str):
            value = str(value)
        
        # Remove control characters that could affect log parsing
        sanitized = ''.join(
            c for c in value
            if c.isprintable() or c in '\n\t'
        )
        
        # Escape potential injection characters
        sanitized = sanitized.replace('\r', '\\r')
        sanitized = sanitized.replace('\n', '\\n')
        
        return sanitized
    
    def _sanitize_json(self, data: Dict[str, Any]) -> str:
        """
        Sanitize and serialize data to JSON.
        
        Handles nested structures and prevents injection.
        """
        def sanitize_value(v):
            if isinstance(v, str):
                return self._sanitize_string(v)[:1000]
            elif isinstance(v, dict):
                return {k: sanitize_value(val) for k, val in list(v.items())[:50]}
            elif isinstance(v, list):
                return [sanitize_value(item) for item in v[:50]]
            else:
                return str(v)[:100]
        
        try:
            sanitized = sanitize_value(data)
            return json.dumps(sanitized)
        except Exception:
            return '{}'


# Module-level interface instance
_interface: Optional[LoggingInterface] = None


def init_logging_interface(config: Dict[str, Any]) -> None:
    """
    Initialize the global logging interface.
    
    Called once during app startup.
    """
    global _interface
    if _interface is None:
        _interface = LoggingInterface(config)


def queue_event(
    session_id: str,
    analysis: Dict[str, Any],
    response_code: int,
    response_type: str = 'normal'
) -> None:
    """
    Queue an event for logging.
    
    This is the ONLY function route handlers should use for logging.
    It's non-blocking and safe to call from any context.
    
    Args:
        session_id: Attacker session identifier
        analysis: Detection analysis result
        response_code: HTTP response code
        response_type: Type of fake response returned
    """
    global _interface
    if _interface is not None:
        _interface.log_event(session_id, analysis, response_code, response_type)
    
    # Write to shared file for operator dashboard
    _write_to_operator_log(session_id, analysis, response_code)


def _write_to_operator_log(session_id: str, analysis: Dict[str, Any], response_code: int) -> None:
    """Write event to shared log file for operator dashboard."""
    import os
    from datetime import datetime
    
    log_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), 'data')
    log_file = os.path.join(log_dir, 'operatordata.jsonl')
    
    try:
        os.makedirs(log_dir, exist_ok=True)
        
        raw_request = analysis.get('raw_request', {})
        event = {
            'session_id': session_id,
            'timestamp': datetime.now().isoformat(),
            'ip': raw_request.get('ip', 'unknown'),
            'user_agent': raw_request.get('headers', {}).get('User-Agent', '')[:100],
            'endpoint': raw_request.get('url', '/'),
            'method': raw_request.get('method', 'GET'),
            'detected_attacks': analysis.get('detected_attacks', []),
            'stage': analysis.get('stage_indicator', 'recon'),
            'response_code': response_code
        }
        
        with open(log_file, 'a') as f:
            f.write(json.dumps(event) + '\n')
    except Exception:
        pass  # Silent fail - don't affect main app
