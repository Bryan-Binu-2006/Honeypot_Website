"""
Logging Daemon - Standalone Logging Service

This is a SEPARATE service that handles all log storage.
It runs independently of the main application.

INTERNAL DOCUMENTATION - SECURITY CRITICAL:
- This daemon is the ONLY component that writes to the log database
- It reads from Redis queue and writes to PostgreSQL
- Uses separate credentials with INSERT-only privileges
- Implements append-only logging (no updates, no deletes)
- Designed to survive even if main app is compromised
"""

import os
import sys
import json
import time
import signal
import logging
from typing import Dict, Any, Optional
from datetime import datetime
from queue import Queue
from threading import Thread, Event
import atexit

# Database drivers - imported with fallbacks
try:
    import psycopg2
    from psycopg2.extras import execute_values
    HAS_POSTGRES = True
except ImportError:
    HAS_POSTGRES = False
    psycopg2 = None

try:
    import redis
    HAS_REDIS = True
except ImportError:
    HAS_REDIS = False
    redis = None


# Configure service logging (separate from honeypot logs)
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler('logging_daemon.log', mode='a')
    ]
)
logger = logging.getLogger('logging_daemon')


class LoggingDaemon:
    """
    Standalone logging service for the honeypot.
    
    INTERNAL SECURITY MODEL:
    This daemon is completely separate from the main application.
    It has its own database credentials with ONLY INSERT privileges.
    It cannot:
    - Delete logs
    - Update logs
    - Read back logs
    - Access the main application database
    
    This ensures log integrity even if the main app is compromised.
    """
    
    def __init__(self, config: Dict[str, Any]):
        """
        Initialize logging daemon.
        
        Args:
            config: Configuration dictionary containing:
                - LOG_DATABASE_URL: PostgreSQL connection string
                - REDIS_URL: Redis connection string
                - LOG_QUEUE_NAME: Name of the Redis queue
                - LOG_BATCH_SIZE: Number of events to batch before writing
                - LOG_FLUSH_INTERVAL: Seconds between forced flushes
        """
        self.config = config
        self._running = False
        self._shutdown_event = Event()
        
        # Batch buffer
        self._buffer: list = []
        self._batch_size = config.get('LOG_BATCH_SIZE', 100)
        self._flush_interval = config.get('LOG_FLUSH_INTERVAL', 5)
        self._last_flush = time.time()
        
        # Connections
        self._redis_client = None
        self._pg_connection = None
        self._queue_name = config.get('LOG_QUEUE_NAME', 'honeypot_logs')
        
        # Initialize connections
        self._init_connections()
        
        # Ensure clean shutdown
        signal.signal(signal.SIGTERM, self._signal_handler)
        signal.signal(signal.SIGINT, self._signal_handler)
        atexit.register(self._cleanup)
    
    def _init_connections(self) -> None:
        """Initialize database connections."""
        # Redis connection
        if HAS_REDIS:
            try:
                redis_url = self.config.get('REDIS_URL', 'redis://localhost:6379/0')
                self._redis_client = redis.from_url(redis_url)
                self._redis_client.ping()
                logger.info("Connected to Redis")
            except Exception as e:
                logger.error(f"Failed to connect to Redis: {e}")
                self._redis_client = None
        else:
            logger.warning("Redis not available - using fallback mode")
        
        # PostgreSQL connection
        if HAS_POSTGRES:
            try:
                db_url = self.config.get('LOG_DATABASE_URL')
                if db_url:
                    self._pg_connection = psycopg2.connect(db_url)
                    self._pg_connection.autocommit = False
                    self._ensure_tables()
                    logger.info("Connected to PostgreSQL")
                else:
                    logger.warning("No LOG_DATABASE_URL configured")
            except Exception as e:
                logger.error(f"Failed to connect to PostgreSQL: {e}")
                self._pg_connection = None
        else:
            logger.warning("PostgreSQL driver not available")
    
    def _ensure_tables(self) -> None:
        """
        Create log tables if they don't exist.
        
        IMPORTANT: The log table is append-only.
        The database user should only have INSERT privileges.
        """
        if not self._pg_connection:
            return
        
        cursor = self._pg_connection.cursor()
        
        # Main events table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS honeypot_events (
                id SERIAL PRIMARY KEY,
                event_id VARCHAR(64) UNIQUE NOT NULL,
                session_id VARCHAR(256) NOT NULL,
                timestamp TIMESTAMP NOT NULL,
                ip_address VARCHAR(45) NOT NULL,
                endpoint VARCHAR(500),
                method VARCHAR(10),
                request_payload TEXT,
                detected_attacks TEXT,
                attack_count INTEGER DEFAULT 0,
                highest_severity VARCHAR(20),
                response_code INTEGER,
                response_type VARCHAR(50),
                stage VARCHAR(50),
                user_agent VARCHAR(500),
                additional_data TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        # Session summary table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS session_summary (
                id SERIAL PRIMARY KEY,
                session_id VARCHAR(256) UNIQUE NOT NULL,
                first_seen TIMESTAMP NOT NULL,
                last_seen TIMESTAMP NOT NULL,
                ip_address VARCHAR(45) NOT NULL,
                total_requests INTEGER DEFAULT 0,
                total_attacks INTEGER DEFAULT 0,
                unique_techniques TEXT,
                highest_stage VARCHAR(50),
                behavior_pattern VARCHAR(50),
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        # Integration events table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS integration_events (
                id SERIAL PRIMARY KEY,
                source VARCHAR(50) NOT NULL,
                event_type VARCHAR(100) NOT NULL,
                timestamp TIMESTAMP NOT NULL,
                source_ip VARCHAR(45) NOT NULL,
                destination_ip VARCHAR(45),
                destination_port INTEGER,
                protocol VARCHAR(20),
                severity VARCHAR(20),
                description TEXT,
                indicators TEXT,
                matched_session_id VARCHAR(256),
                raw_event TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        # Create indexes
        cursor.execute('''
            CREATE INDEX IF NOT EXISTS idx_events_session 
            ON honeypot_events(session_id)
        ''')
        cursor.execute('''
            CREATE INDEX IF NOT EXISTS idx_events_timestamp 
            ON honeypot_events(timestamp)
        ''')
        cursor.execute('''
            CREATE INDEX IF NOT EXISTS idx_events_ip 
            ON honeypot_events(ip_address)
        ''')
        
        self._pg_connection.commit()
        cursor.close()
        logger.info("Database tables initialized")
    
    def _signal_handler(self, signum, frame):
        """Handle shutdown signals."""
        logger.info(f"Received signal {signum}, shutting down...")
        self._shutdown_event.set()
    
    def _cleanup(self) -> None:
        """Clean up resources on shutdown."""
        # Flush remaining events
        if self._buffer:
            self._flush_buffer()
        
        # Close connections
        if self._pg_connection:
            try:
                self._pg_connection.close()
            except Exception:
                pass
    
    def run(self) -> None:
        """
        Main daemon loop.
        
        Reads events from Redis queue and writes to PostgreSQL.
        """
        self._running = True
        logger.info("Logging daemon started")
        
        while not self._shutdown_event.is_set():
            try:
                # Read from Redis queue
                event_data = self._read_from_queue()
                
                if event_data:
                    self._buffer.append(event_data)
                
                # Check if we should flush
                if self._should_flush():
                    self._flush_buffer()
                
            except Exception as e:
                logger.error(f"Error in daemon loop: {e}")
                time.sleep(1)
        
        self._running = False
        logger.info("Logging daemon stopped")
    
    def _read_from_queue(self) -> Optional[Dict[str, Any]]:
        """Read an event from the Redis queue."""
        if not self._redis_client:
            time.sleep(0.1)
            return None
        
        try:
            # Blocking pop with 1 second timeout
            result = self._redis_client.blpop(self._queue_name, timeout=1)
            
            if result:
                _, data = result
                return json.loads(data.decode('utf-8'))
        except Exception as e:
            logger.error(f"Error reading from queue: {e}")
        
        return None
    
    def _should_flush(self) -> bool:
        """Check if buffer should be flushed."""
        # Flush if buffer is full
        if len(self._buffer) >= self._batch_size:
            return True
        
        # Flush if interval exceeded
        if time.time() - self._last_flush >= self._flush_interval:
            return len(self._buffer) > 0
        
        return False
    
    def _flush_buffer(self) -> None:
        """Write buffered events to database."""
        if not self._buffer:
            return
        
        if not self._pg_connection:
            # Fallback: write to file
            self._write_to_file()
            return
        
        try:
            cursor = self._pg_connection.cursor()
            
            # Prepare batch insert
            values = []
            for event in self._buffer:
                values.append((
                    event.get('event_id'),
                    event.get('session_id'),
                    datetime.fromtimestamp(event.get('timestamp', time.time())),
                    event.get('ip_address', 'unknown'),
                    event.get('endpoint', ''),
                    event.get('method', 'GET'),
                    event.get('request_payload', '{}'),
                    event.get('detected_attacks', '[]'),
                    event.get('attack_count', 0),
                    event.get('highest_severity', 'NONE'),
                    event.get('response_code', 200),
                    event.get('response_type', 'normal'),
                    event.get('stage', 'unknown'),
                    event.get('user_agent', ''),
                    event.get('additional_data', '{}')
                ))
            
            # Batch insert
            execute_values(
                cursor,
                '''
                INSERT INTO honeypot_events 
                (event_id, session_id, timestamp, ip_address, endpoint, method,
                 request_payload, detected_attacks, attack_count, highest_severity,
                 response_code, response_type, stage, user_agent, additional_data)
                VALUES %s
                ON CONFLICT (event_id) DO NOTHING
                ''',
                values
            )
            
            self._pg_connection.commit()
            cursor.close()
            
            logger.info(f"Flushed {len(self._buffer)} events to database")
            
            self._buffer.clear()
            self._last_flush = time.time()
            
        except Exception as e:
            logger.error(f"Error flushing to database: {e}")
            self._pg_connection.rollback()
            # Fallback to file
            self._write_to_file()
    
    def _write_to_file(self) -> None:
        """Fallback: write events to file."""
        try:
            with open('honeypot_events.jsonl', 'a') as f:
                for event in self._buffer:
                    f.write(json.dumps(event) + '\n')
            
            logger.info(f"Wrote {len(self._buffer)} events to file (fallback)")
            self._buffer.clear()
            self._last_flush = time.time()
            
        except Exception as e:
            logger.error(f"Error writing to file: {e}")


def load_config() -> Dict[str, Any]:
    """Load configuration from environment."""
    return {
        'LOG_DATABASE_URL': os.environ.get(
            'LOG_DATABASE_URL',
            'postgresql://honeypot_logger:password@localhost:5432/honeypot_logs'
        ),
        'REDIS_URL': os.environ.get('REDIS_URL', 'redis://localhost:6379/0'),
        'LOG_QUEUE_NAME': os.environ.get('LOG_QUEUE_NAME', 'honeypot_logs'),
        'LOG_BATCH_SIZE': int(os.environ.get('LOG_BATCH_SIZE', 100)),
        'LOG_FLUSH_INTERVAL': int(os.environ.get('LOG_FLUSH_INTERVAL', 5)),
    }


def main():
    """Main entry point for the logging daemon."""
    config = load_config()
    daemon = LoggingDaemon(config)
    daemon.run()


if __name__ == '__main__':
    main()
