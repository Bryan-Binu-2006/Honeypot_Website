"""
Logging Daemon - Database Connection Manager

Handles PostgreSQL connections with proper security settings.
"""

import os
from typing import Optional, Dict, Any
from contextlib import contextmanager

try:
    import psycopg2
    from psycopg2.pool import ThreadedConnectionPool
    HAS_POSTGRES = True
except ImportError:
    HAS_POSTGRES = False
    psycopg2 = None
    ThreadedConnectionPool = None


class DatabaseManager:
    """
    Manages PostgreSQL connections for the logging daemon.
    
    INTERNAL: Uses connection pooling for efficiency.
    The database user should have INSERT-only privileges.
    """
    
    def __init__(self, database_url: str, min_connections: int = 1, max_connections: int = 10):
        """
        Initialize database manager.
        
        Args:
            database_url: PostgreSQL connection string
            min_connections: Minimum pool size
            max_connections: Maximum pool size
        """
        self._database_url = database_url
        self._pool: Optional[ThreadedConnectionPool] = None
        self._min = min_connections
        self._max = max_connections
        
        if HAS_POSTGRES:
            self._init_pool()
    
    def _init_pool(self) -> None:
        """Initialize connection pool."""
        try:
            self._pool = ThreadedConnectionPool(
                self._min,
                self._max,
                self._database_url
            )
        except Exception as e:
            print(f"Failed to initialize connection pool: {e}")
            self._pool = None
    
    @contextmanager
    def get_connection(self):
        """
        Get a connection from the pool.
        
        Usage:
            with db.get_connection() as conn:
                cursor = conn.cursor()
                ...
        """
        if not self._pool:
            yield None
            return
        
        conn = None
        try:
            conn = self._pool.getconn()
            yield conn
        finally:
            if conn:
                self._pool.putconn(conn)
    
    def close_all(self) -> None:
        """Close all connections in the pool."""
        if self._pool:
            self._pool.closeall()
    
    @property
    def is_available(self) -> bool:
        """Check if database is available."""
        return self._pool is not None


def get_log_database_url() -> str:
    """Get the logging database URL from environment."""
    return os.environ.get(
        'LOG_DATABASE_URL',
        'postgresql://honeypot_logger:password@localhost:5432/honeypot_logs'
    )
