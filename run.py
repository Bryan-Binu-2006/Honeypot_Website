"""
Honeypot Web Application - Main Entry Point

Run this script to start the honeypot application.

Usage:
    python run.py
    
For production:
    nginx -> waitress (this script) on 127.0.0.1:5000
"""

import os
import sys
import logging
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

# Add the project root to Python path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from app import create_app


def _env_bool(name: str, default: bool) -> bool:
    raw = os.environ.get(name)
    if raw is None:
        return default
    return str(raw).strip().lower() in {'1', 'true', 'yes', 'on'}


def main():
    """Main entry point for running the application."""
    # Create Flask app
    app = create_app()
    
    # Get configuration from environment
    host = os.environ.get('HOST', '0.0.0.0')
    port = int(os.environ.get('PORT', 5000))
    debug = os.environ.get('FLASK_DEBUG', '0') == '1'
    flask_env = os.environ.get('FLASK_ENV', 'production').strip().lower()
    is_development = flask_env == 'development' or debug

    # In production/Nginx mode, bind local by default to avoid direct internet exposure.
    if not is_development and host in {'0.0.0.0', '::'}:
        host = os.environ.get('UPSTREAM_HOST', '127.0.0.1')

    use_flask_dev_server = _env_bool('USE_FLASK_DEV_SERVER', is_development)
    waitress_threads = int(os.environ.get('WAITRESS_THREADS', '8'))
    
    print(
        "\n"
        "===============================================================\n"
        "               CyberShield Honeypot Platform                  \n"
        "===============================================================\n"
        f"Status: Starting\n"
        f"Host: {host}:{port}\n"
        f"Debug: {'Enabled' if debug else 'Disabled'}\n"
        "===============================================================\n"
    )
    
    if debug:
        print("WARNING: Debug mode is enabled. Do not use in production!\n")

    if use_flask_dev_server:
        # Development-only server. Keep for local debugging convenience.
        app.run(
            host=host,
            port=port,
            debug=debug,
            threaded=True
        )
        return

    # Production path for Nginx reverse proxy deployments.
    try:
        waitress_module = __import__('waitress')
        serve = getattr(waitress_module, 'serve')
    except Exception:
        logging.error(
            "Waitress is required for production run.py mode. "
            "Install dependencies from requirements.txt, or set USE_FLASK_DEV_SERVER=1 for local testing only."
        )
        raise SystemExit(1)

    print(
        f"Starting production WSGI server (waitress) on {host}:{port}. "
        "Expected topology: nginx -> waitress"
    )
    serve(app, host=host, port=port, threads=max(waitress_threads, 2))


if __name__ == '__main__':
    main()
