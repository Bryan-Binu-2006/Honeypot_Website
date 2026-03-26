"""
Honeypot Web Application - Main Entry Point

Run this script to start the honeypot application.

Usage:
    python run.py
    
For production:
    gunicorn -w 4 -b 0.0.0.0:5000 "app:create_app()"
"""

import os
import sys
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

# Add the project root to Python path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from app import create_app


def main():
    """Main entry point for running the application."""
    # Create Flask app
    app = create_app()
    
    # Get configuration from environment
    host = os.environ.get('HOST', '0.0.0.0')
    port = int(os.environ.get('PORT', 5000))
    debug = os.environ.get('FLASK_DEBUG', '0') == '1'
    
    print(f"""
╔═══════════════════════════════════════════════════════════════╗
║                                                               ║
║     ██████╗██╗   ██╗██████╗ ███████╗██████╗                   ║
║    ██╔════╝╚██╗ ██╔╝██╔══██╗██╔════╝██╔══██╗                  ║
║    ██║      ╚████╔╝ ██████╔╝█████╗  ██████╔╝                  ║
║    ██║       ╚██╔╝  ██╔══██╗██╔══╝  ██╔══██╗                  ║
║    ╚██████╗   ██║   ██████╔╝███████╗██║  ██║                  ║
║     ╚═════╝   ╚═╝   ╚═════╝ ╚══════╝╚═╝  ╚═╝                  ║
║                                                               ║
║        CyberShield Honeypot Security Platform                 ║
║                                                               ║
╠═══════════════════════════════════════════════════════════════╣
║  Status: Starting...                                          ║
║  Host: {host}:{port:<40}      ║
║  Debug: {'Enabled' if debug else 'Disabled':<47}             ║
╚═══════════════════════════════════════════════════════════════╝
""")
    
    if debug:
        print("⚠️  WARNING: Debug mode is enabled. Do not use in production!\n")
    
    # Run the application
    app.run(
        host=host,
        port=port,
        debug=debug,
        threaded=True
    )


if __name__ == '__main__':
    main()
