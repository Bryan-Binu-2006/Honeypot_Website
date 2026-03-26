#!/usr/bin/env python3
"""
Honeypot Startup Script

This script starts all components of the honeypot system:
1. Main Flask application
2. Logging daemon (separate process)

Usage:
    python scripts/start.py
    python scripts/start.py --production
"""

import os
import sys
import subprocess
import signal
import time
import argparse
from pathlib import Path

# Add project root to path
PROJECT_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(PROJECT_ROOT))


class HoneypotLauncher:
    """
    Manages startup and shutdown of honeypot components.
    """
    
    def __init__(self, production: bool = False):
        """
        Initialize launcher.
        
        Args:
            production: Run in production mode (gunicorn)
        """
        self.production = production
        self.processes = []
        self.running = True
        
        # Set up signal handlers
        signal.signal(signal.SIGTERM, self._signal_handler)
        signal.signal(signal.SIGINT, self._signal_handler)
    
    def _signal_handler(self, signum, frame):
        """Handle shutdown signals."""
        print("\n[*] Shutdown signal received...")
        self.running = False
        self.stop_all()
    
    def start_logging_daemon(self) -> subprocess.Popen:
        """Start the logging daemon process."""
        print("[*] Starting logging daemon...")
        
        daemon_script = PROJECT_ROOT / 'logging_daemon' / 'service.py'
        
        process = subprocess.Popen(
            [sys.executable, str(daemon_script)],
            cwd=str(PROJECT_ROOT),
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT
        )
        
        self.processes.append(('logging_daemon', process))
        print(f"[+] Logging daemon started (PID: {process.pid})")
        
        return process
    
    def start_web_app(self) -> subprocess.Popen:
        """Start the Flask web application."""
        print("[*] Starting web application...")
        
        if self.production:
            # Use gunicorn for production
            cmd = [
                'gunicorn',
                '-w', '4',
                '-b', '0.0.0.0:5000',
                '--access-logfile', '-',
                '--error-logfile', '-',
                'app:create_app()'
            ]
        else:
            # Development mode
            cmd = [sys.executable, str(PROJECT_ROOT / 'run.py')]
        
        env = os.environ.copy()
        if not self.production:
            env['FLASK_ENV'] = 'development'
            env['FLASK_DEBUG'] = '1'
        
        process = subprocess.Popen(
            cmd,
            cwd=str(PROJECT_ROOT),
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT
        )
        
        self.processes.append(('web_app', process))
        print(f"[+] Web application started (PID: {process.pid})")
        
        return process
    
    def stop_all(self):
        """Stop all running processes."""
        print("[*] Stopping all processes...")
        
        for name, process in self.processes:
            if process.poll() is None:
                print(f"[*] Stopping {name} (PID: {process.pid})...")
                process.terminate()
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    print(f"[!] Force killing {name}...")
                    process.kill()
        
        print("[+] All processes stopped")
    
    def monitor(self):
        """Monitor running processes and restart if needed."""
        while self.running:
            for name, process in self.processes:
                if process.poll() is not None:
                    print(f"[!] {name} exited with code {process.returncode}")
                    if self.running:
                        print(f"[*] Restarting {name}...")
                        if name == 'logging_daemon':
                            self.start_logging_daemon()
                        elif name == 'web_app':
                            self.start_web_app()
            
            time.sleep(1)
    
    def start(self):
        """Start all components."""
        print("""
╔═══════════════════════════════════════════════════════════════╗
║           HONEYPOT SECURITY PLATFORM - LAUNCHER               ║
╚═══════════════════════════════════════════════════════════════╝
""")
        
        # Check for .env file
        env_file = PROJECT_ROOT / '.env'
        if not env_file.exists():
            env_example = PROJECT_ROOT / '.env.example'
            if env_example.exists():
                print("[!] No .env file found. Creating from .env.example...")
                import shutil
                shutil.copy(env_example, env_file)
                print("[+] Created .env file. Please configure it for production use.")
            else:
                print("[!] Warning: No .env file found. Using defaults.")
        
        # Load environment
        from dotenv import load_dotenv
        load_dotenv(env_file)
        
        # Start components
        self.start_logging_daemon()
        time.sleep(1)  # Give logging daemon time to initialize
        self.start_web_app()
        
        print("\n[+] All components started successfully!")
        print(f"[*] Web application: http://localhost:5000")
        print("[*] Press Ctrl+C to stop\n")
        
        # Monitor processes
        self.monitor()


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(description='Start the Honeypot Security Platform')
    parser.add_argument('--production', '-p', action='store_true',
                       help='Run in production mode with gunicorn')
    args = parser.parse_args()
    
    launcher = HoneypotLauncher(production=args.production)
    launcher.start()


if __name__ == '__main__':
    main()
