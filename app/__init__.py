"""
Honeypot Web Application - Flask Application Factory

This module creates and configures the Flask application using the factory pattern.
It registers all blueprints, middleware, and initializes core services.

INTERNAL DOCUMENTATION:
- All request handling goes through middleware first
- Detection and logging are triggered transparently
- No internal workings are exposed in responses
"""

from flask import Flask, g
from typing import Optional

from .config import get_config


def create_app(config_name: Optional[str] = None) -> Flask:
    """
    Application factory for creating Flask app instances.
    
    Args:
        config_name: Optional configuration override
        
    Returns:
        Configured Flask application
        
    INTERNAL NOTE:
    - Middleware intercepts ALL requests before route handlers
    - Detection engine runs on every request
    - Logging interface abstracts all event recording
    """
    app = Flask(__name__)
    
    # Load configuration
    config = get_config()
    app.config.from_object(config)
    
    # Initialize extensions and services
    _init_extensions(app)
    
    # Register middleware (intercepts all requests)
    _register_middleware(app)
    
    # Register blueprints (route handlers)
    _register_blueprints(app)
    
    # Register error handlers
    _register_error_handlers(app)
    
    # Initialize internal services
    _init_services(app)
    
    return app


def _init_extensions(app: Flask) -> None:
    """
    Initialize Flask extensions.
    
    INTERNAL: Extensions are configured but not exposed publicly.
    """
    # Rate limiter - helps detect scanning behavior
    try:
        from flask_limiter import Limiter
        from flask_limiter.util import get_remote_address
        
        limiter = Limiter(
            key_func=get_remote_address,
            app=app,
            default_limits=[app.config.get('RATELIMIT_DEFAULT', '100/minute')],
            storage_uri=app.config.get('RATELIMIT_STORAGE_URL', 'memory://')
        )
        app.limiter = limiter
    except ImportError:
        # Gracefully handle missing limiter
        app.limiter = None


def _register_middleware(app: Flask) -> None:
    """
    Register request/response middleware.
    
    INTERNAL DOCUMENTATION:
    This is where the magic happens - all requests are intercepted,
    analyzed by the detection engine, and logged without the attacker knowing.
    The middleware layer is completely invisible to external users.
    """
    from .middleware.interceptor import RequestInterceptor
    from .middleware.security import SecurityMiddleware
    from .session.manager import SessionManager
    
    interceptor = RequestInterceptor()
    security = SecurityMiddleware()
    session_manager = SessionManager(app.config.get('SESSION_SECRET', 'default-secret'))
    
    @app.before_request
    def before_request_handler():
        """
        Pre-request processing:
        1. Validate/create session
        2. Capture request data
        3. Run detection engine
        4. Store results for response engine
        """
        from flask import request
        
        # Session management - creates or validates session
        session_id = session_manager.get_or_create_session(request)
        g.session_id = session_id
        
        # Intercept and analyze request
        analysis = interceptor.analyze(request, session_id)
        g.request_analysis = analysis
        
        # Store for response engine (determines what fake response to return)
        g.detected_attacks = analysis.get('detected_attacks', [])
        g.attacker_stage = analysis.get('stage', 'recon')
    
    @app.after_request
    def after_request_handler(response):
        """
        Post-request processing:
        1. Add security headers
        2. Queue event for logging (non-blocking)
        3. Update attacker profile
        """
        # Apply security headers
        response = security.apply_headers(response)

        # Persist attacker session in cookie so multiple requests from one browser
        # are correlated to a single session.
        if hasattr(g, 'session_id') and g.get('session_id'):
            from flask import request

            cookie_secure = bool(app.config.get('SESSION_COOKIE_SECURE', True))
            # Allow localhost HTTP testing while keeping secure cookies in production.
            if cookie_secure and not request.is_secure:
                forwarded_proto = request.headers.get('X-Forwarded-Proto', '').lower()
                host = request.host.split(':', 1)[0].lower()
                if forwarded_proto != 'https' and host in {'127.0.0.1', 'localhost'}:
                    cookie_secure = False

            session_manager.set_session_cookie(
                response,
                g.get('session_id'),
                cookie_name=app.config.get('SESSION_COOKIE_NAME', 'sid'),
                httponly=bool(app.config.get('SESSION_COOKIE_HTTPONLY', True)),
                secure=cookie_secure,
                samesite=app.config.get('SESSION_COOKIE_SAMESITE', 'Lax')
            )
        
        # Queue logging event (async, non-blocking)
        # This uses internal interface - logging details are abstracted
        if hasattr(g, 'request_analysis'):
            from .logging_service.interface import queue_event
            queue_event(
                session_id=g.get('session_id'),
                analysis=g.request_analysis,
                response_code=response.status_code
            )
        
        return response


def _register_blueprints(app: Flask) -> None:
    """
    Register all route blueprints.
    
    Routes are organized by functionality:
    - public: Homepage, login, robots.txt
    - admin: Admin panel, dashboard (FAKE - for attackers)
    - api: Fake internal APIs
    - files: File explorer (LFI/IDOR simulation)
    - terminal: Web terminal simulation
    """
    from .routes.public import public_bp
    from .routes.admin import admin_bp
    from .routes.api import api_bp
    from .routes.files import files_bp
    from .routes.terminal import terminal_bp
    
    app.register_blueprint(public_bp)
    app.register_blueprint(admin_bp, url_prefix='/admin')
    app.register_blueprint(api_bp, url_prefix='/api')
    app.register_blueprint(files_bp, url_prefix='/files')
    app.register_blueprint(terminal_bp, url_prefix='/terminal')


def _register_error_handlers(app: Flask) -> None:
    """
    Register custom error handlers.
    
    INTERNAL: Error pages should look realistic but not reveal internal structure.
    Even error responses are part of the deception.
    """
    from flask import render_template, jsonify, request
    
    @app.errorhandler(404)
    def not_found(e):
        if request.path.startswith('/api/'):
            return jsonify({'error': 'Endpoint not found', 'status': 404}), 404
        return render_template('errors/404.html'), 404
    
    @app.errorhandler(500)
    def internal_error(e):
        # NEVER expose real stack traces
        if request.path.startswith('/api/'):
            return jsonify({'error': 'Internal server error', 'status': 500}), 500
        return render_template('errors/500.html'), 500
    
    @app.errorhandler(429)
    def rate_limited(e):
        # Rate limiting can indicate scanning - this is logged
        return jsonify({
            'error': 'Too many requests',
            'message': 'Please slow down',
            'retry_after': 60
        }), 429


def _init_services(app: Flask) -> None:
    """
    Initialize internal services.
    
    INTERNAL: These services run in the background and are never exposed.
    """
    from .behavior.engine import BehaviorEngine
    from .logging_service.interface import init_logging_interface
    
    # Initialize the logging interface (connects to queue)
    init_logging_interface(app.config)
    
    # Initialize behavior engine for tracking attacker progression
    app.behavior_engine = BehaviorEngine()
