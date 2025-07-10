"""
NetLink Security Middleware

Unified middleware for authentication and security enforcement.
"""

import logging
from typing import Dict, Any, Optional, Callable
from fastapi import Request, Response
from starlette.middleware.base import BaseHTTPMiddleware

from .auth import auth_manager, session_manager
from .protection import ddos_protection, rate_limiter, input_sanitizer
from .exceptions import SecurityError, AuthenticationError

logger = logging.getLogger(__name__)


class SecurityMiddleware(BaseHTTPMiddleware):
    """
    Comprehensive security middleware that integrates all security features.
    """
    
    def __init__(self, app, config: Dict[str, Any] = None):
        super().__init__(app)
        self.config = config or {}
        
    async def dispatch(self, request: Request, call_next):
        """Main security dispatch method."""
        try:
            # DDoS protection check
            client_ip = request.client.host
            user_agent = request.headers.get('user-agent', '')
            endpoint = str(request.url.path)
            
            allowed, threat = await ddos_protection.check_request(client_ip, user_agent, endpoint)
            if not allowed:
                return Response(
                    content="Access denied - DDoS protection",
                    status_code=429,
                    headers={"Retry-After": "3600"}
                )
            
            # Rate limiting check
            rate_allowed, rate_message = await rate_limiter.is_allowed(client_ip, 'api')
            if not rate_allowed:
                return Response(
                    content=f"Rate limit exceeded: {rate_message}",
                    status_code=429,
                    headers={"Retry-After": "60"}
                )
            
            # Process request
            response = await call_next(request)
            return response
            
        except SecurityError as e:
            logger.error(f"Security error in middleware: {e}")
            return Response(
                content="Security error",
                status_code=403
            )
        except Exception as e:
            logger.error(f"Unexpected error in security middleware: {e}")
            return Response(
                content="Internal security error",
                status_code=500
            )


class AuthenticationMiddleware(BaseHTTPMiddleware):
    """
    Authentication middleware for session and token validation.
    """
    
    def __init__(self, app, config: Dict[str, Any] = None):
        super().__init__(app)
        self.config = config or {}
        self.public_paths = {'/login', '/register', '/docs', '/health'}
        
    async def dispatch(self, request: Request, call_next):
        """Authentication dispatch method."""
        path = str(request.url.path)
        
        # Skip authentication for public paths
        if path in self.public_paths or path.startswith('/static/'):
            return await call_next(request)
        
        # Check for session or token
        session_id = request.cookies.get('session_id')
        auth_header = request.headers.get('authorization')
        
        if session_id:
            # Validate session
            session = await session_manager.validate_session(session_id)
            if session:
                request.state.user = session.username
                request.state.security_level = session.security_level
                return await call_next(request)
        
        if auth_header and auth_header.startswith('Bearer '):
            # Validate token (placeholder)
            token = auth_header[7:]
            # Token validation would go here
            pass
        
        # No valid authentication found
        if path.startswith('/api/'):
            return Response(
                content='{"error": "Authentication required"}',
                status_code=401,
                media_type="application/json"
            )
        else:
            # Redirect to login for web interface
            return Response(
                status_code=302,
                headers={"Location": "/login"}
            )
