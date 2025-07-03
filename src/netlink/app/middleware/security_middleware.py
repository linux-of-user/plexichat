# app/middleware/security_middleware.py
"""
Advanced security middleware for comprehensive protection.
"""

import time
import json
from datetime import datetime, timezone
from typing import Dict, Any, Optional, List
from fastapi import Request, Response, HTTPException
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse

from app.logger_config import settings, logger
from app.utils.ip_security import ip_security
from app.utils.rate_limiting import rate_limiter
from app.utils.security import InputSanitizer, SecurityManager


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """Add security headers to all responses."""
    
    def __init__(self, app, config: Optional[Dict] = None):
        super().__init__(app)
        self.config = config or {}
        
        # Default security headers
        self.default_headers = {
            'X-Content-Type-Options': 'nosniff',
            'X-Frame-Options': 'DENY',
            'X-XSS-Protection': '1; mode=block',
            'Strict-Transport-Security': 'max-age=31536000; includeSubDomains',
            'Referrer-Policy': 'strict-origin-when-cross-origin',
            'Permissions-Policy': 'geolocation=(), microphone=(), camera=()',
            'Content-Security-Policy': "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'",
        }
    
    async def dispatch(self, request: Request, call_next):
        response = await call_next(request)
        
        # Add security headers
        for header, value in self.default_headers.items():
            if header not in response.headers:
                response.headers[header] = value
        
        # Add custom headers from config
        custom_headers = self.config.get('custom_headers', {})
        for header, value in custom_headers.items():
            response.headers[header] = value
        
        return response


class IPSecurityMiddleware(BaseHTTPMiddleware):
    """IP-based access control middleware."""
    
    def __init__(self, app, enabled: bool = True):
        super().__init__(app)
        self.enabled = enabled
    
    async def dispatch(self, request: Request, call_next):
        if not self.enabled:
            return await call_next(request)
        
        # Get client IP
        client_ip = ip_security.get_client_ip(request)
        
        # Check if IP is allowed
        is_allowed, reason = ip_security.is_ip_allowed(client_ip)
        
        if not is_allowed:
            logger.warning("Access denied for IP %s: %s", client_ip, reason)
            
            # Record failed attempt
            ip_security.record_failed_attempt(client_ip, "ip_blocked")
            
            return JSONResponse(
                status_code=403,
                content={
                    "error": "Access Forbidden",
                    "message": "Your IP address is not allowed to access this resource",
                    "code": "IP_BLOCKED"
                }
            )
        
        # Add IP info to request state
        request.state.client_ip = client_ip
        
        return await call_next(request)


class RateLimitMiddleware(BaseHTTPMiddleware):
    """Rate limiting middleware."""
    
    def __init__(self, app, enabled: bool = True, default_limit: int = 100, default_window: int = 60):
        super().__init__(app)
        self.enabled = enabled
        self.default_limit = default_limit
        self.default_window = default_window
        
        # Endpoint-specific rate limits
        self.endpoint_limits = {
            '/v1/auth/login': {'limit': 5, 'window': 15},  # 5 attempts per 15 minutes
            '/v1/auth/register': {'limit': 3, 'window': 60},  # 3 attempts per hour
            '/v1/messages/send': {'limit': 50, 'window': 60},  # 50 messages per minute
            '/admin/': {'limit': 20, 'window': 60},  # 20 admin requests per minute
        }
    
    async def dispatch(self, request: Request, call_next):
        if not self.enabled:
            return await call_next(request)
        
        # Get client identifier
        client_ip = getattr(request.state, 'client_ip', request.client.host)
        user_id = getattr(request.state, 'user_id', None)
        
        # Use user ID if authenticated, otherwise IP
        rate_limit_key = f"user:{user_id}" if user_id else f"ip:{client_ip}"
        
        # Get endpoint-specific limits
        endpoint = request.url.path
        endpoint_config = self.endpoint_limits.get(endpoint, {})
        limit = endpoint_config.get('limit', self.default_limit)
        window = endpoint_config.get('window', self.default_window)
        
        # Check rate limit
        allowed = rate_limiter.check_rate_limit(
            key=rate_limit_key,
            max_attempts=limit,
            window_minutes=window,
            algorithm="sliding_window"
        )
        
        if not allowed:
            logger.warning("Rate limit exceeded for %s on %s", rate_limit_key, endpoint)
            
            # Record failed attempt for IP security
            if client_ip:
                ip_security.record_failed_attempt(client_ip, "rate_limit_exceeded")
            
            # Get rate limit info
            _, info = rate_limiter.is_rate_limited(rate_limit_key, limit, window)
            
            return JSONResponse(
                status_code=429,
                content={
                    "error": "Rate Limit Exceeded",
                    "message": "Too many requests. Please try again later.",
                    "retry_after": info.get("retry_after_seconds", 60),
                    "limit": limit,
                    "window": window
                },
                headers=rate_limiter.get_rate_limit_headers(rate_limit_key, limit, window)
            )
        
        # Record successful attempt
        rate_limiter.record_attempt(rate_limit_key)
        
        return await call_next(request)


class InputValidationMiddleware(BaseHTTPMiddleware):
    """Input validation and sanitization middleware."""
    
    def __init__(self, app, enabled: bool = True):
        super().__init__(app)
        self.enabled = enabled
        self.max_request_size = 10 * 1024 * 1024  # 10MB
        
        # Dangerous patterns to detect
        self.suspicious_patterns = [
            r'<script[^>]*>.*?</script>',
            r'javascript:',
            r'on\w+\s*=',
            r'(\b(SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER|EXEC|UNION)\b)',
            r'(--|#|/\*|\*/)',
            r'(\.\./){2,}',  # Path traversal
            r'(cmd|exec|system|eval)\s*\(',  # Command injection
        ]
    
    async def dispatch(self, request: Request, call_next):
        if not self.enabled:
            return await call_next(request)
        
        # Check request size
        content_length = request.headers.get('content-length')
        if content_length and int(content_length) > self.max_request_size:
            logger.warning("Request too large: %s bytes from %s", content_length, request.client.host)
            return JSONResponse(
                status_code=413,
                content={
                    "error": "Request Too Large",
                    "message": "Request body exceeds maximum allowed size",
                    "max_size": self.max_request_size
                }
            )
        
        # Validate URL path
        if self._contains_suspicious_patterns(request.url.path):
            logger.warning("Suspicious URL path detected: %s from %s", request.url.path, request.client.host)
            
            # Record security incident
            client_ip = getattr(request.state, 'client_ip', request.client.host)
            ip_security.record_failed_attempt(client_ip, "suspicious_url")
            
            return JSONResponse(
                status_code=400,
                content={
                    "error": "Invalid Request",
                    "message": "Request contains invalid characters",
                    "code": "INVALID_INPUT"
                }
            )
        
        # Validate query parameters
        for key, value in request.query_params.items():
            if self._contains_suspicious_patterns(f"{key}={value}"):
                logger.warning("Suspicious query parameter: %s=%s from %s", key, value, request.client.host)
                
                client_ip = getattr(request.state, 'client_ip', request.client.host)
                ip_security.record_failed_attempt(client_ip, "suspicious_query")
                
                return JSONResponse(
                    status_code=400,
                    content={
                        "error": "Invalid Request",
                        "message": "Request contains invalid parameters",
                        "code": "INVALID_QUERY"
                    }
                )
        
        return await call_next(request)
    
    def _contains_suspicious_patterns(self, text: str) -> bool:
        """Check if text contains suspicious patterns."""
        import re
        
        for pattern in self.suspicious_patterns:
            if re.search(pattern, text, re.IGNORECASE):
                return True
        return False


class SecurityAuditMiddleware(BaseHTTPMiddleware):
    """Security audit logging middleware."""
    
    def __init__(self, app, enabled: bool = True):
        super().__init__(app)
        self.enabled = enabled
        self.sensitive_endpoints = [
            '/v1/auth/',
            '/admin/',
            '/v1/users/',
            '/v1/config/',
        ]
    
    async def dispatch(self, request: Request, call_next):
        if not self.enabled:
            return await call_next(request)
        
        start_time = time.time()
        
        # Collect request info
        client_ip = getattr(request.state, 'client_ip', request.client.host)
        user_id = getattr(request.state, 'user_id', None)
        
        # Check if this is a sensitive endpoint
        is_sensitive = any(request.url.path.startswith(endpoint) for endpoint in self.sensitive_endpoints)
        
        response = await call_next(request)
        
        # Calculate response time
        response_time = time.time() - start_time
        
        # Log security events
        if is_sensitive or response.status_code >= 400:
            audit_data = {
                'timestamp': datetime.now(timezone.utc).isoformat(),
                'client_ip': client_ip,
                'user_id': user_id,
                'method': request.method,
                'path': request.url.path,
                'status_code': response.status_code,
                'response_time': response_time,
                'user_agent': request.headers.get('user-agent', ''),
                'referer': request.headers.get('referer', ''),
            }
            
            if response.status_code >= 400:
                audit_data['event_type'] = 'security_error'
                logger.warning("Security audit: %s", json.dumps(audit_data))
            elif is_sensitive:
                audit_data['event_type'] = 'sensitive_access'
                logger.info("Security audit: %s", json.dumps(audit_data))
        
        # Add security headers to response
        response.headers['X-Request-ID'] = str(time.time())
        response.headers['X-Response-Time'] = f"{response_time:.3f}s"
        
        return response


class AdvancedAuthenticationMiddleware(BaseHTTPMiddleware):
    """Advanced authentication with 2FA support."""
    
    def __init__(self, app, security_manager: SecurityManager):
        super().__init__(app)
        self.security_manager = security_manager
        self.protected_paths = ['/admin/', '/v1/users/', '/v1/messages/']
        self.public_paths = ['/docs', '/redoc', '/openapi.json', '/v1/auth/', '/v1/status/']
    
    async def dispatch(self, request: Request, call_next):
        # Check if path requires authentication
        path = request.url.path
        
        # Allow public paths
        if any(path.startswith(public_path) for public_path in self.public_paths):
            return await call_next(request)
        
        # Check if path requires authentication
        requires_auth = any(path.startswith(protected_path) for protected_path in self.protected_paths)
        
        if requires_auth:
            # Extract token from Authorization header
            auth_header = request.headers.get('Authorization')
            if not auth_header or not auth_header.startswith('Bearer '):
                return JSONResponse(
                    status_code=401,
                    content={
                        "error": "Authentication Required",
                        "message": "Valid authentication token required",
                        "code": "AUTH_REQUIRED"
                    }
                )
            
            token = auth_header.split(' ')[1]
            
            try:
                # Validate token
                payload = self.security_manager.validate_access_token(token)
                
                # Add user info to request state
                request.state.user_id = payload.get('user_id')
                request.state.user_scopes = payload.get('scopes', [])
                request.state.token_payload = payload
                
            except Exception as e:
                logger.warning("Token validation failed: %s", e)
                return JSONResponse(
                    status_code=401,
                    content={
                        "error": "Invalid Token",
                        "message": "Authentication token is invalid or expired",
                        "code": "INVALID_TOKEN"
                    }
                )
        
        return await call_next(request)


# Global security manager instance
security_manager = SecurityManager()

# Middleware configuration
def get_security_middleware_config():
    """Get security middleware configuration."""
    return {
        'security_headers': {
            'enabled': True,
            'custom_headers': {}
        },
        'ip_security': {
            'enabled': getattr(settings, 'IP_SECURITY_ENABLED', True)
        },
        'rate_limiting': {
            'enabled': getattr(settings, 'RATE_LIMIT_ENABLED', True),
            'default_limit': getattr(settings, 'RATE_LIMIT_REQUESTS', 100),
            'default_window': getattr(settings, 'RATE_LIMIT_WINDOW', 60)
        },
        'input_validation': {
            'enabled': True
        },
        'security_audit': {
            'enabled': True
        },
        'advanced_auth': {
            'enabled': True
        }
    }
