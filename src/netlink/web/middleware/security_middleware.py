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

import logging import settings, logger
from netlink.utils.ip_security import ip_security
from netlink.utils.rate_limiting import rate_limiter
from netlink.utils.security import InputSanitizer, SecurityManager

# Import enhanced security services
try:
    from netlink.services.security_service import SecurityService
    from netlink.security.ddos_protection import ddos_protection
    ENHANCED_SECURITY_AVAILABLE = True
except ImportError:
    ENHANCED_SECURITY_AVAILABLE = False


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
    """Enhanced rate limiting middleware with progressive blocking and DDoS protection."""

    def __init__(self, app, enabled: bool = True, default_limit: int = 100, default_window: int = 60):
        super().__init__(app)
        self.enabled = enabled
        self.default_limit = default_limit
        self.default_window = default_window

        # Initialize enhanced security services
        if ENHANCED_SECURITY_AVAILABLE:
            self.security_service = SecurityService()
        else:
            self.security_service = None

        # Enhanced endpoint-specific rate limits with progressive blocking
        self.endpoint_limits = {
            '/api/v1/auth/login': {'limit': 5, 'window': 15, 'progressive': True},  # 5 attempts per 15 minutes
            '/api/v1/auth/register': {'limit': 3, 'window': 60, 'progressive': True},  # 3 attempts per hour
            '/api/v1/messages': {'limit': 50, 'window': 60, 'progressive': False},  # 50 messages per minute
            '/api/v1/messages/send': {'limit': 30, 'window': 60, 'progressive': False},  # 30 sends per minute
            '/api/v1/files/upload': {'limit': 10, 'window': 60, 'progressive': True},  # 10 uploads per minute
            '/admin/': {'limit': 20, 'window': 60, 'progressive': True},  # 20 admin requests per minute
            '/api/v1/system/': {'limit': 100, 'window': 60, 'progressive': False},  # 100 system requests per minute
        }

        # Progressive blocking configuration
        self.progressive_blocks = {}  # IP -> {endpoint -> block_info}
        self.violation_counts = {}    # IP -> {endpoint -> count}

        # Witty rate limit messages
        self.rate_limit_messages = {
            'auth': [
                "Whoa there, speed racer! 🏎️ Authentication isn't a race!",
                "Easy on the login attempts! 🔐 Your password isn't going anywhere!",
                "Too many login tries! 🚫 Take a breather and try again later!",
                "Login limit exceeded! 🛑 Maybe it's time for a password manager?"
            ],
            'messages': [
                "Slow down, chatterbox! 💬 Quality over quantity!",
                "Message limit reached! 📝 Give others a chance to speak!",
                "Too many messages! 🗣️ Time for a digital detox?",
                "Message flood detected! 🌊 Let's keep it conversational!"
            ],
            'files': [
                "File upload limit exceeded! 📁 Rome wasn't built in a day!",
                "Too many uploads! 📤 Your files aren't going anywhere!",
                "Upload limit reached! 💾 Quality uploads over quantity!",
                "File flood detected! 🗂️ Let's pace ourselves!"
            ],
            'admin': [
                "Admin limit exceeded! 👑 Even admins need to follow rules!",
                "Too many admin requests! ⚡ Power comes with responsibility!",
                "Admin rate limit hit! 🛡️ Slow and steady wins the race!",
                "Administrative overload! 🎛️ Take a moment to breathe!"
            ],
            'default': [
                "Rate limit exceeded! 🚦 Slow down and try again!",
                "Too many requests! ⏰ Patience is a virtue!",
                "Request limit reached! 🛑 Quality over quantity!",
                "Slow down there! 🐌 Good things come to those who wait!"
            ]
        }
    
    async def dispatch(self, request: Request, call_next):
        if not self.enabled:
            return await call_next(request)

        # Get client identifier
        client_ip = getattr(request.state, 'client_ip', request.client.host)
        user_id = getattr(request.state, 'user_id', None)
        user_agent = request.headers.get("user-agent", "")

        # Use user ID if authenticated, otherwise IP
        rate_limit_key = f"user:{user_id}" if user_id else f"ip:{client_ip}"

        # Check DDoS protection first
        if ENHANCED_SECURITY_AVAILABLE:
            ddos_allowed, ddos_reason, ddos_info = await ddos_protection.check_request(
                client_ip, user_agent
            )
            if not ddos_allowed:
                logger.warning(f"DDoS protection blocked request from {client_ip}: {ddos_reason}")
                return JSONResponse(
                    status_code=429,
                    content={
                        "error": "DDoS Protection",
                        "message": "Request blocked by DDoS protection",
                        "witty_response": "🛡️ Our shields are up! Slow down, space cowboy!",
                        "reason": ddos_reason,
                        "retry_after": 300  # 5 minutes
                    }
                )

        # Get endpoint-specific limits
        endpoint = request.url.path
        endpoint_config = self._get_endpoint_config(endpoint)
        limit = endpoint_config.get('limit', self.default_limit)
        window = endpoint_config.get('window', self.default_window)
        progressive = endpoint_config.get('progressive', False)

        # Check if IP is in progressive block for this endpoint
        if progressive and self._is_progressively_blocked(client_ip, endpoint):
            block_info = self.progressive_blocks[client_ip][endpoint]
            remaining_time = int(block_info['expires'] - time.time())

            if remaining_time > 0:
                return JSONResponse(
                    status_code=429,
                    content={
                        "error": "Progressive Block",
                        "message": f"Temporarily blocked due to repeated violations",
                        "witty_response": self._get_progressive_block_message(endpoint, block_info['level']),
                        "retry_after": remaining_time,
                        "block_level": block_info['level']
                    }
                )
            else:
                # Block expired, remove it
                del self.progressive_blocks[client_ip][endpoint]

        # Check rate limit
        allowed = rate_limiter.check_rate_limit(
            key=rate_limit_key,
            max_attempts=limit,
            window_minutes=window,
            algorithm="sliding_window"
        )

        if not allowed:
            logger.warning("Rate limit exceeded for %s on %s", rate_limit_key, endpoint)

            # Handle progressive blocking
            if progressive:
                self._handle_progressive_violation(client_ip, endpoint)

            # Record failed attempt for IP security
            if client_ip:
                ip_security.record_failed_attempt(client_ip, "rate_limit_exceeded")

            # Get rate limit info
            _, info = rate_limiter.is_rate_limited(rate_limit_key, limit, window)

            # Get witty message
            witty_message = self._get_witty_message(endpoint, client_ip)

            return JSONResponse(
                status_code=429,
                content={
                    "error": "Rate Limit Exceeded",
                    "message": "Too many requests. Please try again later.",
                    "witty_response": witty_message,
                    "retry_after": info.get("retry_after_seconds", window),
                    "limit": limit,
                    "window": window,
                    "endpoint": endpoint
                },
                headers=rate_limiter.get_rate_limit_headers(rate_limit_key, limit, window)
            )

        # Record successful attempt
        rate_limiter.record_attempt(rate_limit_key)

        # Reset violation count on successful request
        if progressive and client_ip in self.violation_counts:
            if endpoint in self.violation_counts[client_ip]:
                self.violation_counts[client_ip][endpoint] = max(0,
                    self.violation_counts[client_ip][endpoint] - 1)

        return await call_next(request)

    def _get_endpoint_config(self, endpoint: str) -> Dict[str, Any]:
        """Get configuration for endpoint, including pattern matching."""
        # Direct match first
        if endpoint in self.endpoint_limits:
            return self.endpoint_limits[endpoint]

        # Pattern matching for endpoints
        for pattern, config in self.endpoint_limits.items():
            if endpoint.startswith(pattern):
                return config

        # Default configuration
        return {'limit': self.default_limit, 'window': self.default_window, 'progressive': False}

    def _is_progressively_blocked(self, ip: str, endpoint: str) -> bool:
        """Check if IP is progressively blocked for endpoint."""
        if ip not in self.progressive_blocks:
            return False
        if endpoint not in self.progressive_blocks[ip]:
            return False

        block_info = self.progressive_blocks[ip][endpoint]
        return time.time() < block_info['expires']

    def _handle_progressive_violation(self, ip: str, endpoint: str):
        """Handle progressive blocking violation."""
        # Initialize structures
        if ip not in self.violation_counts:
            self.violation_counts[ip] = {}
        if endpoint not in self.violation_counts[ip]:
            self.violation_counts[ip][endpoint] = 0

        # Increment violation count
        self.violation_counts[ip][endpoint] += 1
        violation_count = self.violation_counts[ip][endpoint]

        # Progressive blocking levels
        block_durations = {
            3: 60,      # 1 minute after 3 violations
            5: 300,     # 5 minutes after 5 violations
            8: 900,     # 15 minutes after 8 violations
            12: 3600,   # 1 hour after 12 violations
            20: 86400   # 24 hours after 20 violations
        }

        # Check if blocking threshold reached
        for threshold, duration in block_durations.items():
            if violation_count >= threshold:
                # Initialize progressive blocks structure
                if ip not in self.progressive_blocks:
                    self.progressive_blocks[ip] = {}

                # Set block
                self.progressive_blocks[ip][endpoint] = {
                    'level': threshold,
                    'expires': time.time() + duration,
                    'violations': violation_count
                }

                logger.warning(f"Progressive block applied to {ip} for {endpoint}: "
                             f"level {threshold}, duration {duration}s, violations {violation_count}")
                break

    def _get_witty_message(self, endpoint: str, ip: str) -> str:
        """Get witty rate limit message based on endpoint and violation history."""
        # Determine message category
        category = 'default'
        if 'auth' in endpoint:
            category = 'auth'
        elif 'message' in endpoint:
            category = 'messages'
        elif 'file' in endpoint or 'upload' in endpoint:
            category = 'files'
        elif 'admin' in endpoint:
            category = 'admin'

        # Get violation count for escalation
        violation_count = 0
        if ip in self.violation_counts:
            violation_count = sum(self.violation_counts[ip].values())

        # Select message based on violation count
        messages = self.rate_limit_messages[category]
        message_index = min(violation_count, len(messages) - 1)

        return messages[message_index]

    def _get_progressive_block_message(self, endpoint: str, level: int) -> str:
        """Get witty message for progressive blocks."""
        messages = {
            3: "🚦 Yellow card! Slow down a bit!",
            5: "🛑 Red card! Time for a short break!",
            8: "⏰ Extended timeout! Go grab a coffee!",
            12: "🏖️ Mandatory vacation time! See you in an hour!",
            20: "🌙 Good night! Come back tomorrow!"
        }

        return messages.get(level, "🛡️ Progressive block active! Please wait!")


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
