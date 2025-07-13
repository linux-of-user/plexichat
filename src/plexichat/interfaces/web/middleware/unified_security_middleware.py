"""
PlexiChat Unified Security Middleware - SINGLE SOURCE OF TRUTH

CONSOLIDATED from multiple security middleware systems:
- interfaces/web/middleware/comprehensive_security_middleware.py - INTEGRATED
- interfaces/web/middleware/security_middleware.py - INTEGRATED
- interfaces/web/middleware/message_security_middleware.py - INTEGRATED
- features/security/comprehensive_security.py - INTEGRATED

Features:
- Comprehensive authentication and authorization
- Advanced rate limiting and DDoS protection
- Input validation and sanitization
- SQL injection and XSS prevention
- Malware and threat detection
- Real-time security monitoring
- Audit logging integration
- Zero-trust security enforcement
"""

import ipaddress
import re
import time
from datetime import datetime, timezone
from typing import Any, Dict, Optional

from fastapi import Request, Response
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse

from ....core_system.config import get_config
from ....core_system.logging import get_logger
from ....core_system.security.input_validation import (
    InputType,
    ValidationLevel,
    get_input_validator,
)
from ....core_system.security.unified_audit_system import (
    SecurityEventType,
    SecuritySeverity,
    ThreatLevel,
    get_unified_audit_system,
)
from ....core_system.security.unified_auth_manager import get_unified_auth_manager
from ....core_system.security.unified_security_manager import get_unified_security_manager
from ....features.security.network_protection import RateLimitRequest, get_network_protection

logger = get_logger(__name__)


class SecurityLevel:
    """Security levels for endpoints."""
    PUBLIC = 0      # No authentication required
    BASIC = 1       # Basic authentication required
    SECURE = 2      # Authenticated + basic security
    HIGH = 3        # Authenticated + MFA recommended
    CRITICAL = 4    # Authenticated + MFA required
    ADMIN = 5       # Admin privileges required


class UnifiedSecurityMiddleware(BaseHTTPMiddleware):
    """
    Unified Security Middleware - Single Source of Truth
    
    Applies comprehensive security across all API endpoints including:
    - Authentication and authorization
    - Rate limiting and DDoS protection
    - Input validation and sanitization
    - Threat detection and monitoring
    - Audit logging
    """
    
    def __init__(self, app, config: Optional[Dict[str, Any]] = None):
        super().__init__(app)
        self.config = config or get_config().get("security_middleware", {})
        self.enabled = self.config.get("enabled", True)
        
        # Security components
        self.security_manager = None
        self.auth_manager = None
        self.input_validator = None
        self.network_protection = None
        self.audit_system = None
        
        # Security policies
        self.endpoint_security_levels = {
            # Public endpoints
            '/docs': SecurityLevel.PUBLIC,
            '/redoc': SecurityLevel.PUBLIC,
            '/openapi.json': SecurityLevel.PUBLIC,
            '/health': SecurityLevel.PUBLIC,
            '/status': SecurityLevel.PUBLIC,
            
            # Basic authentication
            '/api/v1/auth/login': SecurityLevel.BASIC,
            '/api/v1/auth/register': SecurityLevel.BASIC,
            '/api/v1/auth/refresh': SecurityLevel.BASIC,
            
            # Secure endpoints
            '/api/v1/messages': SecurityLevel.SECURE,
            '/api/v1/files': SecurityLevel.SECURE,
            '/api/v1/users/profile': SecurityLevel.SECURE,
            
            # High security endpoints
            '/api/v1/users/admin': SecurityLevel.HIGH,
            '/api/v1/system/config': SecurityLevel.HIGH,
            
            # Critical endpoints
            '/api/v1/admin': SecurityLevel.CRITICAL,
            '/api/v1/system/backup': SecurityLevel.CRITICAL,
            '/api/v1/system/cluster': SecurityLevel.CRITICAL,
            
            # Admin endpoints
            '/admin': SecurityLevel.ADMIN,
            '/api/v1/system/security': SecurityLevel.ADMIN
        }
        
        # Rate limiting configuration
        self.rate_limits = {
            'default': {'requests_per_minute': 60, 'burst': 10},
            '/api/v1/auth/login': {'requests_per_minute': 10, 'burst': 3},
            '/api/v1/auth/register': {'requests_per_minute': 5, 'burst': 2},
            '/api/v1/files/upload': {'requests_per_minute': 20, 'burst': 5},
            '/admin': {'requests_per_minute': 30, 'burst': 5}
        }
        
        # Security headers
        self.security_headers = {
            'X-Content-Type-Options': 'nosniff',
            'X-Frame-Options': 'DENY',
            'X-XSS-Protection': '1; mode=block',
            'Strict-Transport-Security': 'max-age=31536000; includeSubDomains',
            'Content-Security-Policy': "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'",
            'Referrer-Policy': 'strict-origin-when-cross-origin',
            'Permissions-Policy': 'geolocation=(), microphone=(), camera=()'
        }
        
        # Blocked patterns
        self.sql_injection_patterns = [
            r"(\b(SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER|EXEC|UNION)\b)",
            r"(--|#|/\*|\*/)",
            r"(\b(OR|AND)\s+\d+\s*=\s*\d+)",
            r"(\bUNION\s+SELECT\b)",
            r"(\b(EXEC|EXECUTE)\s*\()",
            r"(\bxp_cmdshell\b)"
        ]
        
        self.xss_patterns = [
            r"<script[^>]*>.*?</script>",
            r"javascript:",
            r"vbscript:",
            r"on\w+\s*=",
            r"<iframe[^>]*>",
            r"<object[^>]*>"
        ]
        
        # Statistics
        self.stats = {
            'total_requests': 0,
            'blocked_requests': 0,
            'threats_detected': 0,
            'auth_failures': 0,
            'rate_limit_violations': 0
        }
        
        logger.info("Unified Security Middleware initialized")
    
    async def dispatch(self, request: Request, call_next):
        """Main security dispatch method."""
        if not self.enabled:
            return await call_next(request)
        
        start_time = time.time()
        self.stats['total_requests'] += 1
        
        try:
            # Initialize security components if needed
            await self._ensure_components_initialized()
            
            # Extract request information
            request_info = await self._extract_request_info(request)
            
            # 1. IP-based security checks
            ip_check = await self._check_ip_security(request_info)
            if not ip_check['allowed']:
                return self._create_security_response(ip_check, 403)
            
            # 2. Rate limiting
            rate_check = await self._check_rate_limits(request_info)
            if not rate_check['allowed']:
                return self._create_security_response(rate_check, 429)
            
            # 3. Input validation and threat detection
            input_check = await self._validate_input_security(request, request_info)
            if not input_check['allowed']:
                return self._create_security_response(input_check, 400)
            
            # 4. Authentication and authorization
            auth_check = await self._check_authentication_authorization(request, request_info)
            if not auth_check['allowed']:
                return self._create_security_response(auth_check, 401)
            
            # 5. Endpoint-specific security
            endpoint_check = await self._check_endpoint_security(request, request_info)
            if not endpoint_check['allowed']:
                return self._create_security_response(endpoint_check, 403)
            
            # Request passed all security checks
            response = await call_next(request)
            
            # Add security headers
            self._add_security_headers(response)
            
            # Log successful request
            processing_time = (time.time() - start_time) * 1000
            await self._log_security_event(
                SecurityEventType.DATA_ACCESS,
                f"Successful request to {request_info['path']}",
                SecuritySeverity.INFO,
                ThreatLevel.LOW,
                request_info,
                {"processing_time_ms": processing_time}
            )
            
            return response
            
        except Exception as e:
            logger.error(f"Security middleware error: {e}")
            
            # Log security error
            await self._log_security_event(
                SecurityEventType.SYSTEM_COMPROMISE,
                f"Security middleware error: {str(e)}",
                SecuritySeverity.ERROR,
                ThreatLevel.HIGH,
                request_info if 'request_info' in locals() else {},
                {"error": str(e)}
            )
            
            # On error, block request for security
            return self._create_security_response({
                'reason': 'Security system error',
                'action': 'blocked'
            }, 500)
    
    async def _ensure_components_initialized(self):
        """Ensure all security components are initialized."""
        if not self.security_manager:
            self.security_manager = get_unified_security_manager()
            if not self.security_manager.initialized:
                await self.security_manager.initialize()
        
        if not self.auth_manager:
            self.auth_manager = get_unified_auth_manager()
            if not self.auth_manager.initialized:
                await self.auth_manager.initialize()
        
        if not self.input_validator:
            self.input_validator = get_input_validator()
            if not self.input_validator.initialized:
                await self.input_validator.initialize()
        
        if not self.network_protection:
            self.network_protection = get_network_protection()
            if not self.network_protection.initialized:
                await self.network_protection.initialize()
        
        if not self.audit_system:
            self.audit_system = get_unified_audit_system()
            if not self.audit_system.initialized:
                await self.audit_system.initialize()
    
    async def _extract_request_info(self, request: Request) -> Dict[str, Any]:
        """Extract comprehensive request information."""
        # Get client IP
        client_ip = self._get_client_ip(request)
        
        # Get request body if present
        body = None
        if request.method in ['POST', 'PUT', 'PATCH']:
            try:
                body = await request.body()
                if body:
                    body = body.decode('utf-8')
            except Exception:
                body = None
        
        return {
            'client_ip': client_ip,
            'method': request.method,
            'path': str(request.url.path),
            'query_params': dict(request.query_params),
            'headers': dict(request.headers),
            'user_agent': request.headers.get('user-agent', ''),
            'content_type': request.headers.get('content-type', ''),
            'content_length': request.headers.get('content-length', 0),
            'body': body,
            'timestamp': datetime.now(timezone.utc)
        }
    
    def _get_client_ip(self, request: Request) -> str:
        """Get the real client IP address."""
        # Check for forwarded headers
        forwarded_for = request.headers.get('x-forwarded-for')
        if forwarded_for:
            return forwarded_for.split(',')[0].strip()
        
        real_ip = request.headers.get('x-real-ip')
        if real_ip:
            return real_ip
        
        # Fallback to direct connection
        if hasattr(request, 'client') and request.client:
            return request.client.host
        
        return 'unknown'
    
    def _get_security_level_for_path(self, path: str) -> int:
        """Get required security level for a path."""
        # Check exact matches first
        if path in self.endpoint_security_levels:
            return self.endpoint_security_levels[path]
        
        # Check prefix matches
        for endpoint_path, level in self.endpoint_security_levels.items():
            if path.startswith(endpoint_path):
                return level
        
        # Default to SECURE for API endpoints, PUBLIC for others
        if path.startswith('/api/'):
            return SecurityLevel.SECURE
        
        return SecurityLevel.PUBLIC

    async def _check_ip_security(self, request_info: Dict[str, Any]) -> Dict[str, Any]:
        """Check IP-based security (blacklists, geolocation, etc.)."""
        client_ip = request_info['client_ip']

        try:
            # Check if IP is valid
            try:
                ipaddress.ip_address(client_ip)
            except ValueError:
                return {
                    'allowed': False,
                    'reason': 'Invalid IP address',
                    'action': 'blocked'
                }

            # Check with network protection
            if self.network_protection:
                # Create a basic rate limit request for IP checking
                rate_request = RateLimitRequest(
                    ip_address=client_ip,
                    endpoint=request_info['path'],
                    method=request_info['method'],
                    user_agent=request_info['user_agent']
                )

                # This will check blacklists, whitelists, etc.
                allowed, threat = await self.network_protection.check_request(rate_request)

                if not allowed:
                    self.stats['blocked_requests'] += 1
                    await self._log_security_event(
                        SecurityEventType.SUSPICIOUS_ACTIVITY,
                        f"IP blocked by network protection: {threat.description if threat else 'Unknown reason'}",
                        SecuritySeverity.WARNING,
                        ThreatLevel.HIGH,
                        request_info
                    )

                    return {
                        'allowed': False,
                        'reason': f"IP blocked: {threat.description if threat else 'Security policy violation'}",
                        'action': 'blocked'
                    }

            return {'allowed': True}

        except Exception as e:
            logger.error(f"IP security check failed: {e}")
            return {'allowed': True}  # Fail open for availability

    async def _check_rate_limits(self, request_info: Dict[str, Any]) -> Dict[str, Any]:
        """Check rate limiting for the request."""
        try:
            path = request_info['path']
            client_ip = request_info['client_ip']

            # Get rate limit config for this path
            self.rate_limits.get(path, self.rate_limits['default'])

            # Use network protection for rate limiting
            if self.network_protection:
                rate_request = RateLimitRequest(
                    ip_address=client_ip,
                    endpoint=path,
                    method=request_info['method'],
                    user_agent=request_info['user_agent'],
                    size_bytes=int(request_info.get('content_length', 0))
                )

                allowed, threat = await self.network_protection.check_request(rate_request)

                if not allowed:
                    self.stats['rate_limit_violations'] += 1
                    await self._log_security_event(
                        SecurityEventType.RATE_LIMIT_EXCEEDED,
                        f"Rate limit exceeded for {client_ip} on {path}",
                        SecuritySeverity.WARNING,
                        ThreatLevel.MEDIUM,
                        request_info
                    )

                    return {
                        'allowed': False,
                        'reason': 'Rate limit exceeded',
                        'action': 'rate_limited',
                        'retry_after': 60
                    }

            return {'allowed': True}

        except Exception as e:
            logger.error(f"Rate limit check failed: {e}")
            return {'allowed': True}  # Fail open

    async def _validate_input_security(self, request: Request, request_info: Dict[str, Any]) -> Dict[str, Any]:
        """Validate input for security threats."""
        try:
            threats_detected = []

            # Check query parameters
            for key, value in request_info['query_params'].items():
                if self._detect_sql_injection(str(value)):
                    threats_detected.append(f"SQL injection in query parameter '{key}'")

                if self._detect_xss(str(value)):
                    threats_detected.append(f"XSS attempt in query parameter '{key}'")

            # Check request body
            if request_info['body']:
                body = request_info['body']

                if self._detect_sql_injection(body):
                    threats_detected.append("SQL injection in request body")

                if self._detect_xss(body):
                    threats_detected.append("XSS attempt in request body")

                # Use unified input validator for comprehensive validation
                if self.input_validator:
                    validation_result = self.input_validator.validate(
                        body,
                        InputType.TEXT,
                        ValidationLevel.STANDARD
                    )

                    if not validation_result.is_safe:
                        threats_detected.extend([
                            f"Input validation threat: {threat.value}"
                            for threat in validation_result.threats_detected
                        ])

            # Check headers for suspicious content
            user_agent = request_info['user_agent']
            if self._detect_malicious_user_agent(user_agent):
                threats_detected.append("Suspicious user agent detected")

            if threats_detected:
                self.stats['threats_detected'] += 1
                await self._log_security_event(
                    SecurityEventType.MALICIOUS_CONTENT,
                    f"Input security threats detected: {', '.join(threats_detected)}",
                    SecuritySeverity.WARNING,
                    ThreatLevel.HIGH,
                    request_info,
                    {"threats": threats_detected}
                )

                return {
                    'allowed': False,
                    'reason': f"Security threats detected: {', '.join(threats_detected)}",
                    'action': 'blocked',
                    'threats': threats_detected
                }

            return {'allowed': True}

        except Exception as e:
            logger.error(f"Input validation failed: {e}")
            return {'allowed': True}  # Fail open

    async def _check_authentication_authorization(self, request: Request, request_info: Dict[str, Any]) -> Dict[str, Any]:
        """Check authentication and authorization."""
        try:
            path = request_info['path']
            required_level = self._get_security_level_for_path(path)

            # Public endpoints don't require authentication
            if required_level == SecurityLevel.PUBLIC:
                return {'allowed': True}

            # Extract token from request
            token = self._extract_token(request)

            if not token:
                self.stats['auth_failures'] += 1
                await self._log_security_event(
                    SecurityEventType.AUTHENTICATION_FAILURE,
                    f"No authentication token provided for {path}",
                    SecuritySeverity.WARNING,
                    ThreatLevel.MEDIUM,
                    request_info
                )

                return {
                    'allowed': False,
                    'reason': 'Authentication required',
                    'action': 'unauthorized'
                }

            # Validate token with auth manager
            if self.auth_manager:
                from ....core_system.security.unified_auth_manager import (
                    SecurityLevel as AuthSecurityLevel,
                )

                # Map security levels
                auth_level_map = {
                    SecurityLevel.BASIC: AuthSecurityLevel.BASIC,
                    SecurityLevel.SECURE: AuthSecurityLevel.ENHANCED,
                    SecurityLevel.HIGH: AuthSecurityLevel.SECURE,
                    SecurityLevel.CRITICAL: AuthSecurityLevel.HIGH,
                    SecurityLevel.ADMIN: AuthSecurityLevel.CRITICAL
                }

                required_auth_level = auth_level_map.get(required_level, AuthSecurityLevel.BASIC)

                auth_result = await self.auth_manager.require_authentication(token, required_auth_level)

                if not auth_result.get('authenticated'):
                    self.stats['auth_failures'] += 1
                    await self._log_security_event(
                        SecurityEventType.AUTHORIZATION_FAILURE,
                        f"Authorization failed for {path}: {auth_result.get('error')}",
                        SecuritySeverity.WARNING,
                        ThreatLevel.MEDIUM,
                        request_info,
                        {"auth_error": auth_result.get('error')}
                    )

                    return {
                        'allowed': False,
                        'reason': f"Authorization failed: {auth_result.get('error')}",
                        'action': 'unauthorized'
                    }

                # Store user info in request state
                request.state.user_id = auth_result.get('user_id')
                request.state.security_level = auth_result.get('security_level')
                request.state.permissions = auth_result.get('permissions', [])

            return {'allowed': True}

        except Exception as e:
            logger.error(f"Authentication check failed: {e}")
            return {
                'allowed': False,
                'reason': 'Authentication system error',
                'action': 'error'
            }

    async def _check_endpoint_security(self, request: Request, request_info: Dict[str, Any]) -> Dict[str, Any]:
        """Check endpoint-specific security requirements."""
        try:
            path = request_info['path']
            method = request_info['method']

            # Admin endpoints require special handling
            if path.startswith('/admin') or path.startswith('/api/v1/admin'):
                # Check if user has admin permissions
                permissions = getattr(request.state, 'permissions', [])
                if 'admin' not in permissions and 'super_admin' not in permissions:
                    await self._log_security_event(
                        SecurityEventType.PRIVILEGE_ESCALATION,
                        f"Non-admin user attempted to access admin endpoint: {path}",
                        SecuritySeverity.CRITICAL,
                        ThreatLevel.HIGH,
                        request_info
                    )

                    return {
                        'allowed': False,
                        'reason': 'Admin privileges required',
                        'action': 'forbidden'
                    }

            # System endpoints require system permissions
            if path.startswith('/api/v1/system'):
                permissions = getattr(request.state, 'permissions', [])
                if 'system_config' not in permissions:
                    return {
                        'allowed': False,
                        'reason': 'System configuration privileges required',
                        'action': 'forbidden'
                    }

            # Destructive operations require additional verification
            if method in ['DELETE'] and path.startswith('/api/v1/'):
                # Log destructive operations
                await self._log_security_event(
                    SecurityEventType.DATA_DELETION,
                    f"Destructive operation attempted: {method} {path}",
                    SecuritySeverity.WARNING,
                    ThreatLevel.MEDIUM,
                    request_info
                )

            return {'allowed': True}

        except Exception as e:
            logger.error(f"Endpoint security check failed: {e}")
            return {'allowed': True}  # Fail open

    def _extract_token(self, request: Request) -> Optional[str]:
        """Extract authentication token from request."""
        # Check Authorization header
        auth_header = request.headers.get('authorization')
        if auth_header and auth_header.startswith('Bearer '):
            return auth_header[7:]  # Remove 'Bearer ' prefix

        # Check query parameter
        token = request.query_params.get('token')
        if token:
            return token

        # Check cookie
        token = request.cookies.get('access_token')
        if token:
            return token

        return None

    def _detect_sql_injection(self, text: str) -> bool:
        """Detect SQL injection patterns."""
        if not text:
            return False

        text_lower = text.lower()
        for pattern in self.sql_injection_patterns:
            if re.search(pattern, text_lower, re.IGNORECASE):
                return True
        return False

    def _detect_xss(self, text: str) -> bool:
        """Detect XSS patterns."""
        if not text:
            return False

        text_lower = text.lower()
        for pattern in self.xss_patterns:
            if re.search(pattern, text_lower, re.IGNORECASE):
                return True
        return False

    def _detect_malicious_user_agent(self, user_agent: str) -> bool:
        """Detect malicious user agents."""
        if not user_agent:
            return False

        malicious_patterns = [
            r'sqlmap',
            r'nikto',
            r'nmap',
            r'masscan',
            r'zap',
            r'burp',
            r'w3af',
            r'acunetix',
            r'nessus'
        ]

        user_agent_lower = user_agent.lower()
        for pattern in malicious_patterns:
            if re.search(pattern, user_agent_lower):
                return True

        return False

    def _create_security_response(self, check_result: Dict[str, Any], status_code: int) -> JSONResponse:
        """Create a security response for blocked requests."""
        reason = check_result.get('reason', 'Security policy violation')
        action = check_result.get('action', 'blocked')

        response_data = {
            'error': 'Security violation',
            'message': reason,
            'action': action,
            'timestamp': datetime.now(timezone.utc).isoformat()
        }

        # Add retry information for rate limiting
        if action == 'rate_limited':
            response_data['retry_after'] = check_result.get('retry_after', 60)

        # Add threat information if available
        if 'threats' in check_result:
            response_data['threats_detected'] = check_result['threats']

        headers = {}
        if action == 'rate_limited':
            headers['Retry-After'] = str(check_result.get('retry_after', 60))

        return JSONResponse(
            status_code=status_code,
            content=response_data,
            headers=headers
        )

    def _add_security_headers(self, response: Response):
        """Add security headers to response."""
        for header, value in self.security_headers.items():
            response.headers[header] = value

        # Add request processing headers
        response.headers['X-Security-Middleware'] = 'PlexiChat-Unified-Security'
        response.headers['X-Security-Version'] = '1.0'

    async def _log_security_event(self,
                                 event_type: SecurityEventType,
                                 description: str,
                                 severity: SecuritySeverity,
                                 threat_level: ThreatLevel,
                                 request_info: Dict[str, Any],
                                 details: Optional[Dict[str, Any]] = None):
        """Log security event to audit system."""
        try:
            if self.audit_system:
                self.audit_system.log_security_event(
                    event_type=event_type,
                    description=description,
                    severity=severity,
                    threat_level=threat_level,
                    user_id=request_info.get('user_id'),
                    source_ip=request_info.get('client_ip'),
                    user_agent=request_info.get('user_agent'),
                    resource=request_info.get('path'),
                    action=request_info.get('method'),
                    details=details or {}
                )
        except Exception as e:
            logger.error(f"Failed to log security event: {e}")

    def get_security_stats(self) -> Dict[str, Any]:
        """Get security middleware statistics."""
        return {
            'enabled': self.enabled,
            'stats': self.stats.copy(),
            'components_initialized': {
                'security_manager': self.security_manager is not None,
                'auth_manager': self.auth_manager is not None,
                'input_validator': self.input_validator is not None,
                'network_protection': self.network_protection is not None,
                'audit_system': self.audit_system is not None
            },
            'endpoint_security_levels': len(self.endpoint_security_levels),
            'rate_limit_configs': len(self.rate_limits)
        }

    async def get_security_status(self) -> Dict[str, Any]:
        """Get comprehensive security status."""
        await self._ensure_components_initialized()

        status = {
            'middleware': self.get_security_stats(),
            'components': {}
        }

        # Get component statuses
        if self.security_manager:
            status['components']['security_manager'] = await self.security_manager.get_status()

        if self.auth_manager:
            status['components']['auth_manager'] = await self.auth_manager.get_status()

        if self.input_validator:
            status['components']['input_validator'] = self.input_validator.get_status()

        if self.network_protection:
            status['components']['network_protection'] = self.network_protection.get_status()

        if self.audit_system:
            status['components']['audit_system'] = self.audit_system.get_status()

        return status


# Global instance - SINGLE SOURCE OF TRUTH
_unified_security_middleware: Optional[UnifiedSecurityMiddleware] = None


def get_unified_security_middleware() -> UnifiedSecurityMiddleware:
    """Get the global unified security middleware instance."""
    global _unified_security_middleware
    if _unified_security_middleware is None:
        _unified_security_middleware = UnifiedSecurityMiddleware(None)
    return _unified_security_middleware


# Export main components
__all__ = [
    "UnifiedSecurityMiddleware",
    "get_unified_security_middleware",
    "SecurityLevel"
]
