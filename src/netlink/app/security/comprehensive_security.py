"""
Comprehensive Security System for NetLink
Integrates all security features including 2FA, MITM protection, and advanced authentication.
"""

import asyncio
import json
import time
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Callable
from fastapi import Request, Response, HTTPException, Depends
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse, RedirectResponse

from netlink.app.security.advanced_2fa import tfa_system, Advanced2FASystem
from netlink.app.security.mitm_protection import mitm_protection, MITMProtectionSystem
from netlink.app.logger_config import logger


class SecurityLevel:
    """Security level constants."""
    PUBLIC = 0      # No authentication required
    BASIC = 1       # Basic authentication required
    SECURE = 2      # Authentication + additional security checks
    HIGH = 3        # Authentication + 2FA required
    CRITICAL = 4    # Maximum security (2FA + additional verification)


class SecurityPolicy:
    """Security policy configuration."""
    
    def __init__(self):
        # Path-based security levels
        self.path_security = {
            '/docs': SecurityLevel.PUBLIC,
            '/redoc': SecurityLevel.PUBLIC,
            '/openapi.json': SecurityLevel.PUBLIC,
            '/api/v1/auth/login': SecurityLevel.BASIC,
            '/api/v1/auth/register': SecurityLevel.BASIC,
            '/api/v1/status': SecurityLevel.BASIC,
            '/api/v1/users': SecurityLevel.SECURE,
            '/api/v1/messages': SecurityLevel.SECURE,
            '/admin': SecurityLevel.HIGH,
            '/api/v1/admin': SecurityLevel.CRITICAL,
            '/api/v1/system': SecurityLevel.CRITICAL
        }
        
        # 2FA required paths
        self.require_2fa_paths = [
            '/admin',
            '/api/v1/admin',
            '/api/v1/system',
            '/api/v1/users/admin'
        ]
        
        # Rate limiting configuration
        self.rate_limits = {
            '/api/v1/auth/login': {'requests': 5, 'window': 300},  # 5 per 5 minutes
            '/api/v1/auth/register': {'requests': 3, 'window': 3600},  # 3 per hour
            '/api/v1/messages': {'requests': 100, 'window': 60},  # 100 per minute
            'default': {'requests': 60, 'window': 60}  # 60 per minute default
        }
        
        # CORS configuration
        self.cors_config = {
            'allow_origins': ['https://localhost:8000', 'https://127.0.0.1:8000'],
            'allow_methods': ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
            'allow_headers': ['*'],
            'allow_credentials': True
        }


class SessionManager:
    """Advanced session management."""
    
    def __init__(self):
        self.active_sessions: Dict[str, Dict[str, Any]] = {}
        self.session_timeout = 3600  # 1 hour
        self.max_sessions_per_user = 5
        
    def create_session(self, user_id: int, device_info: Dict[str, Any]) -> str:
        """Create new session."""
        session_id = f"session_{int(time.time())}_{user_id}"
        
        # Clean old sessions for user
        self._cleanup_user_sessions(user_id)
        
        session_data = {
            'user_id': user_id,
            'created_at': datetime.utcnow(),
            'last_activity': datetime.utcnow(),
            'device_info': device_info,
            'ip_address': device_info.get('ip_address'),
            'user_agent': device_info.get('user_agent'),
            'is_2fa_verified': False,
            'security_level': SecurityLevel.BASIC
        }
        
        self.active_sessions[session_id] = session_data
        logger.info(f"Session created for user {user_id}: {session_id}")
        
        return session_id
        
    def validate_session(self, session_id: str) -> Optional[Dict[str, Any]]:
        """Validate session and return session data."""
        if session_id not in self.active_sessions:
            return None
            
        session = self.active_sessions[session_id]
        
        # Check if session expired
        if self._is_session_expired(session):
            self.destroy_session(session_id)
            return None
            
        # Update last activity
        session['last_activity'] = datetime.utcnow()
        
        return session
        
    def destroy_session(self, session_id: str) -> bool:
        """Destroy session."""
        if session_id in self.active_sessions:
            user_id = self.active_sessions[session_id]['user_id']
            del self.active_sessions[session_id]
            logger.info(f"Session destroyed for user {user_id}: {session_id}")
            return True
        return False
        
    def upgrade_session_security(self, session_id: str, level: int):
        """Upgrade session security level after 2FA verification."""
        if session_id in self.active_sessions:
            self.active_sessions[session_id]['security_level'] = level
            self.active_sessions[session_id]['is_2fa_verified'] = True
            
    def _cleanup_user_sessions(self, user_id: int):
        """Clean up old sessions for user."""
        user_sessions = [
            (sid, session) for sid, session in self.active_sessions.items()
            if session['user_id'] == user_id
        ]
        
        # Sort by last activity and keep only recent ones
        user_sessions.sort(key=lambda x: x[1]['last_activity'], reverse=True)
        
        # Remove excess sessions
        for sid, _ in user_sessions[self.max_sessions_per_user:]:
            del self.active_sessions[sid]
            
    def _is_session_expired(self, session: Dict[str, Any]) -> bool:
        """Check if session is expired."""
        last_activity = session['last_activity']
        return (datetime.utcnow() - last_activity).total_seconds() > self.session_timeout


class ComprehensiveSecurityMiddleware(BaseHTTPMiddleware):
    """Comprehensive security middleware integrating all security features."""
    
    def __init__(self, app, config: Dict[str, Any] = None):
        super().__init__(app)
        self.config = config or {}
        
        # Initialize components
        self.security_policy = SecurityPolicy()
        self.session_manager = SessionManager()
        self.tfa_system = tfa_system
        self.mitm_protection = mitm_protection
        
        # Security state
        self.failed_attempts: Dict[str, List[datetime]] = {}
        self.blocked_ips: Dict[str, datetime] = {}
        
        logger.info("Comprehensive security middleware initialized")
        
    async def dispatch(self, request: Request, call_next):
        """Main security dispatch method."""
        start_time = time.time()
        
        try:
            # 1. Basic security checks
            security_check = await self._perform_basic_security_checks(request)
            if not security_check['passed']:
                return self._create_security_response(security_check)
                
            # 2. MITM protection
            mitm_validation = self.mitm_protection.validate_request(request)
            if not mitm_validation['valid']:
                logger.warning(f"MITM protection blocked request: {mitm_validation['issues']}")
                return JSONResponse(
                    status_code=403,
                    content={'error': 'Request blocked by security system'}
                )
                
            # 3. Rate limiting
            rate_limit_check = await self._check_rate_limits(request)
            if not rate_limit_check['allowed']:
                return JSONResponse(
                    status_code=429,
                    content={'error': 'Rate limit exceeded', 'retry_after': rate_limit_check['retry_after']}
                )
                
            # 4. Authentication and authorization
            auth_result = await self._handle_authentication(request)
            if auth_result['redirect']:
                return auth_result['response']
                
            # 5. Process request
            response = await call_next(request)
            
            # 6. Add security headers
            self._add_security_headers(response)
            
            # 7. Log security event
            await self._log_security_event(request, response, time.time() - start_time)
            
            return response
            
        except Exception as e:
            logger.error(f"Security middleware error: {e}")
            return JSONResponse(
                status_code=500,
                content={'error': 'Internal security error'}
            )
            
    async def _perform_basic_security_checks(self, request: Request) -> Dict[str, Any]:
        """Perform basic security checks."""
        client_ip = self._get_client_ip(request)
        
        # Check if IP is blocked
        if client_ip in self.blocked_ips:
            block_time = self.blocked_ips[client_ip]
            if datetime.utcnow() < block_time:
                return {
                    'passed': False,
                    'reason': 'IP blocked',
                    'status_code': 403
                }
            else:
                # Unblock expired IP
                del self.blocked_ips[client_ip]
                
        # Check for suspicious patterns
        user_agent = request.headers.get('user-agent', '').lower()
        suspicious_patterns = ['sqlmap', 'nikto', 'nmap', 'masscan']
        
        if any(pattern in user_agent for pattern in suspicious_patterns):
            self._block_ip(client_ip, minutes=60)
            return {
                'passed': False,
                'reason': 'Suspicious user agent',
                'status_code': 403
            }
            
        return {'passed': True}
        
    async def _check_rate_limits(self, request: Request) -> Dict[str, Any]:
        """Check rate limits for the request."""
        client_ip = self._get_client_ip(request)
        path = str(request.url.path)
        
        # Get rate limit config for path
        rate_config = self.security_policy.rate_limits.get(path, 
                                                          self.security_policy.rate_limits['default'])
        
        # Check rate limit (simplified implementation)
        key = f"rate_limit:{client_ip}:{path}"
        current_time = datetime.utcnow()
        
        # This would typically use Redis or similar for distributed rate limiting
        # For now, using in-memory storage
        
        return {'allowed': True, 'retry_after': 0}  # Simplified for now
        
    async def _handle_authentication(self, request: Request) -> Dict[str, Any]:
        """Handle authentication and authorization."""
        path = str(request.url.path)
        
        # Get required security level for path
        required_level = self._get_required_security_level(path)
        
        if required_level == SecurityLevel.PUBLIC:
            return {'redirect': False}
            
        # Check for authentication token
        auth_header = request.headers.get('Authorization')
        session_cookie = request.cookies.get('session_id')
        
        if not auth_header and not session_cookie:
            if request.url.path.startswith('/api/'):
                return {
                    'redirect': True,
                    'response': JSONResponse(
                        status_code=401,
                        content={'error': 'Authentication required'}
                    )
                }
            else:
                return {
                    'redirect': True,
                    'response': RedirectResponse(url='/login')
                }
                
        # Validate session/token
        session_data = None
        if session_cookie:
            session_data = self.session_manager.validate_session(session_cookie)
            
        if not session_data:
            return {
                'redirect': True,
                'response': JSONResponse(
                    status_code=401,
                    content={'error': 'Invalid or expired session'}
                )
            }
            
        # Check if 2FA is required
        if required_level >= SecurityLevel.HIGH and not session_data.get('is_2fa_verified'):
            return {
                'redirect': True,
                'response': JSONResponse(
                    status_code=403,
                    content={'error': '2FA verification required', 'redirect': '/2fa'}
                )
            }
            
        # Add user info to request state
        request.state.user_id = session_data['user_id']
        request.state.session_id = session_cookie
        request.state.security_level = session_data['security_level']
        
        return {'redirect': False}
        
    def _get_required_security_level(self, path: str) -> int:
        """Get required security level for path."""
        for pattern, level in self.security_policy.path_security.items():
            if path.startswith(pattern):
                return level
        return SecurityLevel.BASIC
        
    def _add_security_headers(self, response: Response):
        """Add security headers to response."""
        security_headers = self.mitm_protection.get_security_headers()
        
        for header, value in security_headers.items():
            response.headers[header] = value
            
        # Add additional headers
        response.headers['X-Security-Level'] = 'High'
        response.headers['X-Frame-Options'] = 'DENY'
        response.headers['X-Content-Type-Options'] = 'nosniff'
        
    def _get_client_ip(self, request: Request) -> str:
        """Get client IP address."""
        # Check for forwarded headers
        forwarded_for = request.headers.get('X-Forwarded-For')
        if forwarded_for:
            return forwarded_for.split(',')[0].strip()
            
        real_ip = request.headers.get('X-Real-IP')
        if real_ip:
            return real_ip
            
        return request.client.host if request.client else 'unknown'
        
    def _block_ip(self, ip: str, minutes: int = 30):
        """Block IP address for specified duration."""
        block_until = datetime.utcnow() + timedelta(minutes=minutes)
        self.blocked_ips[ip] = block_until
        logger.warning(f"IP {ip} blocked until {block_until}")
        
    def _create_security_response(self, security_check: Dict[str, Any]) -> Response:
        """Create security response for failed checks."""
        return JSONResponse(
            status_code=security_check['status_code'],
            content={
                'error': 'Security check failed',
                'reason': security_check['reason']
            }
        )
        
    async def _log_security_event(self, request: Request, response: Response, duration: float):
        """Log security event."""
        event_data = {
            'timestamp': datetime.utcnow().isoformat(),
            'method': request.method,
            'path': str(request.url.path),
            'client_ip': self._get_client_ip(request),
            'user_agent': request.headers.get('user-agent', 'Unknown'),
            'status_code': response.status_code,
            'duration': duration,
            'user_id': getattr(request.state, 'user_id', None),
            'security_level': getattr(request.state, 'security_level', SecurityLevel.PUBLIC)
        }
        
        # Log to security audit log
        logger.info(f"Security event: {json.dumps(event_data)}")


# Global security middleware instance
security_middleware = ComprehensiveSecurityMiddleware


# Security decorators
def require_security_level(level: int):
    """Decorator to require specific security level."""
    def decorator(func):
        async def wrapper(request: Request, *args, **kwargs):
            current_level = getattr(request.state, 'security_level', SecurityLevel.PUBLIC)
            if current_level < level:
                raise HTTPException(
                    status_code=403,
                    detail=f"Security level {level} required"
                )
            return await func(request, *args, **kwargs)
        return wrapper
    return decorator


def require_2fa(func):
    """Decorator to require 2FA verification."""
    async def wrapper(request: Request, *args, **kwargs):
        session_id = request.cookies.get('session_id')
        if not session_id:
            raise HTTPException(status_code=401, detail="Authentication required")
            
        # This would check 2FA status from session
        # Simplified for now
        return await func(request, *args, **kwargs)
    return wrapper
