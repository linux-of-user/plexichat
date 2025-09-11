# pyright: reportArgumentType=false
# pyright: reportCallIssue=false
# pyright: reportAttributeAccessIssue=false
# pyright: reportAssignmentType=false
# pyright: reportReturnType=false
import asyncio
from collections.abc import Awaitable, Callable
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime
import ipaddress
import re
from typing import Any

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse, Response

from plexichat.core.authentication import get_auth_manager as get_unified_auth_manager
from plexichat.core.config import get_config
from plexichat.core.logging import get_logger
from plexichat.core.security import (
    InputType,
    RateLimitRequest,
    SecurityEventType,
    ThreatLevel,
    ValidationLevel,
    get_input_validator,
    get_network_protection,
)
from plexichat.core.security import Severity as SecuritySeverity
from plexichat.core.security.unified_audit_system import get_unified_audit_system

logger = get_logger(__name__)

# ThreadPoolExecutor for concurrent security checks
executor = ThreadPoolExecutor(max_workers=8)

class SecurityLevel:
    PUBLIC = 0
    BASIC = 1
    SECURE = 2
    HIGH = 3
    CRITICAL = 4
    ADMIN = 5

class SecurityMiddleware(BaseHTTPMiddleware):
    def __init__(self, app: Any, config: dict[str, Any] | None = None) -> None:
        super().__init__(app)
        self.config = config or get_config().get("security_middleware", {})
        self.enabled = self.config.get("enabled", True)
        # Use UnifiedAuthManager via get_unified_auth_manager()
        try:
            self.auth_manager = get_unified_auth_manager()
        except Exception as e:
            # Log this as a security-related initialization issue
            logger.security(f"Failed to obtain unified auth manager: {e}",
                            component="auth_manager", source="security_middleware")
            self.auth_manager = None
        self.input_validator = None
        try:
            self.input_validator = get_input_validator()
        except Exception:
            self.input_validator = None
        self.network_protection = None
        try:
            self.network_protection = get_network_protection()
        except Exception:
            self.network_protection = None
        try:
            self.audit_system = get_unified_audit_system()
        except Exception:
            self.audit_system = None
        self.stats = { 'total_requests': 0, 'blocked_requests': 0, 'threats_detected': 0, 'auth_failures': 0, 'rate_limit_violations': 0 }
        self.security_headers = {
            "X-Content-Type-Options": "nosniff",
            "X-Frame-Options": "DENY",
            "X-XSS-Protection": "1; mode=block",
            "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
            "Referrer-Policy": "strict-origin-when-cross-origin",
            "Permissions-Policy": "geolocation=(), microphone=(), camera=()",
            "Content-Security-Policy": "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https: https:; font-src 'self' https:; connect-src 'self' wss: https:; frame-ancestors 'none';"
        }
        self.endpoint_security_levels = {
            '/docs': SecurityLevel.PUBLIC,
            '/redoc': SecurityLevel.PUBLIC,
            '/openapi.json': SecurityLevel.PUBLIC,
            '/health': SecurityLevel.PUBLIC,
            '/status': SecurityLevel.PUBLIC,
            '/api/v1/auth/login': SecurityLevel.BASIC,
            '/api/v1/auth/register': SecurityLevel.BASIC,
            '/api/v1/auth/refresh': SecurityLevel.BASIC,
            '/api/v1/messages': SecurityLevel.SECURE,
            '/api/v1/files': SecurityLevel.SECURE,
            '/api/v1/users/profile': SecurityLevel.SECURE,
            '/api/v1/users/admin': SecurityLevel.HIGH,
            '/api/v1/system/config': SecurityLevel.HIGH,
            '/api/v1/admin': SecurityLevel.CRITICAL,
            '/api/v1/system/backup': SecurityLevel.CRITICAL,
            '/api/v1/system/cluster': SecurityLevel.CRITICAL,
            '/admin': SecurityLevel.ADMIN,
            '/api/v1/system/security': SecurityLevel.ADMIN
        }
        self.rate_limits = {
            'default': {'requests_per_minute': 60, 'burst': 10},
            '/api/v1/auth/login': {'requests_per_minute': 10, 'burst': 3},
            '/api/v1/auth/register': {'requests_per_minute': 5, 'burst': 2},
            '/api/v1/files/upload': {'requests_per_minute': 20, 'burst': 5},
            '/admin': {'requests_per_minute': 30, 'burst': 5}
        }
        logger.info("Security Middleware initialized")

    async def dispatch(self, request: Request, call_next: Callable[..., Awaitable[Response]]) -> Response:
        if not self.enabled:
            return await call_next(request)
        self.stats['total_requests'] += 1
        try:
            await self._ensure_components_initialized()
        except Exception as e:
            # Log initialization errors as security events with context
            logger.security(f"Error during middleware component initialization: {e}",
                            component="security_middleware")
        request_info = await self._extract_request_info(request)
        # Run security checks concurrently
        loop = asyncio.get_event_loop()
        ip_check_future = self._check_ip_security(request_info)
        rate_check_future = self._check_rate_limits(request_info)
        input_check_future = self._validate_input_security(request, request_info)
        try:
            ip_check, rate_check, input_check = await asyncio.gather(ip_check_future, rate_check_future, input_check_future)
        except Exception as e:
            logger.security(f"Error during concurrent security checks: {e}", component="security_checks")
            # Fail-safe: block the request if security checks cannot be completed
            return JSONResponse({'success': False, 'reason': 'Security checks failed', 'action': 'blocked'}, status_code=500)
        if not ip_check['allowed']:
            return self._create_security_response(ip_check, 403)
        if not rate_check['allowed']:
            return self._create_security_response(rate_check, 429)
        if not input_check['allowed']:
            return self._create_security_response(input_check, 400)
        # CSRF protection (sync for now)
        if request.method in ['POST', 'PUT', 'DELETE', 'PATCH']:
            csrf_check = await self._validate_csrf_token(request)
            if not csrf_check['valid']:
                return self._create_security_response(csrf_check, 403)
        # Authentication and authorization
        try:
            auth_check = await self._check_authentication_authorization(request, request_info)
        except Exception as e:
            logger.security(f"Authentication check error: {e}", component="authentication")
            self.stats['auth_failures'] += 1
            return self._create_security_response({'authenticated': False, 'reason': 'Authentication system error'}, 500)
        if not auth_check.get('authenticated') and not self._is_public_endpoint(request_info['path']):
            return self._create_security_response(auth_check, 401)
        # Risk-based authentication for admin/critical endpoints
        endpoint_level = self.endpoint_security_levels.get(request_info['path'], SecurityLevel.BASIC)
        if endpoint_level >= SecurityLevel.CRITICAL and auth_check.get('authenticated'):
            risk_result = await self._risk_based_authentication(request, request_info, auth_check)
            if not risk_result['allowed']:
                return self._create_security_response(risk_result, 403)
        if auth_check.get('authenticated'):
            try:
                session_check = await self._validate_session_security(request, auth_check)
            except Exception as e:
                logger.security(f"Session validation error: {e}", component="session_validation")
                return self._create_security_response({'valid': False, 'reason': 'Session validation failed'}, 401)
            if not session_check['valid']:
                return self._create_security_response(session_check, 401)
        response = await call_next(request)
        self._add_security_headers(response)
        return response

    async def _ensure_components_initialized(self):
        """
        Ensure that optional components (auth_manager, input_validator, network_protection, audit_system)
        are available and initialized if they expose an initialize method.
        Handles both sync and async initialize implementations gracefully.
        """
        components = {
            "auth_manager": self.auth_manager,
            "input_validator": self.input_validator,
            "network_protection": self.network_protection,
            "audit_system": self.audit_system
        }
        for name, comp in components.items():
            if not comp:
                continue
            try:
                # If component has attribute 'initialized' and it's truthy, skip initialization
                if getattr(comp, 'initialized', False):
                    continue
                init = getattr(comp, 'initialize', None)
                if init:
                    if asyncio.iscoroutinefunction(init):
                        await init()
                    else:
                        # run sync init in threadpool to avoid blocking event loop
                        loop = asyncio.get_event_loop()
                        await loop.run_in_executor(None, init)
            except Exception as e:
                logger.debug(f"Failed to initialize component {name}: {e}")

    async def _extract_request_info(self, request: Request) -> dict[str, Any]:
        client_ip = self._get_client_ip(request)
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
            'timestamp': datetime.now(UTC)
        }

    def _get_client_ip(self, request: Request) -> str:
        forwarded_for = request.headers.get('x-forwarded-for')
        if forwarded_for:
            return forwarded_for.split(',')[0].strip()
        real_ip = request.headers.get('x-real-ip')
        if real_ip:
            return real_ip
        if hasattr(request, 'client') and request.client:
            return request.client.host
        return 'unknown'

    def _is_public_endpoint(self, path: str) -> bool:
        if path in self.endpoint_security_levels:
            return self.endpoint_security_levels[path] == SecurityLevel.PUBLIC
        return False

    async def _check_ip_security(self, request_info: dict[str, Any]) -> dict[str, Any]:
        client_ip = request_info['client_ip']
        try:
            ipaddress.ip_address(client_ip)
        except ValueError:
            # Invalid IP address is a security concern
            logger.security("Invalid client IP address detected",
                            source_ip=client_ip, resource=request_info.get('path'))
            return {'allowed': False, 'reason': 'Invalid IP address', 'action': 'blocked'}
        if self.network_protection:
            try:
                rate_request = RateLimitRequest()
                rate_request.ip_address = client_ip
                rate_request.endpoint = request_info['path']
                rate_request.method = request_info['method']
                rate_request.user_agent = request_info['user_agent']
                allowed, threat = await self.network_protection.check_request(rate_request)
                if not allowed:
                    self.stats['blocked_requests'] += 1
                    # Log security event via unified logger with context
                    logger.security(f"IP blocked by network protection: {threat.description if threat else 'Unknown reason'}",
                                    user_id=request_info.get('user_id'),
                                    source_ip=client_ip,
                                    resource=request_info.get('path'),
                                    threat_level=getattr(threat, 'level', None),
                                    details={'threat': getattr(threat, 'description', None)})
                    await self._log_security_event(SecurityEventType.SUSPICIOUS_ACTIVITY,
                        f"IP blocked by network protection: {threat.description if threat else 'Unknown reason'}",
                        SecuritySeverity.WARNING,
                        ThreatLevel.HIGH,
                        request_info
                    )
                    return {'allowed': False, 'reason': f"IP blocked: {threat.description if threat else 'Security policy violation'}", 'action': 'blocked'}
            except Exception as e:
                logger.debug(f"Network protection check failed: {e}")
        return {'allowed': True}

    async def _check_rate_limits(self, request_info: dict[str, Any]) -> dict[str, Any]:
        path = request_info['path']
        client_ip = request_info['client_ip']
        if self.network_protection:
            try:
                rate_request = RateLimitRequest()
                rate_request.ip_address = client_ip
                rate_request.endpoint = path
                rate_request.method = request_info['method']
                rate_request.user_agent = request_info['user_agent']
                rate_request.size_bytes = int(request_info.get('content_length', 0))
                allowed, threat = await self.network_protection.check_request(rate_request)
                if not allowed:
                    self.stats['rate_limit_violations'] += 1
                    # Unified logging for rate-limit violations
                    logger.security(f"Rate limit exceeded for {client_ip} on {path}",
                                    user_id=request_info.get('user_id'),
                                    source_ip=client_ip,
                                    resource=path,
                                    details={'rate_limit': True})
                    await self._log_security_event(SecurityEventType.RATE_LIMIT_EXCEEDED,
                        f"Rate limit exceeded for {client_ip} on {path}",
                        SecuritySeverity.WARNING,
                        ThreatLevel.MEDIUM,
                        request_info
                    )
                    return {'allowed': False, 'reason': 'Rate limit exceeded', 'action': 'rate_limited', 'retry_after': 60}
            except Exception as e:
                logger.debug(f"Rate limit check failed: {e}")
        return {'allowed': True}

    async def _validate_input_security(self, request: Request, request_info: dict[str, Any]) -> dict[str, Any]:
        threats_detected = []
        for key, value in request_info['query_params'].items():
            if self._detect_sql_injection(str(value)):
                threats_detected.append(f"SQL injection in query parameter '{key}'")
            if self._detect_xss(str(value)):
                threats_detected.append(f"XSS attempt in query parameter '{key}'")
        if request_info['body']:
            body = request_info['body']
            if self._detect_sql_injection(body):
                threats_detected.append("SQL injection in request body")
            if self._detect_xss(body):
                threats_detected.append("XSS attempt in request body")
            if self.input_validator:
                try:
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
                except Exception as e:
                    logger.debug(f"Input validator error: {e}")
        user_agent = request_info['user_agent']
        if self._detect_malicious_user_agent(user_agent):
            threats_detected.append("Suspicious user agent detected")
        if threats_detected:
            self.stats['threats_detected'] += 1
            # Unified logging for detected threats
            logger.security(f"Input security threats detected: {', '.join(threats_detected)}",
                            user_id=request_info.get('user_id'),
                            source_ip=request_info.get('client_ip'),
                            resource=request_info.get('path'),
                            user_agent=user_agent,
                            details={'threats': threats_detected})
            await self._log_security_event(SecurityEventType.MALICIOUS_CONTENT,
                f"Input security threats detected: {', '.join(threats_detected)}",
                SecuritySeverity.WARNING,
                ThreatLevel.HIGH,
                request_info,
                {"threats": threats_detected}
            )
            return {'allowed': False, 'reason': 'Input validation failed', 'action': 'blocked', 'threats': threats_detected}
        return {'allowed': True}

    async def _check_authentication_authorization(self, request: Request, request_info: dict[str, Any]) -> dict[str, Any]:
        """
        Use UnifiedAuthManager for token and API key validation.
        Returns a dict with keys:
          - authenticated: bool
          - reason: optional reason string
          - user_id: optional user identifier
          - permissions: optional set/list of permissions
          - session_id: optional session id if available
        """
        token = self._extract_token(request)
        api_key = request.headers.get('x-api-key') or request.query_params.get('api_key')
        # If no token and no API key, it's unauthenticated
        if not token and not api_key:
            return {'authenticated': False, 'reason': 'No token provided'}
        try:
            # Prefer bearer token validation
            if token and self.auth_manager:
                valid, payload = await self.auth_manager.validate_token(token)
                if valid and payload:
                    user_id = payload.get('user_id') or payload.get('sub') or None
                    permissions = set(payload.get('permissions', [])) if payload.get('permissions') else set()
                    session_id = payload.get('session_id') if isinstance(payload, dict) else None
                    # Attach to request_info for auditing downstream
                    request_info['user_id'] = user_id
                    request_info['session_id'] = session_id
                    # Log successful token validation as audit/security info
                    logger.security("Token validated successfully",
                                    user_id=user_id,
                                    session_id=session_id,
                                    source_ip=request_info.get('client_ip'),
                                    resource=request_info.get('path'))
                    return {
                        'authenticated': True,
                        'user_id': user_id,
                        'permissions': permissions,
                        'session_id': session_id
                    }
                else:
                    self.stats['auth_failures'] += 1
                    logger.security("Invalid or expired token presented",
                                    source_ip=request_info.get('client_ip'),
                                    resource=request_info.get('path'),
                                    details={'token_present': True})
                    await self._log_security_event(SecurityEventType.AUTHENTICATION,
                                                  "Invalid or expired token presented",
                                                  SecuritySeverity.WARNING,
                                                  ThreatLevel.MEDIUM,
                                                  request_info,
                                                  details={'token_present': True})
                    return {'authenticated': False, 'reason': 'Invalid or expired token'}
            # Fallback to API key validation
            if api_key and self.auth_manager:
                api_result = await self.auth_manager.validate_api_key(api_key)
                if api_result:
                    user_id = api_result.get('user_id')
                    permissions = api_result.get('permissions', set())
                    request_info['user_id'] = user_id
                    request_info['session_id'] = None
                    logger.security("API key validated successfully",
                                    user_id=user_id,
                                    source_ip=request_info.get('client_ip'),
                                    resource=request_info.get('path'))
                    return {
                        'authenticated': True,
                        'user_id': user_id,
                        'permissions': permissions,
                        'session_id': None
                    }
                else:
                    self.stats['auth_failures'] += 1
                    logger.security("Invalid API key presented",
                                    source_ip=request_info.get('client_ip'),
                                    resource=request_info.get('path'),
                                    details={'api_key_present': True})
                    await self._log_security_event(SecurityEventType.AUTHENTICATION,
                                                  "Invalid API key presented",
                                                  SecuritySeverity.WARNING,
                                                  ThreatLevel.MEDIUM,
                                                  request_info,
                                                  details={'api_key_present': True})
                    return {'authenticated': False, 'reason': 'Invalid API key'}
        except Exception as e:
            # Log via unified logger and audit system
            logger.security(f"Error validating authentication: {e}",
                            source_ip=request_info.get('client_ip'),
                            resource=request_info.get('path'))
            self.stats['auth_failures'] += 1
            await self._log_security_event(SecurityEventType.AUTHENTICATION,
                                          f"Authentication validation error: {e!s}",
                                          SecuritySeverity.ERROR,
                                          ThreatLevel.HIGH,
                                          request_info)
            return {'authenticated': False, 'reason': 'Authentication validation error'}
        # If we reach here, not authenticated
        return {'authenticated': False, 'reason': 'Authentication failed'}

    async def _validate_csrf_token(self, request: Request) -> dict[str, Any]:
        """Validate CSRF token for state-changing requests."""
        try:
            # Skip CSRF for API endpoints with proper authentication
            if request.url.path.startswith('/api/') and request.headers.get('Authorization'):
                return {'valid': True}

            # Skip CSRF for safe methods
            if request.method in ['GET', 'HEAD', 'OPTIONS']:
                return {'valid': True}

            # Get CSRF token from various sources
            csrf_token = None

            # Check headers (most common for AJAX)
            csrf_headers = ['X-CSRF-Token', 'X-CSRFToken', 'CSRF-Token']
            for header in csrf_headers:
                csrf_token = request.headers.get(header)
                if csrf_token:
                    break

            # Check form data if no header token
            if not csrf_token:
                try:
                    if request.headers.get('content-type', '').startswith('application/x-www-form-urlencoded'):
                        form_data = await request.form()
                        csrf_token = form_data.get('csrf_token')
                    elif request.headers.get('content-type', '').startswith('application/json'):
                        json_data = await request.json()
                        csrf_token = json_data.get('csrf_token')
                except Exception:
                    pass

            # Check cookies for double-submit pattern
            cookie_token = request.cookies.get('csrf_token')

            if not csrf_token:
                return {
                    'valid': False,
                    'reason': 'CSRF token missing',
                    'required_headers': csrf_headers
                }

            # Validate token format (should be hex string of specific length)
            import re
            if not re.match(r'^[a-f0-9]{64}$', csrf_token):
                return {
                    'valid': False,
                    'reason': 'Invalid CSRF token format'
                }

            # For double-submit pattern, compare header/form token with cookie
            if cookie_token:
                if not self._constant_time_compare(csrf_token, cookie_token):
                    return {
                        'valid': False,
                        'reason': 'CSRF token mismatch'
                    }
            else:
                # If no cookie, validate against server-side storage
                # This is a simplified validation - in production, use proper session storage
                session_id = request.cookies.get('session_id')
                if not session_id:
                    return {
                        'valid': False,
                        'reason': 'No session for CSRF validation'
                    }

                # In a real implementation, you would validate against stored tokens
                # For now, we'll accept properly formatted tokens
                pass

            return {'valid': True}

        except Exception as e:
            logger.security(f"CSRF validation error: {e}", component="csrf_validation")
            return {
                'valid': False,
                'reason': 'CSRF validation failed'
            }

    def _constant_time_compare(self, a: str, b: str) -> bool:
        """Constant-time string comparison to prevent timing attacks."""
        if len(a) != len(b):
            return False

        result = 0
        for x, y in zip(a, b, strict=False):
            result |= ord(x) ^ ord(y)
        return result == 0

    async def _validate_session_security(self, request: Request, auth_check: dict[str, Any]) -> dict[str, Any]:
        """
        Validate session using UnifiedAuthManager.validate_session if session id is available.
        If only token-based auth is used and no session_id exists, allow by default (token already validated).
        """
        session_id = auth_check.get('session_id') or request.cookies.get('session_id') or None
        user_id = auth_check.get('user_id')
        # If no session id, and we have a user_id from token validation, treat as valid
        if not session_id:
            if user_id:
                return {'valid': True}
            return {'valid': False, 'reason': 'No session ID'}
        # Validate session via auth_manager
        if not self.auth_manager:
            logger.security("Authentication backend unavailable during session validation",
                            user_id=user_id, session_id=session_id)
            return {'valid': False, 'reason': 'Authentication backend unavailable'}
        try:
            valid, session_info = await self.auth_manager.validate_session(session_id)
            if not valid:
                self.stats['auth_failures'] += 1
                logger.security("Invalid session detected",
                                user_id=user_id, session_id=session_id,
                                source_ip=request.client.host if request.client else 'unknown',
                                resource=str(request.url.path))
                await self._log_security_event(SecurityEventType.AUTHENTICATION,
                                               "Invalid session detected",
                                               SecuritySeverity.WARNING,
                                               ThreatLevel.MEDIUM,
                                               {'client_ip': request.client.host if request.client else 'unknown', 'path': str(request.url.path)})
                return {'valid': False, 'reason': 'Invalid session'}
            # Optionally verify session user_id matches token user_id
            if user_id and session_info and getattr(session_info, 'user_id', None) != user_id:
                logger.security("Session user mismatch",
                                user_id=user_id,
                                session_id=session_id,
                                details={'session_user': getattr(session_info, 'user_id', None), 'token_user': user_id})
                await self._log_security_event(SecurityEventType.AUTHENTICATION,
                                               "Session user mismatch",
                                               SecuritySeverity.WARNING,
                                               ThreatLevel.MEDIUM,
                                               {'client_ip': request.client.host if request.client else 'unknown', 'path': str(request.url.path)},
                                               details={'session_user': getattr(session_info, 'user_id', None), 'token_user': user_id})
                return {'valid': False, 'reason': 'Session user mismatch'}
            return {'valid': True}
        except Exception as e:
            logger.security(f"Error validating session: {e}", component="session_validation")
            return {'valid': False, 'reason': 'Session validation error'}

    async def _risk_based_authentication(self, request: Request, request_info: dict[str, Any], auth_check: dict[str, Any]) -> dict[str, Any]:
        """Perform risk-based authentication for admin/critical endpoints."""
        # Example risk factors
        risk_score = 0.0
        risk_factors = []
        # Location anomaly (simulate with IP octet check)
        client_ip = request_info['client_ip']
        if client_ip and client_ip != 'unknown':
            if client_ip.startswith('10.') or client_ip.startswith('192.168.'):
                risk_score += 0.1  # Private IP, low risk
            else:
                risk_score += 0.3  # Public IP, higher risk
                risk_factors.append('Public IP address')
        # Device fingerprinting (user-agent)
        user_agent = request_info['user_agent']
        if 'Windows' not in user_agent and 'Macintosh' not in user_agent and 'Linux' not in user_agent:
            risk_score += 0.2
            risk_factors.append('Unknown device/user-agent')
        # Behavioral analysis (time of day, request rate)
        hour = request_info['timestamp'].hour
        if hour < 6 or hour > 22:
            risk_score += 0.2
            risk_factors.append('Unusual access time')
        # TODO: Add more behavioral analysis (e.g., request rate, geoip, device cookies)
        # Step-up authentication (MFA required if risk is high)
        mfa_required = risk_score >= 0.4
        mfa_passed = False
        if mfa_required:
            # Simulate MFA check (in production, integrate with real MFA system)
            mfa_token = request.headers.get('x-mfa-token') or request.query_params.get('mfa_token')
            if mfa_token == 'valid-mfa':
                mfa_passed = True
            else:
                risk_factors.append('MFA required')
        allowed = (not mfa_required) or (mfa_required and mfa_passed)
        # Log risk-based decision
        logger.security(f"Risk-based authentication for {request_info['path']} (risk_score={risk_score:.2f})",
                        user_id=request_info.get('user_id'),
                        source_ip=request_info.get('client_ip'),
                        resource=request_info.get('path'),
                        details={
                            'risk_score': risk_score,
                            'risk_factors': risk_factors,
                            'mfa_required': mfa_required,
                            'mfa_passed': mfa_passed
                        })
        await self._log_security_event(
            SecurityEventType.AUTHENTICATION,
            f"Risk-based authentication for {request_info['path']} (risk_score={risk_score:.2f})",
            SecuritySeverity.INFO if allowed else SecuritySeverity.WARNING,
            ThreatLevel.HIGH if risk_score >= 0.4 else ThreatLevel.MEDIUM,
            request_info,
            details={
                'risk_score': risk_score,
                'risk_factors': risk_factors,
                'mfa_required': mfa_required,
                'mfa_passed': mfa_passed
            }
        )
        if not allowed:
            return {
                'allowed': False,
                'reason': 'Risk-based authentication failed: ' + ', '.join(risk_factors),
                'action': 'step_up_auth',
                'risk_score': risk_score,
                'risk_factors': risk_factors
            }
        return {'allowed': True}

    def _extract_token(self, request: Request) -> str | None:
        auth_header = request.headers.get('authorization')
        if auth_header and auth_header.startswith('Bearer '):
            return auth_header[7:]
        token = request.query_params.get('token')
        if token:
            return token
        token = request.cookies.get('access_token')
        if token:
            return token
        return None

    def _detect_sql_injection(self, text: str) -> bool:
        patterns = [
            r"(\b(SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER|EXEC|UNION)\b)",
            r"(--|#|/\*|\*/)",
            r"(\b(OR|AND)\s+\d+\s*=\s*\d+)",
            r"(\bUNION\s+SELECT\b)",
            r"(\b(EXEC|EXECUTE)\s*\()",
            r"(\bxp_cmdshell\b)"
        ]
        for pattern in patterns:
            if re.search(pattern, text, re.IGNORECASE):
                return True
        return False

    def _detect_xss(self, text: str) -> bool:
        patterns = [r"<script[^>]*>.*?</script>", r"javascript:", r"vbscript:", r"on\w+\s*=", r"<iframe[^>]*>", r"<object[^>]*>"]
        for pattern in patterns:
            if re.search(pattern, text, re.IGNORECASE):
                return True
        return False

    def _detect_malicious_user_agent(self, user_agent: str) -> bool:
        patterns = [r"sqlmap", r"nmap", r"nikto", r"acunetix", r"nessus", r"w3af", r"metasploit", r"fuzz", r"scanner", r"bot", r"crawler"]
        for pattern in patterns:
            if re.search(pattern, user_agent, re.IGNORECASE):
                return True
        return False

    def _create_security_response(self, check_result: dict[str, Any], status_code: int) -> JSONResponse:
        return JSONResponse({
            'success': False,
            'reason': check_result.get('reason', 'Security check failed'),
            'action': check_result.get('action', 'blocked'),
            'threats': check_result.get('threats', []),
            'retry_after': check_result.get('retry_after')
        }, status_code=status_code)

    def _add_security_headers(self, response: Response):
        # Set all required security headers from security.txt
        response.headers["Strict-Transport-Security"] = "max-age=63072000; includeSubDomains; preload"
        response.headers["Content-Security-Policy"] = "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'"
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=(), payment=()"
        response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, private"
        response.headers["Pragma"] = "no-cache"
        response.headers["Expect-CT"] = "max-age=86400, enforce"
        # Remove deprecated X-XSS-Protection if present
        if "X-XSS-Protection" in response.headers:
            response.headers.delete("X-XSS-Protection")

    async def _log_security_event(self, event_type, description, severity, threat_level, request_info, details=None):
        """
        Use audit system's log_security_event if available.
        Handles both sync and async implementations of the audit system.

        Always log to the unified logger.security as a baseline so security events are not lost
        even if the audit system is unavailable.
        """
        try:
            # Prepare structured params for audit system and unified logger
            params = dict(
                event_type=event_type,
                description=description,
                severity=severity,
                threat_level=threat_level,
                user_id=request_info.get('user_id'),
                session_id=request_info.get('session_id'),
                source_ip=request_info.get('client_ip'),
                user_agent=request_info.get('user_agent'),
                resource=request_info.get('path'),
                action=request_info.get('method'),
                details=details or {},
                correlation_id=None,
                compliance_tags=None
            )

            # Log via unified security logger first
            try:
                logger.security(description,
                                user_id=params.get('user_id'),
                                session_id=params.get('session_id'),
                                source_ip=params.get('source_ip'),
                                user_agent=params.get('user_agent'),
                                resource=params.get('resource'),
                                action=params.get('action'),
                                threat_level=getattr(threat_level, 'name', str(threat_level)),
                                details=params.get('details'))
            except Exception:
                # Ensure unified logger failures don't break flow
                pass

            # Then delegate to audit system if available
            if self.audit_system:
                log_func = getattr(self.audit_system, 'log_security_event', None)
                if not log_func:
                    # If audit system lacks the method, still continue
                    return
                if asyncio.iscoroutinefunction(log_func):
                    await log_func(**params)
                else:
                    loop = asyncio.get_event_loop()
                    await loop.run_in_executor(None, lambda: log_func(**params))
            else:
                # If no audit system is present, record at debug that audit was skipped
                logger.debug("Audit system not available; security event logged to unified logger only")
        except Exception as e:
            # Ensure any errors in logging are captured in unified logs
            logger.debug(f"Failed to log security event: {e}")

    def get_security_stats(self) -> dict[str, Any]:
        return self.stats

    async def get_security_status(self) -> dict[str, Any]:
        # Use audit system's get_status if available
        try:
            if self.audit_system and hasattr(self.audit_system, 'get_status'):
                get_status = self.audit_system.get_status
                if asyncio.iscoroutinefunction(get_status):
                    return await get_status()
                else:
                    loop = asyncio.get_event_loop()
                    return await loop.run_in_executor(None, get_status)
        except Exception as e:
            logger.debug(f"Failed to retrieve audit system status: {e}")
        return {}

# Factory function

def get_security_middleware() -> SecurityMiddleware:
    return SecurityMiddleware(None)
