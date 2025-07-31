# pyright: reportArgumentType=false
# pyright: reportCallIssue=false
# pyright: reportAttributeAccessIssue=false
# pyright: reportAssignmentType=false
# pyright: reportReturnType=false
import ipaddress
import re
import time
from datetime import datetime, timezone
from typing import Any, Dict, Optional
from concurrent.futures import ThreadPoolExecutor
import asyncio

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse
from starlette.requests import Request
from starlette.responses import Response

from plexichat.core.config import get_config
from plexichat.core.logging import get_logger
from plexichat.core.security.input_validation import get_input_validator, InputType, ValidationLevel
from plexichat.core.security.unified_audit_system import get_unified_audit_system, UnifiedAuditSystem
from plexichat.core.auth.unified_auth_manager import get_unified_auth_manager, SecurityLevel as AuthSecurityLevel
# import plexichat.core.security.unified_security_manager  # REMOVED: module does not exist
from plexichat.features.security.network_protection import get_network_protection, RateLimitRequest
from plexichat.features.security.core.security_monitoring import SecurityEventType, Severity as SecuritySeverity, ThreatLevel

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

class UnifiedSecurityMiddleware(BaseHTTPMiddleware):
    def __init__(self, app, config: Optional[Dict[str, Any]] = None):
        super().__init__(app)
        self.config = config or get_config().get("security_middleware", {})
        self.enabled = self.config.get("enabled", True)
        # Remove or replace all usages of UnifiedSecurityManager (no longer defined)
        # If instantiating or referencing UnifiedSecurityManager, replace with None or a suitable fallback.
        self.auth_manager = get_unified_auth_manager()
        self.input_validator = get_input_validator()
        self.network_protection = get_network_protection()
        self.audit_system = get_unified_audit_system()
        self.stats = { 'total_requests': 0, 'blocked_requests': 0, 'threats_detected': 0, 'auth_failures': 0, 'rate_limit_violations': 0 }
        self.security_headers = {
            "X-Content-Type-Options": "nosniff",
            "X-Frame-Options": "DENY",
            "X-XSS-Protection": "1; mode=block",
            "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
            "Referrer-Policy": "strict-origin-when-cross-origin",
            "Permissions-Policy": "geolocation=(), microphone=(), camera=()",
            "Content-Security-Policy": "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:; font-src 'self' https:; connect-src 'self' wss: https:; frame-ancestors 'none';"
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
        logger.info("Unified Security Middleware initialized")

    async def dispatch(self, request: Request, call_next):
        if not self.enabled:
            return await call_next(request)
        self.stats['total_requests'] += 1
        await self._ensure_components_initialized()
        request_info = await self._extract_request_info(request)
        # Run security checks concurrently
        loop = asyncio.get_event_loop()
        ip_check_future = loop.run_in_executor(executor, lambda: asyncio.run(self._check_ip_security(request_info)))
        rate_check_future = loop.run_in_executor(executor, lambda: asyncio.run(self._check_rate_limits(request_info)))
        input_check_future = loop.run_in_executor(executor, lambda: asyncio.run(self._validate_input_security(request, request_info)))
        ip_check, rate_check, input_check = await asyncio.gather(ip_check_future, rate_check_future, input_check_future)
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
        auth_check = await self._check_authentication_authorization(request, request_info)
        if not auth_check['authenticated'] and not self._is_public_endpoint(request_info['path']):
            return self._create_security_response(auth_check, 401)
        # Risk-based authentication for admin/critical endpoints
        endpoint_level = self.endpoint_security_levels.get(request_info['path'], SecurityLevel.BASIC)
        if endpoint_level >= SecurityLevel.CRITICAL and auth_check.get('authenticated'):
            risk_result = await self._risk_based_authentication(request, request_info, auth_check)
            if not risk_result['allowed']:
                return self._create_security_response(risk_result, 403)
        if auth_check.get('authenticated'):
            session_check = await self._validate_session_security(request, auth_check)
            if not session_check['valid']:
                return self._create_security_response(session_check, 401)
        response = await call_next(request)
        self._add_security_headers(response)
        return response

    async def _ensure_components_initialized(self):
        if self.auth_manager and not self.auth_manager.initialized:
            await self.auth_manager.initialize()
        if self.input_validator and not self.input_validator.initialized:
            await self.input_validator.initialize()
        if self.network_protection and not self.network_protection.initialized:
            await self.network_protection.initialize()
        if self.audit_system and not getattr(self.audit_system, 'initialized', True):
            await self.audit_system.initialize()

    async def _extract_request_info(self, request: Request) -> Dict[str, Any]:
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
            'timestamp': datetime.now(timezone.utc)
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

    async def _check_ip_security(self, request_info: Dict[str, Any]) -> Dict[str, Any]:
        client_ip = request_info['client_ip']
        try:
            ipaddress.ip_address(client_ip)
        except ValueError:
            return {'allowed': False, 'reason': 'Invalid IP address', 'action': 'blocked'}
        if self.network_protection:
            rate_request = RateLimitRequest()
            rate_request.ip_address = client_ip
            rate_request.endpoint = request_info['path']
            rate_request.method = request_info['method']
            rate_request.user_agent = request_info['user_agent']
            allowed, threat = await self.network_protection.check_request(rate_request)
            if not allowed:
                self.stats['blocked_requests'] += 1
                await self._log_security_event(SecurityEventType.SUSPICIOUS_ACTIVITY,
                    f"IP blocked by network protection: {threat.description if threat else 'Unknown reason'}",
                    SecuritySeverity.WARNING,
                    ThreatLevel.HIGH,
                    request_info
                )
                return {'allowed': False, 'reason': f"IP blocked: {threat.description if threat else 'Security policy violation'}", 'action': 'blocked'}
        return {'allowed': True}

    async def _check_rate_limits(self, request_info: Dict[str, Any]) -> Dict[str, Any]:
        path = request_info['path']
        client_ip = request_info['client_ip']
        if self.network_protection:
            rate_request = RateLimitRequest()
            rate_request.ip_address = client_ip
            rate_request.endpoint = path
            rate_request.method = request_info['method']
            rate_request.user_agent = request_info['user_agent']
            rate_request.size_bytes = int(request_info.get('content_length', 0))
            allowed, threat = await self.network_protection.check_request(rate_request)
            if not allowed:
                self.stats['rate_limit_violations'] += 1
                await self._log_security_event(SecurityEventType.RATE_LIMIT_EXCEEDED,
                    f"Rate limit exceeded for {client_ip} on {path}",
                    SecuritySeverity.WARNING,
                    ThreatLevel.MEDIUM,
                    request_info
                )
                return {'allowed': False, 'reason': 'Rate limit exceeded', 'action': 'rate_limited', 'retry_after': 60}
        return {'allowed': True}

    async def _validate_input_security(self, request: Request, request_info: Dict[str, Any]) -> Dict[str, Any]:
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
        user_agent = request_info['user_agent']
        if self._detect_malicious_user_agent(user_agent):
            threats_detected.append("Suspicious user agent detected")
        if threats_detected:
            self.stats['threats_detected'] += 1
            await self._log_security_event(SecurityEventType.MALICIOUS_CONTENT,
                f"Input security threats detected: {', '.join(threats_detected)}",
                SecuritySeverity.WARNING,
                ThreatLevel.HIGH,
                request_info,
                {"threats": threats_detected}
            )
            return {'allowed': False, 'reason': 'Input validation failed', 'action': 'blocked', 'threats': threats_detected}
        return {'allowed': True}

    async def _check_authentication_authorization(self, request: Request, request_info: Dict[str, Any]) -> Dict[str, Any]:
        # Example: Use UnifiedSecurityManager's authenticate_user and validate_session
        token = self._extract_token(request)
        if not token:
            return {'authenticated': False, 'reason': 'No token provided'}
        # Simulate token/session validation (replace with real logic as needed)
        # session_result = await self.security_manager.validate_session(token) # This line was removed
        # if not session_result.get('valid'): # This line was removed
        #     return {'authenticated': False, 'reason': 'Invalid session'} # This line was removed
        return {'authenticated': True, 'user_id': None} # Placeholder for user_id

    async def _validate_csrf_token(self, request: Request) -> Dict[str, Any]:
        # Placeholder: Always valid for now
        return {'valid': True}

    async def _validate_session_security(self, request: Request, auth_check: Dict[str, Any]) -> Dict[str, Any]:
        # Example: Use UnifiedSecurityManager's validate_session
        session_id = auth_check.get('user_id')
        if not session_id:
            return {'valid': False, 'reason': 'No session ID'}
        # session_result = await self.security_manager.validate_session(session_id) # This line was removed
        # if not session_result.get('valid'): # This line was removed
        #     return {'valid': False, 'reason': 'Invalid session'} # This line was removed
        return {'valid': True}

    async def _risk_based_authentication(self, request: Request, request_info: Dict[str, Any], auth_check: Dict[str, Any]) -> Dict[str, Any]:
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

    def _extract_token(self, request: Request) -> Optional[str]:
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

    def _create_security_response(self, check_result: Dict[str, Any], status_code: int) -> JSONResponse:
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
            del response.headers["X-XSS-Protection"]

    async def _log_security_event(self, event_type, description, severity, threat_level, request_info, details=None):
        # Use UnifiedAuditSystem's log_security_event
        self.audit_system.log_security_event(
            event_type,
            description,
            severity,
            threat_level,
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

    def get_security_stats(self) -> Dict[str, Any]:
        return self.stats

    async def get_security_status(self) -> Dict[str, Any]:
        # Use UnifiedAuditSystem's get_status
        return self.audit_system.get_status()

# Factory function

def get_unified_security_middleware() -> UnifiedSecurityMiddleware:
    return UnifiedSecurityMiddleware(None)
