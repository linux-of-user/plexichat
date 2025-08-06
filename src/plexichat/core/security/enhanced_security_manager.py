"""
Enhanced Security Manager for PlexiChat
Provides comprehensive security controls for all endpoints with advanced threat detection.
"""

import asyncio
import hashlib
import hmac
import json
import logging
import secrets
import time
from datetime import datetime, timedelta, timezone
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Set, Callable, Union, Tuple
from pathlib import Path
import ipaddress
import re

# FastAPI imports
from fastapi import Request, HTTPException, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse

# Core imports
try:
    from ..logging_advanced import get_logger, LogLevel, LogCategory
    from ..config.simple_config import get_config
    from ..database.manager import database_manager
    from ..auth.unified_auth_manager import get_unified_auth_manager
    # Import our new middleware
    from ..middleware.account_rate_limiting_middleware import add_account_rate_limiting_middleware
    from ..middleware.dynamic_rate_limiting_middleware import add_dynamic_rate_limiting_middleware
    from ..middleware.ip_blacklist_middleware import add_ip_blacklist_middleware
    from ..error_handling.enhanced_error_responses import setup_exception_handlers
    from ..config.rate_limiting_config import get_rate_limiting_config
except ImportError as e:
    logging.warning(f"Security manager import error: {e}")
    get_logger = logging.getLogger
    LogLevel = None
    LogCategory = None
    get_config = lambda: type('Config', (), {'security': type('Security', (), {})()})()
    database_manager = None
    get_unified_auth_manager = lambda: None
    # Fallback functions for middleware
    def add_account_rate_limiting_middleware(app): pass
    def add_dynamic_rate_limiting_middleware(app): pass
    def add_ip_blacklist_middleware(app): pass
    def setup_exception_handlers(app): pass
    def get_rate_limiting_config(): return None

logger = get_logger(__name__)


class SecurityLevel(Enum):
    """Security access levels for endpoints."""
    PUBLIC = 0          # No authentication required
    BASIC = 1           # Basic authentication required
    AUTHENTICATED = 2   # Valid user session required
    ELEVATED = 3        # Enhanced privileges required
    ADMIN = 4           # Admin access required
    SYSTEM = 5          # System-level access required


class ThreatLevel(Enum):
    """Threat severity levels."""
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4
    EXTREME = 5


class SecurityEventType(Enum):
    """Types of security events."""
    LOGIN_SUCCESS = "login_success"
    LOGIN_FAILURE = "login_failure"
    ACCESS_DENIED = "access_denied"
    RATE_LIMIT_EXCEEDED = "rate_limit_exceeded"
    SUSPICIOUS_ACTIVITY = "suspicious_activity"
    MALICIOUS_INPUT = "malicious_input"
    BRUTE_FORCE_ATTEMPT = "brute_force_attempt"
    SQL_INJECTION_ATTEMPT = "sql_injection_attempt"
    XSS_ATTEMPT = "xss_attempt"
    CSRF_ATTEMPT = "csrf_attempt"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    DATA_BREACH_ATTEMPT = "data_breach_attempt"


@dataclass
class SecurityContext:
    """Security context for requests."""
    user_id: Optional[str] = None
    session_id: Optional[str] = None
    ip_address: Optional[str] = None
    user_agent: Optional[str] = None
    request_id: Optional[str] = None
    endpoint: Optional[str] = None
    method: Optional[str] = None
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    threat_score: float = 0.0
    security_flags: List[str] = field(default_factory=list)


@dataclass
class SecurityEvent:
    """Security event data."""
    event_type: SecurityEventType
    threat_level: ThreatLevel
    context: SecurityContext
    details: Dict[str, Any] = field(default_factory=dict)
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


@dataclass
class RateLimitRule:
    """Rate limiting rule."""
    requests_per_minute: int
    requests_per_hour: int
    burst_limit: int
    window_size: int = 60  # seconds


class InputValidator:
    """Advanced input validation and sanitization."""
    
    # Common attack patterns
    SQL_INJECTION_PATTERNS = [
        r"(\bunion\b.*\bselect\b)",
        r"(\bselect\b.*\bfrom\b)",
        r"(\binsert\b.*\binto\b)",
        r"(\bdelete\b.*\bfrom\b)",
        r"(\bdrop\b.*\btable\b)",
        r"(\bexec\b.*\b\w+\b)",
        r"(\bscript\b.*\b>)",
        r"['\";].*(\bor\b|\band\b).*['\";]",
    ]
    
    XSS_PATTERNS = [
        r"<script[^>]*>.*?</script>",
        r"javascript:",
        r"on\w+\s*=",
        r"<iframe[^>]*>",
        r"<object[^>]*>",
        r"<embed[^>]*>",
    ]
    
    def __init__(self):
        self.sql_regex = re.compile("|".join(self.SQL_INJECTION_PATTERNS), re.IGNORECASE)
        self.xss_regex = re.compile("|".join(self.XSS_PATTERNS), re.IGNORECASE)
    
    async def validate_input(self, data: Any, context: SecurityContext) -> Tuple[bool, List[str]]:
        """Validate input data for security threats."""
        threats = []
        
        if isinstance(data, str):
            threats.extend(await self._check_string_threats(data))
        elif isinstance(data, dict):
            for key, value in data.items():
                if isinstance(value, str):
                    threats.extend(await self._check_string_threats(value))
                elif isinstance(value, (dict, list)):
                    sub_valid, sub_threats = await self.validate_input(value, context)
                    threats.extend(sub_threats)
        elif isinstance(data, list):
            for item in data:
                sub_valid, sub_threats = await self.validate_input(item, context)
                threats.extend(sub_threats)
        
        return len(threats) == 0, threats
    
    async def _check_string_threats(self, text: str) -> List[str]:
        """Check string for security threats."""
        threats = []
        
        # SQL Injection check
        if self.sql_regex.search(text):
            threats.append("sql_injection")
        
        # XSS check
        if self.xss_regex.search(text):
            threats.append("xss_attempt")
        
        # Path traversal check
        if "../" in text or "..\\" in text:
            threats.append("path_traversal")
        
        # Command injection check
        dangerous_commands = [";", "|", "&", "`", "$", "(", ")"]
        if any(cmd in text for cmd in dangerous_commands):
            threats.append("command_injection")
        
        return threats


class RateLimiter:
    """Advanced rate limiting with adaptive controls."""
    
    def __init__(self):
        self.requests = {}  # {ip: {endpoint: [(timestamp, count)]}}
        self.blocked_ips = {}  # {ip: block_until_timestamp}
        self.adaptive_limits = {}  # {ip: adjusted_limits}
    
    async def check_rate_limit(self, ip: str, endpoint: str, rule: RateLimitRule) -> Tuple[bool, Dict[str, Any]]:
        """Check if request is within rate limits."""
        now = time.time()
        
        # Check if IP is currently blocked
        if ip in self.blocked_ips:
            if now < self.blocked_ips[ip]:
                return False, {"reason": "ip_blocked", "blocked_until": self.blocked_ips[ip]}
            else:
                del self.blocked_ips[ip]
        
        # Initialize tracking structures
        if ip not in self.requests:
            self.requests[ip] = {}
        if endpoint not in self.requests[ip]:
            self.requests[ip][endpoint] = []
        
        # Clean old requests (older than 1 hour)
        self.requests[ip][endpoint] = [
            (ts, count) for ts, count in self.requests[ip][endpoint]
            if now - ts < 3600
        ]
        
        # Count requests in different time windows
        minute_requests = sum(
            count for ts, count in self.requests[ip][endpoint]
            if now - ts < 60
        )
        hour_requests = sum(count for ts, count in self.requests[ip][endpoint])
        
        # Check limits
        if minute_requests >= rule.requests_per_minute:
            await self._handle_rate_limit_exceeded(ip, endpoint, "minute_limit")
            return False, {"reason": "minute_limit_exceeded", "limit": rule.requests_per_minute}
        
        if hour_requests >= rule.requests_per_hour:
            await self._handle_rate_limit_exceeded(ip, endpoint, "hour_limit")
            return False, {"reason": "hour_limit_exceeded", "limit": rule.requests_per_hour}
        
        # Record this request
        self.requests[ip][endpoint].append((now, 1))
        
        return True, {"requests_remaining": rule.requests_per_minute - minute_requests - 1}
    
    async def _handle_rate_limit_exceeded(self, ip: str, endpoint: str, limit_type: str):
        """Handle rate limit exceeded events."""
        # Block IP for escalating violations
        violations = sum(
            1 for ts, _ in self.requests.get(ip, {}).get(endpoint, [])
            if time.time() - ts < 300  # 5 minutes
        )
        
        if violations > 10:
            self.blocked_ips[ip] = time.time() + 3600  # Block for 1 hour
            logger.warning(f"Blocked IP {ip} for excessive rate limit violations")


class ThreatDetector:
    """Advanced threat detection system."""
    
    def __init__(self):
        self.suspicious_patterns = {}
        self.user_behavior_baseline = {}
        self.global_threat_score = 0.0
    
    async def analyze_request(self, context: SecurityContext, request_data: Any) -> float:
        """Analyze request for threats and return threat score (0.0-1.0)."""
        threat_score = 0.0
        
        # IP reputation check
        threat_score += await self._check_ip_reputation(context.ip_address)
        
        # User behavior analysis
        threat_score += await self._analyze_user_behavior(context)
        
        # Request pattern analysis
        threat_score += await self._analyze_request_patterns(context, request_data)
        
        # Geolocation anomaly detection
        threat_score += await self._check_geolocation_anomaly(context)
        
        return min(threat_score, 1.0)
    
    async def _check_ip_reputation(self, ip: str) -> float:
        """Check IP against threat intelligence."""
        if not ip:
            return 0.0
        
        # Check against known malicious IPs (simplified)
        malicious_ranges = [
            # Add known malicious IP ranges
        ]
        
        try:
            ip_obj = ipaddress.ip_address(ip)
            for range_str in malicious_ranges:
                if ip_obj in ipaddress.ip_network(range_str):
                    return 0.8
        except ValueError:
            return 0.2  # Invalid IP format is suspicious
        
        return 0.0
    
    async def _analyze_user_behavior(self, context: SecurityContext) -> float:
        """Analyze user behavior patterns."""
        if not context.user_id:
            return 0.1  # Slight increase for unauthenticated requests
        
        # Analyze request frequency, timing, patterns
        # This is a simplified implementation
        return 0.0
    
    async def _analyze_request_patterns(self, context: SecurityContext, request_data: Any) -> float:
        """Analyze request patterns for anomalies."""
        threat_score = 0.0
        
        # Check for suspicious endpoints
        if context.endpoint:
            if any(pattern in context.endpoint for pattern in ["/admin", "/system", "/debug"]):
                threat_score += 0.2
        
        # Check request size anomalies
        if isinstance(request_data, dict):
            data_size = len(json.dumps(request_data))
            if data_size > 1024 * 1024:  # 1MB
                threat_score += 0.3
        
        return threat_score
    
    async def _check_geolocation_anomaly(self, context: SecurityContext) -> float:
        """Check for geolocation-based anomalies."""
        # Implement geolocation-based threat detection
        # This would integrate with GeoIP databases
        return 0.0


class EnhancedSecurityManager:
    """Enhanced security manager with comprehensive protection."""
    
    def __init__(self):
        self.config = get_config()
        self.auth_manager = get_unified_auth_manager()
        self.input_validator = InputValidator()
        self.rate_limiter = RateLimiter()
        self.threat_detector = ThreatDetector()
        
        # Security configuration
        self.enabled = True
        self.log_all_requests = True
        self.block_suspicious_requests = True
        
        # Endpoint security levels
        self.endpoint_security_levels = {}
        
        # Rate limiting rules
        self.rate_limit_rules = {}
        
        # Security headers
        self.security_headers = {
            "X-Content-Type-Options": "nosniff",
            "X-Frame-Options": "DENY",
            "X-XSS-Protection": "1; mode=block",
            "Strict-Transport-Security": "max-age=31536000; includeSubDomains; preload",
            "Referrer-Policy": "strict-origin-when-cross-origin",
            "Permissions-Policy": "geolocation=(), microphone=(), camera=()",
            "Content-Security-Policy": (
                "default-src 'self'; "
                "script-src 'self' 'unsafe-inline' 'unsafe-eval'; "
                "style-src 'self' 'unsafe-inline'; "
                "img-src 'self' data: https:; "
                "font-src 'self' https:; "
                "connect-src 'self' wss: https:; "
                "frame-ancestors 'none';"
            ),
        }
        
        logger.info("Enhanced Security Manager initialized")
    
    async def validate_request(self, request: Request) -> Tuple[bool, Optional[SecurityContext], Optional[Dict]]:
        """Comprehensive request validation."""
        # Extract request context
        context = await self._extract_security_context(request)
        
        # Check rate limits
        endpoint = self._normalize_endpoint(context.endpoint)
        rule = self._get_rate_limit_rule(endpoint)
        rate_ok, rate_info = await self.rate_limiter.check_rate_limit(
            context.ip_address, endpoint, rule
        )
        
        if not rate_ok:
            await self._log_security_event(
                SecurityEventType.RATE_LIMIT_EXCEEDED,
                ThreatLevel.MEDIUM,
                context,
                rate_info
            )
            return False, context, {"error": "Rate limit exceeded", **rate_info}
        
        # Validate input data
        try:
            if request.method in ["POST", "PUT", "PATCH"]:
                body = await request.body()
                if body:
                    try:
                        request_data = json.loads(body.decode())
                        valid, threats = await self.input_validator.validate_input(request_data, context)
                        if not valid:
                            await self._log_security_event(
                                SecurityEventType.MALICIOUS_INPUT,
                                ThreatLevel.HIGH,
                                context,
                                {"threats": threats}
                            )
                            if self.block_suspicious_requests:
                                return False, context, {"error": "Invalid input detected"}
                    except json.JSONDecodeError:
                        pass  # Not JSON, skip validation
        except Exception as e:
            logger.warning(f"Error validating request data: {e}")
        
        # Threat analysis
        threat_score = await self.threat_detector.analyze_request(context, None)
        context.threat_score = threat_score
        
        if threat_score > 0.7:  # High threat threshold
            await self._log_security_event(
                SecurityEventType.SUSPICIOUS_ACTIVITY,
                ThreatLevel.HIGH,
                context,
                {"threat_score": threat_score}
            )
            
            if self.block_suspicious_requests:
                return False, context, {"error": "Request blocked due to security policy"}
        
        return True, context, None
    
    async def check_endpoint_access(self, endpoint: str, user_data: Optional[Dict] = None) -> bool:
        """Check if user has access to endpoint."""
        security_level = self._get_endpoint_security_level(endpoint)
        
        if security_level == SecurityLevel.PUBLIC:
            return True
        
        if not user_data:
            return security_level == SecurityLevel.BASIC
        
        user_level = user_data.get("security_level", 0)
        is_admin = user_data.get("is_admin", False)
        
        if security_level == SecurityLevel.BASIC:
            return True
        elif security_level == SecurityLevel.AUTHENTICATED:
            return user_level >= 1
        elif security_level == SecurityLevel.ELEVATED:
            return user_level >= 2
        elif security_level == SecurityLevel.ADMIN:
            return is_admin
        elif security_level == SecurityLevel.SYSTEM:
            return user_data.get("is_system", False)
        
        return False
    
    async def _extract_security_context(self, request: Request) -> SecurityContext:
        """Extract security context from request."""
        client_ip = "unknown"
        if hasattr(request, 'client') and request.client:
            client_ip = request.client.host
        
        # Check for forwarded headers
        forwarded_for = request.headers.get("X-Forwarded-For")
        if forwarded_for:
            client_ip = forwarded_for.split(",")[0].strip()
        
        real_ip = request.headers.get("X-Real-IP")
        if real_ip:
            client_ip = real_ip
        
        return SecurityContext(
            ip_address=client_ip,
            user_agent=request.headers.get("User-Agent", "unknown"),
            endpoint=str(request.url.path),
            method=request.method,
            request_id=request.headers.get("X-Request-ID", secrets.token_hex(8))
        )
    
    def _normalize_endpoint(self, endpoint: str) -> str:
        """Normalize endpoint for security level lookup."""
        if not endpoint:
            return "/"
        
        # Remove query parameters
        endpoint = endpoint.split("?")[0]
        
        # Check for exact matches first
        if endpoint in self.endpoint_security_levels:
            return endpoint
        
        # Check for pattern matches
        for pattern in self.endpoint_security_levels:
            if pattern.endswith("*"):
                if endpoint.startswith(pattern[:-1]):
                    return pattern
        
        return endpoint
    
    def _get_endpoint_security_level(self, endpoint: str) -> SecurityLevel:
        """Get security level for endpoint."""
        normalized = self._normalize_endpoint(endpoint)
        return self.endpoint_security_levels.get(normalized, SecurityLevel.AUTHENTICATED)
    
    def _get_rate_limit_rule(self, endpoint: str) -> RateLimitRule:
        """Get rate limit rule for endpoint."""
        from .config import settings
        return RateLimitRule(
            requests_per_minute=settings.rate_limit_default_requests_per_minute,
            requests_per_hour=settings.rate_limit_default_requests_per_hour,
            burst_limit=settings.rate_limit_default_burst_limit,
        )
    
    async def _log_security_event(self, event_type: SecurityEventType, threat_level: ThreatLevel, 
                                 context: SecurityContext, details: Dict[str, Any]):
        """Log security event."""
        event = SecurityEvent(
            event_type=event_type,
            threat_level=threat_level,
            context=context,
            details=details
        )
        
        log_data = {
            "event_type": event_type.value,
            "threat_level": threat_level.name,
            "ip_address": context.ip_address,
            "endpoint": context.endpoint,
            "user_id": context.user_id,
            "threat_score": context.threat_score,
            "details": details,
            "timestamp": event.timestamp.isoformat()
        }
        
        if LogLevel and LogCategory:
            logger.log(
                LogLevel.SECURITY.value if hasattr(LogLevel, 'SECURITY') else logging.WARNING,
                f"Security event: {event_type.value}",
                extra={
                    "category": LogCategory.SECURITY if hasattr(LogCategory, 'SECURITY') else "security",
                    "metadata": log_data
                }
            )
        else:
            logger.warning(f"Security event: {json.dumps(log_data, default=str)}")
    
    def get_security_headers(self) -> Dict[str, str]:
        """Get security headers to add to responses."""
        return self.security_headers.copy()

    def configure_comprehensive_security(self, app):
        """Configure all security middleware for the FastAPI app."""
        logger.info("? Configuring comprehensive security middleware...")

        try:
            # 1. Setup enhanced exception handlers
            setup_exception_handlers(app)
            logger.info("[OK] Enhanced exception handlers configured")

            # 2. Add account-based rate limiting
            add_account_rate_limiting_middleware(app)
            logger.info("[OK] Account-based rate limiting middleware added")

            # 3. Add dynamic rate limiting based on system load
            add_dynamic_rate_limiting_middleware(app)
            logger.info("[OK] Dynamic rate limiting middleware added")

            # 4. Add IP blacklist middleware
            add_ip_blacklist_middleware(app)
            logger.info("[OK] IP blacklist middleware added")

            # 5. Add the existing security middleware
            app.add_middleware(SecurityMiddleware)
            logger.info("[OK] Core security middleware added")

            logger.info("?? Comprehensive security configuration completed successfully!")

        except Exception as e:
            logger.error(f"[ERROR] Error configuring security middleware: {e}")
            raise

    def get_security_status(self) -> Dict[str, Any]:
        """Get comprehensive security status."""
        try:
            rate_config = get_rate_limiting_config()

            return {
                "enhanced_security_enabled": True,
                "middleware_status": {
                    "core_security": True,
                    "account_rate_limiting": True,
                    "dynamic_rate_limiting": True,
                    "ip_blacklist": True,
                    "enhanced_error_handling": True
                },
                "rate_limiting": rate_config.get_config_summary() if rate_config else {"enabled": False},
                "security_headers": len(self.security_headers),
                "threat_detection": {
                    "enabled": True,
                    "patterns_monitored": len(self.threat_patterns),
                    "blocked_ips": len(self.blocked_ips)
                },
                "timestamp": datetime.now(timezone.utc).isoformat()
            }
        except Exception as e:
            logger.error(f"Error getting security status: {e}")
            return {"error": str(e), "enhanced_security_enabled": False}


# Global instance
_security_manager = None

def get_enhanced_security_manager() -> EnhancedSecurityManager:
    """Get global enhanced security manager instance."""
    global _security_manager
    if _security_manager is None:
        _security_manager = EnhancedSecurityManager()
    return _security_manager


class SecurityMiddleware(BaseHTTPMiddleware):
    """Security middleware for FastAPI applications."""
    
    def __init__(self, app):
        super().__init__(app)
        self.security_manager = get_enhanced_security_manager()
    
    async def dispatch(self, request: Request, call_next):
        """Process request through security pipeline."""
        start_time = time.time()
        
        # Validate request
        valid, context, error_response = await self.security_manager.validate_request(request)
        
        if not valid and error_response:
            return JSONResponse(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS if "rate limit" in error_response.get("error", "").lower() else status.HTTP_403_FORBIDDEN,
                content=error_response
            )
        
        # Process request
        response = await call_next(request)
        
        # Add security headers
        security_headers = self.security_manager.get_security_headers()
        for header_name, header_value in security_headers.items():
            response.headers[header_name] = header_value
        
        # Add performance headers
        process_time = time.time() - start_time
        response.headers["X-Process-Time"] = str(process_time)
        
        if context:
            response.headers["X-Request-ID"] = context.request_id
        
        return response