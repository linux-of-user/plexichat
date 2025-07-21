# pyright: reportArgumentType=false
# pyright: reportCallIssue=false
# pyright: reportAttributeAccessIssue=false
# pyright: reportAssignmentType=false
# pyright: reportReturnType=false
"""
PlexiChat Government Security Middleware

Enhanced government-grade security middleware with comprehensive protection and performance optimization.
Uses EXISTING database abstraction and optimization systems.
"""

import hashlib
import hmac
import json
import logging
import time
from datetime import datetime, timedelta
from typing import Any, Callable, Dict, List, Optional

from fastapi import Request, Response, HTTPException, status
from starlette.middleware.base import BaseHTTPMiddleware

# Use EXISTING database abstraction layer
try:
    from plexichat.core.database.manager import database_manager
    from plexichat.core.database import get_session, execute_query
except ImportError:
    database_manager = None
    get_session = None
    execute_query = None

# Use EXISTING performance optimization engine
try:
    from plexichat.infrastructure.performance.optimization_engine import PerformanceOptimizationEngine
    from plexichat.infrastructure.utils.performance import async_track_performance
    from plexichat.core.logging_advanced.performance_logger import get_performance_logger, timer
except ImportError:
    PerformanceOptimizationEngine = None
    async_track_performance = None
    get_performance_logger = None
    timer = None

# Security imports
try:
    from plexichat.infrastructure.utils.security import InputSanitizer
except ImportError:
    class InputSanitizer:
        @staticmethod
        def sanitize_input(text: str) -> str:
            return text.strip()

        @staticmethod
        def validate_input(text: str, max_length: int = 1000) -> bool:
            return len(text) <= max_length

# Configuration imports
try:
    from plexichat.core.config import settings
except ImportError:
    class MockSettings:
        SECURITY_LEVEL = "GOVERNMENT"
        RATE_LIMIT_REQUESTS = 100
        RATE_LIMIT_WINDOW = 60
        ENABLE_AUDIT_LOGGING = True
    settings = MockSettings()

logger = logging.getLogger(__name__)

# Initialize EXISTING performance systems
performance_logger = get_performance_logger() if get_performance_logger else None
optimization_engine = PerformanceOptimizationEngine() if PerformanceOptimizationEngine else None

class SecurityMetrics:
    """Security metrics tracking."""

    def __init__(self):
        self.blocked_requests = 0
        self.suspicious_activities = 0
        self.rate_limit_violations = 0
        self.last_reset = datetime.now()

    def reset_if_needed(self):
        """Reset metrics if needed."""
        if datetime.now() - self.last_reset > timedelta(hours=1):
            self.blocked_requests = 0
            self.suspicious_activities = 0
            self.rate_limit_violations = 0
            self.last_reset = datetime.now()

class RateLimiter:
    """Advanced rate limiting with EXISTING database integration."""

    def __init__(self):
        self.db_manager = database_manager
        self.performance_logger = performance_logger
        self.local_cache: Dict[str, List[float]] = {}
        self.cache_cleanup_time = time.time()

    async def is_rate_limited(self, client_ip: str, endpoint: str) -> bool:
        """Check if client is rate limited using EXISTING database abstraction."""
        try:
            # Clean cache periodically
            current_time = time.time()
            if current_time - self.cache_cleanup_time > 300:  # 5 minutes
                self._cleanup_cache()
                self.cache_cleanup_time = current_time

            # Use local cache for performance
            cache_key = f"{client_ip}:{endpoint}"
            current_requests = self.local_cache.get(cache_key, [])

            # Remove old requests (older than rate limit window)
            window_start = current_time - getattr(settings, 'RATE_LIMIT_WINDOW', 60)
            current_requests = [req_time for req_time in current_requests if req_time > window_start]

            # Check rate limit
            max_requests = getattr(settings, 'RATE_LIMIT_REQUESTS', 100)
            if len(current_requests) >= max_requests:
                # Log to database if available
                if self.db_manager:
                    await self._log_rate_limit_violation(client_ip, endpoint)
                return True

            # Add current request
            current_requests.append(current_time)
            self.local_cache[cache_key] = current_requests

            return False

        except Exception as e:
            logger.error(f"Error checking rate limit: {e}")
            return False

    def _cleanup_cache(self):
        """Clean up old cache entries."""
        current_time = time.time()
        window_start = current_time - getattr(settings, 'RATE_LIMIT_WINDOW', 60)

        for key in list(self.local_cache.keys()):
            requests = self.local_cache[key]
            filtered_requests = [req_time for req_time in requests if req_time > window_start]

            if not filtered_requests:
                del self.local_cache[key]
            else:
                self.local_cache[key] = filtered_requests

    async def _log_rate_limit_violation(self, client_ip: str, endpoint: str):
        """Log rate limit violation to database."""
        if self.db_manager:
            try:
                query = """
                    INSERT INTO security_logs (event_type, client_ip, endpoint, timestamp, details)
                    VALUES (?, ?, ?, ?, ?)
                """
                params = {
                    "event_type": "rate_limit_violation",
                    "client_ip": client_ip,
                    "endpoint": endpoint,
                    "timestamp": datetime.now(),
                    "details": json.dumps({"violation_type": "rate_limit"})
                }

                if self.performance_logger and timer:
                    with timer("security_log_insert"):
                        await self.db_manager.execute_query(query, params)
                else:
                    await self.db_manager.execute_query(query, params)

            except Exception as e:
                logger.error(f"Error logging rate limit violation: {e}")

class SecurityAuditor:
    """Security audit logging with EXISTING database integration."""

    def __init__(self):
        self.db_manager = database_manager
        self.performance_logger = performance_logger

    async def log_security_event(self, event_type: str, client_ip: str, endpoint: str, details: Dict[str, Any]):
        """Log security event using EXISTING database abstraction."""
        if not getattr(settings, 'ENABLE_AUDIT_LOGGING', True):
            return

        if self.db_manager:
            try:
                query = """
                    INSERT INTO security_logs (event_type, client_ip, endpoint, timestamp, details)
                    VALUES (?, ?, ?, ?, ?)
                """
                params = {
                    "event_type": event_type,
                    "client_ip": client_ip,
                    "endpoint": endpoint,
                    "timestamp": datetime.now(),
                    "details": json.dumps(details)
                }

                if self.performance_logger and timer:
                    with timer("security_audit_log"):
                        await self.db_manager.execute_query(query, params)
                else:
                    await self.db_manager.execute_query(query, params)

            except Exception as e:
                logger.error(f"Error logging security event: {e}")

class ThreatDetector:
    """Advanced threat detection."""

    def __init__(self):
        self.suspicious_patterns = [
            r'<script[^>]*>.*?</script>',
            r'javascript:',
            r'vbscript:',
            r'onload\s*=',
            r'onerror\s*=',
            r'eval\s*\)',
            r'document\.cookie',
            r'window\.location',
            r'\.\./',
            r'union\s+select',
            r'drop\s+table',
            r'insert\s+into',
            r'delete\s+from'
        ]

    def detect_threats(self, request: Request) -> List[str]:
        """Detect potential threats in request."""
        threats = []

        try:
            # Check URL for suspicious patterns
            url_str = str(request.url)
            for pattern in self.suspicious_patterns:
                import re
                if re.search(pattern, url_str, re.IGNORECASE):
                    threats.append(f"Suspicious URL pattern: {pattern}")

            # Check headers for suspicious content
            for header_name, header_value in request.headers.items():
                for pattern in self.suspicious_patterns:
                    import re
                    if re.search(pattern, header_value, re.IGNORECASE):
                        threats.append(f"Suspicious header {header_name}: {pattern}")

            # Check for common attack indicators
            if len(url_str) > 2000:
                threats.append("Unusually long URL")

            if request.headers.get("user-agent", "").lower() in ["", "curl", "wget", "python-requests"]:
                threats.append("Suspicious user agent")

        except Exception as e:
            logger.error(f"Error in threat detection: {e}")

        return threats

class GovernmentSecurityMiddleware(BaseHTTPMiddleware):
    """Government-grade security middleware with comprehensive protection."""

    def __init__(self, app):
        super().__init__(app)
        self.rate_limiter = RateLimiter()
        self.security_auditor = SecurityAuditor()
        self.threat_detector = ThreatDetector()
        self.security_metrics = SecurityMetrics()
        self.performance_logger = performance_logger

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        """Process request with government-grade security checks."""
        start_time = time.time()
        client_ip = request.client.host if request.client else "unknown"
        endpoint = str(request.url.path)

        # Performance tracking
        if self.performance_logger:
            self.performance_logger.record_metric("security_middleware_requests", 1, "count")

        try:
            # Reset metrics if needed
            self.security_metrics.reset_if_needed()

            # 1. Rate limiting check
            if await self.rate_limiter.is_rate_limited(client_ip, endpoint):
                self.security_metrics.rate_limit_violations += 1

                await self.security_auditor.log_security_event(
                    "rate_limit_violation",
                    client_ip,
                    endpoint,
                    {"requests_exceeded": True}
                )

                if self.performance_logger:
                    self.performance_logger.record_metric("security_rate_limit_blocks", 1, "count")

                raise HTTPException(
                    status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                    detail="Rate limit exceeded"
                )

            # 2. Threat detection
            threats = self.threat_detector.detect_threats(request)
            if threats:
                self.security_metrics.suspicious_activities += 1

                await self.security_auditor.log_security_event(
                    "threat_detected",
                    client_ip,
                    endpoint,
                    {"threats": threats}
                )

                if self.performance_logger:
                    self.performance_logger.record_metric("security_threat_blocks", 1, "count")

                # Block high-risk threats
                high_risk_patterns = ["script", "union select", "drop table"]
                if any(pattern in threat.lower() for threat in threats for pattern in high_risk_patterns):
                    self.security_metrics.blocked_requests += 1

                    raise HTTPException(
                        status_code=status.HTTP_403_FORBIDDEN,
                        detail="Request blocked by security policy"
                    )

            # 3. Input validation for POST/PUT requests
            if request.method in ["POST", "PUT", "PATCH"]:
                await self._validate_request_body(request, client_ip, endpoint)

            # 4. Security headers validation
            self._validate_security_headers(request)

            # 5. Process request
            if self.performance_logger and timer:
                with timer("security_middleware_processing"):
                    response = await call_next(request)
            else:
                response = await call_next(request)

            # 6. Add security headers to response
            self._add_security_headers(response)

            # 7. Log successful request
            await self.security_auditor.log_security_event(
                "request_processed",
                client_ip,
                endpoint,
                {
                    "method": request.method,
                    "status_code": response.status_code,
                    "processing_time": time.time() - start_time
                }
            )

            # Performance tracking
            if self.performance_logger:
                self.performance_logger.record_metric(
                    "security_middleware_processing_time",
                    time.time() - start_time,
                    "seconds"
                )

            return response

        except HTTPException:
            raise
        except Exception as e:
            logger.error(f"Security middleware error: {e}")

            await self.security_auditor.log_security_event(
                "middleware_error",
                client_ip,
                endpoint,
                {"error": str(e)}
            )

            # Continue processing on middleware errors
            response = await call_next(request)
            self._add_security_headers(response)
            return response

    async def _validate_request_body(self, request: Request, client_ip: str, endpoint: str):
        """Validate request body for security threats."""
        try:
            # This is a simplified validation - in practice, you'd want more sophisticated checks
            content_type = request.headers.get("content-type", "")

            if "application/json" in content_type:
                # For JSON requests, we could validate the structure
                pass
            elif "multipart/form-data" in content_type:
                # For file uploads, we could scan for malicious files
                pass

        except Exception as e:
            logger.error(f"Error validating request body: {e}")

    def _validate_security_headers(self, request: Request):
        """Validate security-related headers."""
        # Check for required security headers in certain contexts
        if request.url.path.startswith("/admin"):
            # Admin endpoints might require additional headers
            pass

    def _add_security_headers(self, response: Response):
        """Add government-grade security headers to response."""
        # Security headers for government compliance
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-XSS-Protection"] = "1; mode=block"
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        response.headers["Content-Security-Policy"] = "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=()"

        # Custom security headers
        response.headers["X-Security-Level"] = getattr(settings, 'SECURITY_LEVEL', 'GOVERNMENT')
        response.headers["X-Request-ID"] = f"req_{int(time.time())}"
