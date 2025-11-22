"""
Enhanced Security Middleware
Integrates the enhanced security manager with FastAPI applications.
"""

from dataclasses import dataclass
from datetime import UTC, datetime
import json
import time
from typing import Any

# Core imports
from plexichat.core.security.security_manager import (
    get_security_module,
)

# Authentication manager
try:
    from plexichat.core.authentication import get_auth_manager
except Exception:

    def get_auth_manager():
        return None


# Local simple performance metrics dataclass to be compatible with older code expecting PerformanceMetrics
@dataclass
class PerformanceMetrics:
    duration_ms: float = 0.0


class EnhancedSecurityMiddleware(BaseHTTPMiddleware):
    """Enhanced security middleware with comprehensive protection."""

    def __init__(self, app: Any, config: dict[str, Any] | None = None) -> None:
        super().__init__(app)
        self.config = config or {}
        self.enabled = self.config.get("enabled", True)

        # Initialize components
        self.security_manager = get_security_module()
        # Use unified logging manager if available
        try:
            self.logging_manager = get_logging_manager()
        except Exception:
            self.logging_manager = None

        # Get a module-level unified logger
        try:
            self.logger = get_logger(__name__)
        except Exception:
            # As a last resort, create a very small shim to avoid raising at import time.
            import logging

            fallback = logging.getLogger(__name__)

            # provide minimal methods expected by code so attributes exist
            class FallbackLogger:
                def __init__(self, inner):
                    self._inner = inner
                    self.context = None

                def set_context(self, **kwargs):
                    self.context = kwargs

                def clear_context(self):
                    self.context = None

                def info(self, msg, **kwargs):
                    self._inner.info(msg)

                def warning(self, msg, **kwargs):
                    self._inner.warning(msg)

                def error(self, msg, **kwargs):
                    self._inner.error(msg)

                def security(self, msg, **kwargs):
                    self._inner.warning(f"SECURITY: {msg} {kwargs}")

                def audit(self, msg, **kwargs):
                    self._inner.info(f"AUDIT: {msg} {kwargs}")

                def performance(self, operation, duration, **kwargs):
                    self._inner.info(f"PERF: {operation} took {duration}ms {kwargs}")

                def request(self, method, path, status_code, duration, **kwargs):
                    self._inner.info(
                        f"{method} {path} {status_code} ({duration:.2f}ms) {kwargs}"
                    )

            self.logger = FallbackLogger(fallback)

        # Auth manager
        try:
            self.auth_manager = (
                get_auth_manager() if callable(get_auth_manager) else None
            )
        except Exception:
            self.auth_manager = None

        # Performance metrics
        self.request_count = 0
        self.blocked_requests = 0
        self.threat_detections = 0

        # Endpoints that bypass security (carefully chosen)
        self.bypass_endpoints = {
            "/health",
            "/metrics",
            "/docs",
            "/redoc",
            "/openapi.json",
            "/favicon.ico",
        }

        # Log initialization using unified logger
        try:
            # Set initial context with component info
            try:
                self.logger.set_context(
                    component="enhanced_security_middleware", enabled=self.enabled
                )
            except Exception:
                # If logger doesn't support set_context, ignore
                pass

            # Use unified logger info and include metadata in kwargs
            self.logger.info(
                "Enhanced Security Middleware initialized",
                component="enhanced_security_middleware",
                enabled=self.enabled,
            )
        except Exception:
            # Ensure no exception propagates on init logging
            try:
                self.logger.info(
                    "Enhanced Security Middleware initialized (fallback logging)"
                )
            except Exception:
                # last resort: ignore
                pass

    async def dispatch(self, request: Request, call_next):
        """Main middleware dispatch logic."""
        if not self.enabled:
            return await call_next(request)

        start_time = time.time()
        self.request_count += 1

        # Initialize request context if supported by unified logger
        try:
            self.logger.set_context(
                request_id=f"req_{int(time.time() * 1000)}_{self.request_count}",
                endpoint=str(request.url.path),
                method=request.method,
                ip_address=self._get_client_ip(request),
            )
        except Exception:
            # Non-fatal: continue without structured context
            pass

        try:
            # Check if endpoint should bypass security
            if self._should_bypass_security(request):
                response = await call_next(request)
                return self._add_security_headers(response)

            # Security validation
            validation_result = await self._validate_request_security(request)
            if not validation_result.get("allowed", True):
                self.blocked_requests += 1
                return self._create_security_response(validation_result)

            # Authentication check
            auth_result = await self._check_authentication(request)

            # Authorization check
            if auth_result.get("authenticated"):
                authz_result = await self._check_authorization(
                    request, auth_result.get("user")
                )
                if not authz_result.get("authorized", False):
                    # Log unauthorized attempt as security event
                    await self._log_security_event(
                        "access_denied",
                        {
                            "user_id": (
                                auth_result.get("user", {}).get("user_id")
                                if isinstance(auth_result.get("user"), dict)
                                else None
                            ),
                            "endpoint": str(request.url.path),
                            "method": request.method,
                            "reason": "Insufficient permissions",
                        },
                    )
                    return self._create_auth_error_response("Insufficient permissions")

            # Process request
            response = await call_next(request)

            # Log successful request
            await self._log_request_success(request, response, start_time)

            # Add security headers
            return self._add_security_headers(response)

        except HTTPException:
            # Let FastAPI handle HTTPExceptions; log and re-raise
            await self._log_request_error(request, None, start_time)
            raise
        except Exception as e:
            # Handle unexpected errors
            await self._log_request_error(request, e, start_time)
            return self._create_error_response("Internal server error", 500)
        finally:
            # Clear context if supported
            try:
                self.logger.clear_context()
            except Exception:
                pass

    def _get_client_ip(self, request: Request) -> str:
        """Extract client IP address from request."""
        # Check forwarded headers
        forwarded_for = request.headers.get("X-Forwarded-For")
        if forwarded_for:
            return forwarded_for.split(",")[0].strip()

        real_ip = request.headers.get("X-Real-IP")
        if real_ip:
            return real_ip

        # Use client IP from connection
        if hasattr(request, "client") and request.client:
            try:
                return request.client.host
            except Exception:
                return "unknown"

        return "unknown"

    def _should_bypass_security(self, request: Request) -> bool:
        """Check if request should bypass security checks."""
        path = str(request.url.path)
        return any(path.startswith(bypass) for bypass in self.bypass_endpoints)

    async def _validate_request_security(self, request: Request) -> dict[str, Any]:
        """Validate request security using enhanced security manager."""
        if not self.security_manager:
            return {"allowed": True, "reason": "Security manager not available"}

        try:
            # The comprehensive security manager is expected to provide async validate_request
            # that returns (allowed: bool, context: Optional[dict], error_info: Optional[dict])
            result = await self.security_manager.validate_request(request)
            # Support both tuple result and dict result for backward compatibility
            if isinstance(result, (tuple, list)):
                allowed, context, error_info = (result + [None, None, None])[:3]
            elif isinstance(result, dict):
                allowed = result.get("allowed", True)
                context = result.get("context")
                error_info = result.get("error_info") or result.get("details") or {}
            else:
                # Unknown return structure: treat as allowed
                allowed = True
                context = None
                error_info = {}

            if not allowed:
                # Log security event using unified logger.security
                try:
                    self.logger.security(
                        f"Request blocked: {request.method} {request.url.path}",
                        reason=(
                            (error_info or {}).get("error", "Unknown")
                            if isinstance(error_info, dict)
                            else str(error_info)
                        ),
                        endpoint=str(request.url.path),
                        method=request.method,
                        ip=self._get_client_ip(request),
                    )
                except Exception:
                    try:
                        self.logger.warning(
                            f"Security event - Request blocked: {request.method} {request.url.path} - {error_info}"
                        )
                    except Exception:
                        pass

                return {
                    "allowed": False,
                    "reason": (
                        (error_info or {}).get("error", "Security policy violation")
                        if isinstance(error_info, dict)
                        else str(error_info)
                    ),
                    "details": error_info or {},
                }

            return {"allowed": True, "context": context}

        except Exception as e:
            # Use unified logging if available
            try:
                self.logger.error(
                    f"Security validation error: {e}",
                    endpoint=str(request.url.path),
                    error=str(e),
                )
            except Exception:
                # Ensure no exception while logging tears down flow
                try:
                    self.logger.warning(f"Security validation error: {e}")
                except Exception:
                    pass
            # Fail open in validation to avoid accidental denial due to manager errors
            return {"allowed": True, "reason": "Security validation failed"}

    async def _check_authentication(self, request: Request) -> dict[str, Any]:
        """Check request authentication."""
        # Get authorization header
        auth_header = request.headers.get("Authorization")
        session_id = request.cookies.get("session_id")

        if not auth_header and not session_id:
            return {"authenticated": False, "user": None}

        if not self.auth_manager:
            # No auth manager available; treat as unauthenticated
            return {"authenticated": False, "user": None}

        try:
            # Validate token/session using AuthManager's interface
            if auth_header and auth_header.startswith("Bearer "):
                token = auth_header[7:]
                # validate_token returns (valid: bool, payload: Optional[dict])
                validation = await self.auth_manager.validate_token(token)
                if isinstance(validation, tuple) and len(validation) >= 2:
                    valid, payload = validation[0], validation[1]
                else:
                    # Older return style: payload or None
                    valid, payload = (
                        bool(validation),
                        validation if isinstance(validation, dict) else None,
                    )

                if valid and payload:
                    # Normalize user data
                    user_info = {
                        "user_id": payload.get("user_id")
                        or payload.get("sub")
                        or payload.get("id"),
                        "permissions": (
                            set(payload.get("permissions", []))
                            if payload.get("permissions")
                            else set()
                        ),
                        "session_id": payload.get("session_id") or payload.get("jti"),
                    }
                    # Update logging context
                    try:
                        self.logger.set_context(
                            user_id=str(user_info.get("user_id", "")),
                            session_id=user_info.get("session_id", ""),
                        )
                    except Exception:
                        pass

                    return {"authenticated": True, "user": user_info}

            elif session_id:
                # validate_session returns (valid: bool, SessionInfo)
                validation = await self.auth_manager.validate_session(session_id)
                if isinstance(validation, tuple) and len(validation) >= 2:
                    valid, session_obj = validation[0], validation[1]
                else:
                    valid = bool(validation)
                    session_obj = None

                if valid and session_obj:
                    user_info = {
                        "user_id": getattr(session_obj, "user_id", None),
                        "permissions": getattr(session_obj, "permissions", set()),
                        "session_id": getattr(session_obj, "session_id", None),
                    }
                    try:
                        self.logger.set_context(
                            user_id=str(user_info.get("user_id", "")),
                            session_id=user_info.get("session_id", ""),
                        )
                    except Exception:
                        pass

                    return {"authenticated": True, "user": user_info}

        except Exception as e:
            # Authentication failures should be logged as security events
            try:
                self.logger.security(f"Authentication error: {e}", error=str(e))
            except Exception:
                try:
                    self.logger.warning(f"Authentication error: {e}")
                except Exception:
                    pass

        return {"authenticated": False, "user": None}

    async def _check_authorization(
        self, request: Request, user_data: dict
    ) -> dict[str, Any]:
        """Check request authorization."""
        if not self.security_manager:
            return {"authorized": True}

        endpoint = str(request.url.path)

        try:
            # security_manager.check_endpoint_access is expected to accept endpoint and user info
            authorized = await self.security_manager.check_endpoint_access(
                endpoint, user_data
            )

            if not authorized:
                await self._log_security_event(
                    "access_denied",
                    {
                        "user_id": (
                            user_data.get("user_id")
                            if isinstance(user_data, dict)
                            else None
                        ),
                        "endpoint": endpoint,
                        "method": request.method,
                        "reason": "Insufficient permissions",
                    },
                )

            return {"authorized": bool(authorized)}

        except Exception as e:
            try:
                self.logger.security(
                    f"Authorization check error: {e}", endpoint=endpoint, error=str(e)
                )
            except Exception:
                try:
                    self.logger.error(f"Authorization check error: {e}")
                except Exception:
                    pass
            # Deny by default on authorization errors to be safe
            return {"authorized": False}

    async def _log_request_success(
        self, request: Request, response: Response, start_time: float
    ):
        """Log successful request."""
        duration = (time.time() - start_time) * 1000  # milliseconds

        try:
            # Attempt to fetch response size if possible
            response_size = 0
            try:
                response_size = (
                    len(response.body)
                    if hasattr(response, "body") and response.body is not None
                    else 0
                )
            except Exception:
                response_size = 0

            # Log as an HTTP request (structured)
            try:
                self.logger.request(
                    request.method,
                    request.url.path,
                    getattr(response, "status_code", "unknown"),
                    duration,
                    response_size=response_size,
                    user_agent=request.headers.get("User-Agent", "unknown"),
                )
            except Exception:
                # Fallback to info
                self.logger.info(
                    f"{request.method} {request.url.path} -> {getattr(response, 'status_code', 'unknown')} ({duration:.2f}ms)"
                )

            # Record performance metric via unified logger
            try:
                operation = f"{request.method} {request.url.path}"
                self.logger.performance(
                    operation,
                    duration,
                    status_code=getattr(response, "status_code", None),
                )
            except Exception:
                pass

        except Exception:
            # Ensure no logging error affects response
            try:
                self.logger.info(
                    f"{request.method} {request.url.path} -> {getattr(response, 'status_code', 'unknown')} ({duration:.2f}ms)"
                )
            except Exception:
                pass

    async def _log_request_error(
        self, request: Request, error: Exception | None, start_time: float
    ):
        """Log request error."""
        duration = (time.time() - start_time) * 1000  # milliseconds

        try:
            # Log an error for the request
            try:
                self.logger.error(
                    f"{request.method} {request.url.path} -> ERROR: {str(error) if error else 'HTTPException'}",
                    error_type=type(error).__name__ if error else "HTTPException",
                    error_message=str(error) if error else "",
                    user_agent=request.headers.get("User-Agent", "unknown"),
                )
            except Exception:
                try:
                    self.logger.warning(
                        f"{request.method} {request.url.path} -> ERROR: {str(error) if error else 'HTTPException'}"
                    )
                except Exception:
                    pass

            # Record performance metric as well
            try:
                operation = f"{request.method} {request.url.path}"
                self.logger.performance(operation, duration, error=True)
            except Exception:
                pass

        except Exception:
            try:
                self.logger.error(
                    f"{request.method} {request.url.path} -> ERROR: {str(error) if error else 'HTTPException'}"
                )
            except Exception:
                pass

    async def _log_security_event(self, event_type: str, details: dict[str, Any]):
        """Log security event."""
        try:
            self.logger.security(
                f"Security event: {event_type}",
                event_type=event_type,
                **(details or {}),
            )
        except Exception:
            try:
                self.logger.warning(
                    f"Security event: {event_type} - {json.dumps(details)}"
                )
            except Exception:
                pass

        if event_type in ["request_blocked", "access_denied", "authentication_failed"]:
            self.threat_detections += 1

    def _get_request_id(self) -> str | None:
        """Get the current request id from the logging context if available."""
        try:
            context = getattr(self.logger, "context", None)
            if context and hasattr(context, "request_id"):
                return context.request_id
            if isinstance(context, dict):
                return context.get("request_id")
        except Exception:
            pass
        return None

    def _create_security_response(
        self, validation_result: dict[str, Any]
    ) -> JSONResponse:
        """Create security error response."""
        error_details = validation_result.get("details", {})

        if "rate limit" in validation_result.get("reason", "").lower():
            status_code = status.HTTP_429_TOO_MANY_REQUESTS
            message = "Rate limit exceeded"
        else:
            status_code = status.HTTP_403_FORBIDDEN
            message = "Access denied"

        return JSONResponse(
            status_code=status_code,
            content={
                "error": message,
                "reason": validation_result.get("reason", "Security policy violation"),
                "timestamp": datetime.now(UTC).isoformat(),
                "request_id": self._get_request_id(),
            },
        )

    def _create_auth_error_response(self, message: str) -> JSONResponse:
        """Create authentication/authorization error response."""
        return JSONResponse(
            status_code=status.HTTP_401_UNAUTHORIZED,
            content={
                "error": message,
                "timestamp": datetime.now(UTC).isoformat(),
                "request_id": self._get_request_id(),
            },
        )

    def _create_error_response(
        self, message: str, status_code: int = 500
    ) -> JSONResponse:
        """Create generic error response."""
        return JSONResponse(
            status_code=status_code,
            content={
                "error": message,
                "timestamp": datetime.now(UTC).isoformat(),
                "request_id": self._get_request_id(),
            },
        )

    def _add_security_headers(self, response: Response) -> Response:
        """Add security headers to response."""
        try:
            if self.security_manager and hasattr(
                self.security_manager, "get_security_headers"
            ):
                security_headers = self.security_manager.get_security_headers() or {}
                for header_name, header_value in security_headers.items():
                    # Set header only if value is not None
                    if header_value is not None:
                        response.headers[header_name] = header_value
        except Exception:
            # If security manager fails, do not block response creation
            pass

        # Add additional headers
        request_id = self._get_request_id() or f"req_{int(time.time())}"
        response.headers["X-Request-ID"] = request_id

        return response

    def get_metrics(self) -> dict[str, Any]:
        """Get security middleware metrics."""
        return {
            "total_requests": self.request_count,
            "blocked_requests": self.blocked_requests,
            "threat_detections": self.threat_detections,
            "block_rate": self.blocked_requests / max(self.request_count, 1),
            "threat_rate": self.threat_detections / max(self.request_count, 1),
        }


class SecurityAuditMiddleware(BaseHTTPMiddleware):
    """Additional middleware for security auditing."""

    def __init__(self, app):
        super().__init__(app)
        try:
            self.logging_manager = get_logging_manager()
        except Exception:
            self.logging_manager = None

        try:
            self.logger = get_logger(__name__)
        except Exception:
            import logging

            fallback = logging.getLogger(__name__)

            class FallbackLogger:
                def __init__(self, inner):
                    self._inner = inner
                    self.context = None

                def audit(self, msg, **kwargs):
                    self._inner.info(f"AUDIT: {msg} {kwargs}")

                def info(self, msg, **kwargs):
                    self._inner.info(msg)

            self.logger = FallbackLogger(fallback)

    async def dispatch(self, request: Request, call_next):
        """Audit security-relevant events."""
        # Extract request information for auditing
        audit_info = {
            "timestamp": datetime.now(UTC).isoformat(),
            "method": request.method,
            "path": str(request.url.path),
            "query_params": dict(request.query_params),
            "client_ip": self._get_client_ip(request),
            "user_agent": request.headers.get("User-Agent", "unknown"),
            "referer": request.headers.get("Referer"),
            "content_type": request.headers.get("Content-Type"),
            "content_length": request.headers.get("Content-Length", 0),
        }

        # Check for sensitive endpoints
        sensitive_patterns = [
            "/admin",
            "/api/v1/admin",
            "/system",
            "/api/v1/system",
            "/auth",
            "/login",
            "/register",
            "/password",
            "/token",
        ]

        is_sensitive = any(
            pattern in audit_info["path"] for pattern in sensitive_patterns
        )

        try:
            if is_sensitive:
                try:
                    self.logger.audit(
                        f"Sensitive endpoint access: {audit_info['method']} {audit_info['path']}",
                        metadata=audit_info,
                        tags=["audit", "sensitive_access"],
                    )
                except Exception:
                    self.logger.info(
                        f"Sensitive endpoint access: {audit_info['method']} {audit_info['path']}"
                    )
        except Exception:
            self.logger.info(
                f"Sensitive endpoint access (failed structured log): {audit_info['method']} {audit_info['path']}"
            )

        # Process request
        response = await call_next(request)

        # Log response for sensitive endpoints
        try:
            if is_sensitive:
                try:
                    response_info = {
                        **audit_info,
                        "response_status": getattr(response, "status_code", None),
                        "response_size": (
                            len(response.body)
                            if hasattr(response, "body") and response.body is not None
                            else 0
                        ),
                    }
                    self.logger.audit(
                        f"Sensitive endpoint response: {getattr(response, 'status_code', None)}",
                        metadata=response_info,
                        tags=["audit", "sensitive_response"],
                    )
                except Exception:
                    self.logger.info(
                        f"Sensitive endpoint response: {getattr(response, 'status_code', None)}"
                    )
        except Exception:
            self.logger.info(
                f"Sensitive endpoint response (fallback): {getattr(response, 'status_code', None)}"
            )

        return response

    def _get_client_ip(self, request: Request) -> str:
        """Extract client IP address."""
        forwarded_for = request.headers.get("X-Forwarded-For")
        if forwarded_for:
            return forwarded_for.split(",")[0].strip()

        real_ip = request.headers.get("X-Real-IP")
        if real_ip:
            return real_ip

        if hasattr(request, "client") and request.client:
            try:
                return request.client.host
            except Exception:
                return "unknown"

        return "unknown"


def setup_security_middleware(app, config: dict[str, Any] | None = None):
    """Setup security middleware for FastAPI app."""
    # Add enhanced security middleware
    app.add_middleware(EnhancedSecurityMiddleware, config=config)

    # Add security audit middleware
    app.add_middleware(SecurityAuditMiddleware)

    return app
