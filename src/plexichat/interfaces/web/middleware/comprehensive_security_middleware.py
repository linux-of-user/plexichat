"""
Enhanced Security Middleware
Integrates the enhanced security manager with FastAPI applications.
"""

import asyncio
import json
import time
from datetime import datetime, timezone
from typing import Any, Dict, Optional, Callable
from fastapi import Request, HTTPException, status
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse, Response

# Core imports
from plexichat.core.security.comprehensive_security_manager import (
    get_enhanced_security_manager, SecurityContext, SecurityLevel
)
from plexichat.core.logging_advanced.advanced_logging_system import (
    get_enhanced_logging_system, LogCategory, LogLevel, PerformanceMetrics
)
from plexichat.core.authentication import get_auth_manager as get_unified_auth_manager
    print(f"Security middleware import error: {e}")
    # Fallback implementations
    get_enhanced_security_manager = lambda: None
    get_enhanced_logging_system = lambda: None
    get_unified_auth_manager = lambda: None
    SecurityContext = type('SecurityContext', (), {})
    SecurityLevel = type('SecurityLevel', (), {})
    LogCategory = type('LogCategory', (), {})
    LogLevel = type('LogLevel', (), {})
    PerformanceMetrics = type('PerformanceMetrics', (), {})


class EnhancedSecurityMiddleware(BaseHTTPMiddleware):
    """Enhanced security middleware with comprehensive protection."""
    def __init__(self, app, config: Optional[Dict[str, Any]] = None):
        super().__init__(app)
        self.config = config or {}
        self.enabled = self.config.get("enabled", True)
        
        # Initialize components
        self.security_manager = get_enhanced_security_manager()
        self.logging_system = get_enhanced_logging_system()
        self.auth_manager = get_unified_auth_manager()
        
        # Get loggers
        if self.logging_system:
            self.logger = self.logging_system.get_logger(__name__)
        else:
            import logging
            self.logger = logging.getLogger(__name__)
        
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
            "/favicon.ico"
        }
        
        self.logger.info("Enhanced Security Middleware initialized")
    
    async def dispatch(self, request: Request, call_next):
        """Main middleware dispatch logic."""
        if not self.enabled:
            return await call_next(request)
        
        start_time = time.time()
        self.request_count += 1
        
        # Initialize request context
        if self.logging_system:
            self.logging_system.set_context(
                request_id=f"req_{int(time.time() * 1000)}_{self.request_count}",
                endpoint=str(request.url.path),
                method=request.method,
                ip_address=self._get_client_ip(request)
            )
        
        try:
            # Check if endpoint should bypass security
            if self._should_bypass_security(request):
                response = await call_next(request)
                return self._add_security_headers(response)
            
            # Security validation
            validation_result = await self._validate_request_security(request)
            if not validation_result["allowed"]:
                self.blocked_requests += 1
                return self._create_security_response(validation_result)
            
            # Authentication check
            auth_result = await self._check_authentication(request)
            
            # Authorization check
            if auth_result["authenticated"]:
                authz_result = await self._check_authorization(request, auth_result["user"])
                if not authz_result["authorized"]:
                    return self._create_auth_error_response("Insufficient permissions")
            
            # Process request
            response = await call_next(request)
            
            # Log successful request
            await self._log_request_success(request, response, start_time)
            
            # Add security headers
            return self._add_security_headers(response)
            
        except HTTPException as e:
            # Handle HTTP exceptions
            await self._log_request_error(request, e, start_time)
            raise
        except Exception as e:
            # Handle unexpected errors
            await self._log_request_error(request, e, start_time)
            return self._create_error_response("Internal server error", 500)
        finally:
            # Clear context
            if self.logging_system:
                self.logging_system.clear_context()
    
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
        if hasattr(request, 'client') and request.client:
            return request.client.host
        
        return "unknown"
    
    def _should_bypass_security(self, request: Request) -> bool:
        """Check if request should bypass security checks."""
        path = str(request.url.path)
        return any(path.startswith(bypass) for bypass in self.bypass_endpoints)
    
    async def _validate_request_security(self, request: Request) -> Dict[str, Any]:
        """Validate request security using enhanced security manager."""
        if not self.security_manager:
            return {"allowed": True, "reason": "Security manager not available"}
        
        try:
            allowed, context, error_info = await self.security_manager.validate_request(request)
            
            if not allowed:
                # Log security event
                await self._log_security_event(
                    "request_blocked",
                    {
                        "reason": error_info.get("error", "Unknown"),
                        "endpoint": str(request.url.path),
                        "method": request.method,
                        "ip": self._get_client_ip(request)
                    }
                )
                
                return {
                    "allowed": False,
                    "reason": error_info.get("error", "Security policy violation"),
                    "details": error_info
                }
            
            return {"allowed": True, "context": context}
            
        except Exception as e:
            self.logger.error(f"Security validation error: {e}")
            return {"allowed": True, "reason": "Security validation failed"}
    
    async def _check_authentication(self, request: Request) -> Dict[str, Any]:
        """Check request authentication."""
        # Get authorization header
        auth_header = request.headers.get("Authorization")
        if not auth_header:
            # Check for session cookie or other auth methods
            session_id = request.cookies.get("session_id")
            if not session_id:
                return {"authenticated": False, "user": None}
        
        if self.auth_manager:
            try:
                # Validate token/session
                if auth_header and auth_header.startswith("Bearer "):
                    token = auth_header[7:]
                    user_data = await self.auth_manager.validate_token(token)
                elif session_id:
                    user_data = await self.auth_manager.validate_session(session_id)
                else:
                    user_data = None
                
                if user_data:
                    # Update context with user info
                    if self.logging_system:
                        self.logging_system.set_context(
                            user_id=str(user_data.get("id", "")),
                            session_id=user_data.get("session_id", "")
                        )
                    
                    return {"authenticated": True, "user": user_data}
                
            except Exception as e:
                self.logger.warning(f"Authentication error: {e}")
        
        return {"authenticated": False, "user": None}
    
    async def _check_authorization(self, request: Request, user_data: Dict) -> Dict[str, Any]:
        """Check request authorization."""
        if not self.security_manager:
            return {"authorized": True}
        
        endpoint = str(request.url.path)
        
        try:
            authorized = await self.security_manager.check_endpoint_access(endpoint, user_data)
            
            if not authorized:
                await self._log_security_event(
                    "access_denied",
                    {
                        "user_id": user_data.get("id"),
                        "endpoint": endpoint,
                        "method": request.method,
                        "reason": "Insufficient permissions"
                    }
                )
            
            return {"authorized": authorized}
            
        except Exception as e:
            self.logger.error(f"Authorization check error: {e}")
            return {"authorized": False}
    
    async def _log_request_success(self, request: Request, response: Response, start_time: float):
        """Log successful request."""
        duration = (time.time() - start_time) * 1000  # milliseconds
        
        if self.logging_system:
            performance = PerformanceMetrics(duration_ms=duration)
            
            self.logging_system.log_with_context(
                LogLevel.INFO.value,
                f"{request.method} {request.url.path} -> {response.status_code}",
                category=LogCategory.API,
                performance=performance,
                metadata={
                    "status_code": response.status_code,
                    "response_size": len(response.body) if hasattr(response, 'body') else 0,
                    "user_agent": request.headers.get("User-Agent", "unknown")
                },
                tags=["api_request", "success"]
            )
    
    async def _log_request_error(self, request: Request, error: Exception, start_time: float):
        """Log request error."""
        duration = (time.time() - start_time) * 1000  # milliseconds
        
        if self.logging_system:
            performance = PerformanceMetrics(duration_ms=duration)
            
            self.logging_system.log_with_context(
                LogLevel.ERROR.value,
                f"{request.method} {request.url.path} -> ERROR: {str(error)}",
                category=LogCategory.API,
                performance=performance,
                metadata={
                    "error_type": type(error).__name__,
                    "error_message": str(error),
                    "user_agent": request.headers.get("User-Agent", "unknown")
                },
                tags=["api_request", "error"]
            )
    
    async def _log_security_event(self, event_type: str, details: Dict[str, Any]):
        """Log security event."""
        if self.logging_system:
            self.logging_system.log_with_context(
                LogLevel.SECURITY.value,
                f"Security event: {event_type}",
                category=LogCategory.SECURITY,
                metadata={
                    "event_type": event_type,
                    **details
                },
                tags=["security", event_type]
            )
        
        if event_type in ["request_blocked", "access_denied", "authentication_failed"]:
            self.threat_detections += 1
    
    def _create_security_response(self, validation_result: Dict[str, Any]) -> JSONResponse:
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
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "request_id": self.logging_system.get_context().request_id if self.logging_system else None
            }
        )
    
    def _create_auth_error_response(self, message: str) -> JSONResponse:
        """Create authentication/authorization error response."""
        return JSONResponse(
            status_code=status.HTTP_401_UNAUTHORIZED,
            content={
                "error": message,
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "request_id": self.logging_system.get_context().request_id if self.logging_system else None
            }
        )
    
    def _create_error_response(self, message: str, status_code: int = 500) -> JSONResponse:
        """Create generic error response."""
        return JSONResponse(
            status_code=status_code,
            content={
                "error": message,
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "request_id": self.logging_system.get_context().request_id if self.logging_system else None
            }
        )
    
    def _add_security_headers(self, response: Response) -> Response:
        """Add security headers to response."""
        if self.security_manager:
            security_headers = self.security_manager.get_security_headers()
            for header_name, header_value in security_headers.items():
                response.headers[header_name] = header_value
        
        # Add additional headers
        response.headers["X-Request-ID"] = (
            self.logging_system.get_context().request_id 
            if self.logging_system else f"req_{int(time.time())}"
        )
        
        return response
    
    def get_metrics(self) -> Dict[str, Any]:
        """Get security middleware metrics."""
        return {
            "total_requests": self.request_count,
            "blocked_requests": self.blocked_requests,
            "threat_detections": self.threat_detections,
            "block_rate": self.blocked_requests / max(self.request_count, 1),
            "threat_rate": self.threat_detections / max(self.request_count, 1)
        }


class SecurityAuditMiddleware(BaseHTTPMiddleware):
    """Additional middleware for security auditing."""
    def __init__(self, app):
        super().__init__(app)
        self.logging_system = get_enhanced_logging_system()
        
        if self.logging_system:
            self.logger = self.logging_system.get_logger(__name__)
        else:
            import logging
            self.logger = logging.getLogger(__name__)
    
    async def dispatch(self, request: Request, call_next):
        """Audit security-relevant events."""
        # Extract request information for auditing
        audit_info = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "method": request.method,
            "path": str(request.url.path),
            "query_params": dict(request.query_params),
            "client_ip": self._get_client_ip(request),
            "user_agent": request.headers.get("User-Agent", "unknown"),
            "referer": request.headers.get("Referer"),
            "content_type": request.headers.get("Content-Type"),
            "content_length": request.headers.get("Content-Length", 0)
        }
        
        # Check for sensitive endpoints
        sensitive_patterns = [
            "/admin", "/api/v1/admin", "/system", "/api/v1/system",
            "/auth", "/login", "/register", "/password", "/token"
        ]
        
        is_sensitive = any(pattern in audit_info["path"] for pattern in sensitive_patterns)
        
        if is_sensitive and self.logging_system:
            self.logging_system.log_with_context(
                LogLevel.AUDIT.value,
                f"Sensitive endpoint access: {audit_info['method']} {audit_info['path']}",
                category=LogCategory.AUDIT,
                metadata=audit_info,
                tags=["audit", "sensitive_access"]
            )
        
        # Process request
        response = await call_next(request)
        
        # Log response for sensitive endpoints
        if is_sensitive and self.logging_system:
            response_info = {
                **audit_info,
                "response_status": response.status_code,
                "response_size": len(response.body) if hasattr(response, 'body') else 0
            }
            
            self.logging_system.log_with_context(
                LogLevel.AUDIT.value,
                f"Sensitive endpoint response: {response.status_code}",
                category=LogCategory.AUDIT,
                metadata=response_info,
                tags=["audit", "sensitive_response"]
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
        
        if hasattr(request, 'client') and request.client:
            return request.client.host
        
        return "unknown"


def setup_security_middleware(app, config: Optional[Dict[str, Any]] = None):
    """Setup security middleware for FastAPI app."""
    # Add enhanced security middleware
    app.add_middleware(EnhancedSecurityMiddleware, config=config)
    
    # Add security audit middleware
    app.add_middleware(SecurityAuditMiddleware)
    
    return app