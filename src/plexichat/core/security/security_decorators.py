"""
Security Decorators for PlexiChat Endpoints
Provides decorators for endpoint-level security controls.
"""

import asyncio
import functools
import inspect
import time
from datetime import datetime, timezone
from typing import Any, Callable, Dict, List, Optional, Union
from enum import Enum

from fastapi import HTTPException, Request, status, Depends
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials

# Core imports
try:
    from .enhanced_security_manager import get_enhanced_security_manager, SecurityLevel
    from ..logging_advanced.enhanced_logging_system import (
        get_enhanced_logging_system, LogCategory, LogLevel, PerformanceMetrics, SecurityMetrics
    )
    from ..auth.unified_auth_manager import get_unified_auth_manager
except ImportError as e:
    print(f"Security decorators import error: {e}")
    # Fallback implementations
    get_enhanced_security_manager = lambda: None
    get_enhanced_logging_system = lambda: None
    get_unified_auth_manager = lambda: None
    
    # Fallback SecurityLevel enum
    class SecurityLevel(Enum):
        PUBLIC = 0
        BASIC = 1
        AUTHENTICATED = 2
        ELEVATED = 3
        ADMIN = 4
        SYSTEM = 5
    
    # Fallback LogCategory enum
    class LogCategory(Enum):
        SYSTEM = "system"
        SECURITY = "security"
        PERFORMANCE = "performance"
        API = "api"
        AUTH = "auth"
        AUDIT = "audit"
        ERROR = "error"
        DEBUG = "debug"
    
    # Fallback LogLevel enum
    class LogLevel(Enum):
        TRACE = 5
        DEBUG = 10
        INFO = 20
        WARNING = 30
        ERROR = 40
        CRITICAL = 50
        SECURITY = 60
        AUDIT = 70
        PERFORMANCE = 80
    
    # Fallback metric classes
    class PerformanceMetrics:
        def __init__(self, **kwargs): pass
    
    class SecurityMetrics:
        def __init__(self, **kwargs): pass


class RequiredPermission(Enum):
    """Required permissions for endpoints."""
        READ = "read"
    WRITE = "write"
    DELETE = "delete"
    ADMIN = "admin"
    SYSTEM = "system"


class SecurityScope(Enum):
    """Security scopes for endpoints."""
    PUBLIC = "public"
    USER = "user"
    ADMIN = "admin"
    SYSTEM = "system"


# Global instances
security_manager = get_enhanced_security_manager()
logging_system = get_enhanced_logging_system()
auth_manager = get_unified_auth_manager()
security_bearer = HTTPBearer()


def require_auth(
    required_level: SecurityLevel = SecurityLevel.AUTHENTICATED,
    permissions: Optional[List[RequiredPermission]] = None,
    scope: SecurityScope = SecurityScope.USER
):
    """
    Decorator that requires authentication for endpoint access.
    
    Args:
        required_level: Minimum security level required
        permissions: List of required permissions
        scope: Security scope for the endpoint
    """
    def decorator(func: Callable) -> Callable:
        @functools.wraps(func)
        async def wrapper(*args, **kwargs):
            request = _get_request_from_args(*args, **kwargs)
            
            # Perform authentication check
            user_data = await _authenticate_request(request, required_level)
            
            # Check permissions if specified
            if permissions:
                await _check_permissions(user_data, permissions, request)
            
            # Check scope access
            await _check_scope_access(user_data, scope, request)
            
            # Add user data to kwargs for endpoint use
            kwargs['current_user'] = user_data
            
            # Log access
            if logging_system:
                logging_system.log_with_context(
                    LogLevel.INFO.value,
                    f"Authenticated access to {request.url.path}",
                    category=LogCategory.AUTH,
                    metadata={
                        "user_id": user_data.get("id"),
                        "username": user_data.get("username"),
                        "endpoint": str(request.url.path),
                        "method": request.method,
                        "required_level": required_level.name if hasattr(required_level, 'name') else str(required_level),
                        "permissions": [p.value for p in permissions] if permissions else [],
                        "scope": scope.value
                    },
                    tags=["auth", "access_granted"]
                )
            
            return await func(*args, **kwargs)
        
        # Preserve function signature for FastAPI
        wrapper.__signature__ = inspect.signature(func)
        return wrapper
    
    return decorator


def require_admin(permissions: Optional[List[RequiredPermission]] = None):
    """Decorator that requires admin access.
    return require_auth(
        required_level=SecurityLevel.ADMIN,
        permissions=permissions,
        scope=SecurityScope.ADMIN
    )


def require_system_access():
    """Decorator that requires system-level access."""
    return require_auth(
        required_level=SecurityLevel.SYSTEM,
        scope=SecurityScope.SYSTEM
    )


def rate_limit(
    requests_per_minute: int = 60,
    requests_per_hour: int = 1000,
    burst: int = 10,
    key_func: Optional[Callable[[Request], str]] = None
):
    
    Decorator for rate limiting endpoints.
    
    Args:
        requests_per_minute: Maximum requests per minute
        requests_per_hour: Maximum requests per hour
        burst: Burst limit for short periods
        key_func: Function to generate rate limit key (default: IP-based)
    """
    def decorator(func: Callable) -> Callable:
        @functools.wraps(func)
        async def wrapper(*args, **kwargs):
            request = _get_request_from_args(*args, **kwargs)
            
            # Generate rate limit key
            if key_func:
                rate_key = key_func(request)
            else:
                rate_key = _get_client_ip(request)
            
            # Check rate limit
            if security_manager:
                from .enhanced_security_manager import RateLimitRule
                rule = RateLimitRule(
                    requests_per_minute=requests_per_minute,
                    requests_per_hour=requests_per_hour,
                    burst_limit=burst
                )
                
                allowed, info = await security_manager.rate_limiter.check_rate_limit(
                    rate_key, str(request.url.path), rule
                )
                
                if not allowed:
                    # Log rate limit violation
                    if logging_system:
                        logging_system.log_with_context(
                            LogLevel.WARNING.value,
                            f"Rate limit exceeded for {rate_key}",
                            category=LogCategory.SECURITY,
                            metadata={
                                "rate_key": rate_key,
                                "endpoint": str(request.url.path),
                                "limit_info": info
                            },
                            tags=["rate_limit", "violation"]
                        )
                    
                    raise HTTPException(
                        status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                        detail="Rate limit exceeded",
                        headers={"Retry-After": "60"}
                    )
            
            return await func(*args, **kwargs)
        
        wrapper.__signature__ = inspect.signature(func)
        return wrapper
    
    return decorator


def audit_access(
    action: str,
    resource_type: str = "endpoint",
    include_request_body: bool = False,
    include_response: bool = False
):
    """
    Decorator for auditing endpoint access.
    
    Args:
        action: Action being performed (e.g., "view", "create", "update", "delete")
        resource_type: Type of resource being accessed
        include_request_body: Whether to include request body in audit log
        include_response: Whether to include response in audit log
    """
    def decorator(func: Callable) -> Callable:
        @functools.wraps(func)
        async def wrapper(*args, **kwargs):
            start_time = time.time()
            
            request = _get_request_from_args(*args, **kwargs)
            
            # Prepare audit data
            audit_data = {
                "action": action,
                "resource_type": resource_type,
                "endpoint": str(request.url.path) if request else "unknown",
                "method": request.method if request else "unknown",
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "client_ip": _get_client_ip(request) if request else "unknown",
                "user_agent": request.headers.get("User-Agent", "unknown") if request else "unknown"
            }
            
            # Add user info if available
            current_user = kwargs.get('current_user')
            if current_user:
                audit_data.update({
                    "user_id": current_user.get("id"),
                    "username": current_user.get("username"),
                    "user_role": current_user.get("role")
                })
            
            # Include request body if requested
            if include_request_body and request:
                try:
                    body = await request.body()
                    if body:
                        # Don't log sensitive data
                        if not _contains_sensitive_data(str(request.url.path)):
                            audit_data["request_body"] = body.decode('utf-8')[:1000]  # Limit size
                except Exception:
                    pass
            
            # Execute function
            try:
                result = await func(*args, **kwargs)
                
                # Calculate performance metrics
                duration = (time.time() - start_time) * 1000  # milliseconds
                audit_data["duration_ms"] = duration
                audit_data["status"] = "success"
                
                # Include response if requested
                if include_response and result:
                    # Safely serialize response (limit size)
                    try:
                        import json
                        response_data = json.dumps(result, default=str)[:2000]  # Limit size
                        audit_data["response"] = response_data
                    except Exception:
                        pass
                
                # Log successful audit
                if logging_system:
                    logging_system.log_with_context(
                        LogLevel.AUDIT.value,
                        f"Audit: {action} {resource_type}",
                        category=LogCategory.AUDIT,
                        metadata=audit_data,
                        tags=["audit", action, resource_type]
                    )
                
                return result
                
            except Exception as e:
                # Log failed audit
                audit_data.update({
                    "status": "error",
                    "error": str(e),
                    "error_type": type(e).__name__
                })
                
                if logging_system:
                    logging_system.log_with_context(
                        LogLevel.AUDIT.value,
                        f"Audit: {action} {resource_type} - FAILED",
                        category=LogCategory.AUDIT,
                        metadata=audit_data,
                        tags=["audit", action, resource_type, "error"]
                    )
                
                raise
        
        wrapper.__signature__ = inspect.signature(func)
        return wrapper
    
    return decorator


def validate_input(
    max_size: int = 1024 * 1024,  # 1MB default
    allowed_content_types: Optional[List[str]] = None,
    validate_json: bool = True,
    custom_validator: Optional[Callable] = None
):
    """
    Decorator for input validation.
    
    Args:
        max_size: Maximum request body size in bytes
        allowed_content_types: List of allowed content types
        validate_json: Whether to validate JSON format
        custom_validator: Custom validation function
    """
    def decorator(func: Callable) -> Callable:
        @functools.wraps(func)
        async def wrapper(*args, **kwargs):
            request = _get_request_from_args(*args, **kwargs)
            
            if request and request.method in ["POST", "PUT", "PATCH"]:
                # Check content type
                content_type = request.headers.get("Content-Type", "")
                if allowed_content_types and not any(ct in content_type for ct in allowed_content_types):
                    raise HTTPException(
                        status_code=status.HTTP_415_UNSUPPORTED_MEDIA_TYPE,
                        detail=f"Unsupported content type: {content_type}"
                    )
                
                # Check content length
                content_length = int(request.headers.get("Content-Length", 0))
                if content_length > max_size:
                    raise HTTPException(
                        status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                        detail=f"Request body too large: {content_length} > {max_size}"
                    )
                
                # Validate input with security manager
                if security_manager:
                    try:
                        body = await request.body()
                        if body:
                            # Basic security validation
                            import json
                            try:
                                if validate_json and "application/json" in content_type:
                                    data = json.loads(body.decode('utf-8'))
                                    # Use security manager's input validator
                                    valid, threats = await security_manager.input_validator.validate_input(
                                        data, None
                                    )
                                    
                                    if not valid:
                                        # Log security threat
                                        if logging_system:
                                            logging_system.log_with_context(
                                                LogLevel.SECURITY.value,
                                                f"Malicious input detected: {threats}",
                                                category=LogCategory.SECURITY,
                                                metadata={
                                                    "threats": threats,
                                                    "endpoint": str(request.url.path),
                                                    "client_ip": _get_client_ip(request)
                                                },
                                                tags=["security", "input_validation", "threat"]
                                            )
                                        
                                        raise HTTPException(
                                            status_code=status.HTTP_400_BAD_REQUEST,
                                            detail="Invalid input detected"
                                        )
                            except json.JSONDecodeError:
                                if validate_json and "application/json" in content_type:
                                    raise HTTPException(
                                        status_code=status.HTTP_400_BAD_REQUEST,
                                        detail="Invalid JSON format"
                                    )
                    except HTTPException:
                        raise
                    except Exception as e:
                        if logging_system:
                            logger = logging_system.get_logger(__name__)
                            logger.warning(f"Input validation error: {e}")
                
                # Custom validation
                if custom_validator:
                    try:
                        await custom_validator(request)
                    except Exception as e:
                        raise HTTPException(
                            status_code=status.HTTP_400_BAD_REQUEST,
                            detail=f"Custom validation failed: {str(e)}"
                        )
            
            return await func(*args, **kwargs)
        
        wrapper.__signature__ = inspect.signature(func)
        return wrapper
    
    return decorator


def security_headers(additional_headers: Optional[Dict[str, str]] = None):
    """
    Decorator to add security headers to responses.
    
    Args:
        additional_headers: Additional security headers to add
    
    def decorator(func: Callable) -> Callable:
        @functools.wraps(func)
        async def wrapper(*args, **kwargs):
            from fastapi import Response
            
            result = await func(*args, **kwargs)
            
            # If result is a Response object, add headers
            if isinstance(result, Response):
                if security_manager:
                    headers = security_manager.get_security_headers()
                    for name, value in headers.items():
                        result.headers[name] = value
                
                if additional_headers:
                    for name, value in additional_headers.items():
                        result.headers[name] = value
            
            return result
        
        wrapper.__signature__ = inspect.signature(func)
        return wrapper
    
    return decorator


# Helper functions
def _get_request_from_args(*args, **kwargs) -> Request:
    """Get request object from args/kwargs."""
    request = None
    for arg in args:
        if isinstance(arg, Request):
            request = arg
            break
    
    if not request:
        request = kwargs.get('request')
    
    if not request:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Request object not found"
        )
    return request

async def _authenticate_request(request: Request, required_level: SecurityLevel) -> Dict[str, Any]:
    """Authenticate request and return user data."""
    # Get authorization header
    auth_header = request.headers.get("Authorization")
    if not auth_header:
        # Check for session cookie
        session_id = request.cookies.get("session_id")
        if not session_id and required_level != SecurityLevel.PUBLIC:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Authentication required"
            )
    
    if auth_manager:
        try:
            user_data = None
            
            if auth_header and auth_header.startswith("Bearer "):
                token = auth_header[7:]
                user_data = await auth_manager.validate_token(token)
            elif session_id:
                user_data = await auth_manager.validate_session(session_id)
            
            if not user_data and required_level != SecurityLevel.PUBLIC:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Invalid authentication credentials"
                )
            
            if user_data:
                return user_data
            
        except HTTPException:
            raise
        except Exception as e:
            if logging_system:
                logger = logging_system.get_logger(__name__)
                logger.error(f"Authentication error: {e}")
            
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Authentication failed"
            )
    
    # Return empty user data for public endpoints
    return {


async def _check_permissions(user_data: Dict[str, Any], permissions: List[RequiredPermission], request: Request):
    """Check if user has required permissions."""
    user_permissions = user_data.get("permissions", [])
    
    for required_perm in permissions:
        if required_perm.value not in user_permissions:
            # Log permission denial
            if logging_system:
                logging_system.log_with_context(
                    LogLevel.WARNING.value,
                    f"Permission denied: {user_data.get('username')}} lacks {required_perm.value}",
                    category=LogCategory.SECURITY,
                    metadata={
                        "user_id": user_data.get("id"),
                        "required_permission": required_perm.value,
                        "user_permissions": user_permissions,
                        "endpoint": str(request.url.path)
                    },
                    tags=["security", "permission_denied"]
                )
            
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Permission denied: {required_perm.value} required"
            )


async def _check_scope_access(user_data: Dict[str, Any], scope: SecurityScope, request: Request):
    """Check if user has access to the specified scope."""
    if scope == SecurityScope.PUBLIC:
        return
    
    if scope == SecurityScope.ADMIN and not user_data.get("is_admin", False):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admin access required"
        )
    
    if scope == SecurityScope.SYSTEM and not user_data.get("is_system", False):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="System access required"
        )


def _get_client_ip(request: Request) -> str:
    """Extract client IP address from request."""
    forwarded_for = request.headers.get("X-Forwarded-For")
    if forwarded_for:
        return forwarded_for.split(",")[0].strip()
    
    real_ip = request.headers.get("X-Real-IP")
    if real_ip:
        return real_ip
    
    if hasattr(request, 'client') and request.client:
        return request.client.host
    
    return "unknown"


def _contains_sensitive_data(path: str) -> bool:
    """Check if endpoint path might contain sensitive data."""
    sensitive_patterns = [
        "password", "token", "secret", "key", "auth", "login", "register",
        "credit", "payment", "billing", "ssn", "social"
    ]
    
    path_lower = path.lower()
    return any(pattern in path_lower for pattern in sensitive_patterns)


# Convenience decorators combining common patterns
def secure_endpoint(
    auth_level: SecurityLevel = SecurityLevel.AUTHENTICATED,
    permissions: Optional[List[RequiredPermission]] = None,
    rate_limit_rpm: int = 60,
    audit_action: str = "access",
    validate_input_size: int = 1024 * 1024
):
    """
    Comprehensive security decorator combining authentication, rate limiting, auditing, and input validation.
    """
    def decorator(func: Callable) -> Callable:
        # Apply decorators in order (innermost first)
        secured_func = validate_input(max_size=validate_input_size)(func)
        secured_func = audit_access(audit_action)(secured_func)
        secured_func = rate_limit(requests_per_minute=rate_limit_rpm)(secured_func)
        secured_func = require_auth(auth_level, permissions)(secured_func)
        
        return secured_func
    
    return decorator


def admin_endpoint(
    permissions: Optional[List[RequiredPermission]] = None,
    rate_limit_rpm: int = 30,
    audit_action: str = "admin_access"
):
    """Security decorator for admin endpoints."""
    return secure_endpoint(
        auth_level=SecurityLevel.ADMIN,
        permissions=permissions,
        rate_limit_rpm=rate_limit_rpm,
        audit_action=audit_action
    )


def system_endpoint(
    rate_limit_rpm: int = 10,
    audit_action: str = "system_access"
):
    """Security decorator for system endpoints."""
    return secure_endpoint(
        auth_level=SecurityLevel.SYSTEM,
        rate_limit_rpm=rate_limit_rpm,
        audit_action=audit_action
    )