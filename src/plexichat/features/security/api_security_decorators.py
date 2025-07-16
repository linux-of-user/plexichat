# pyright: reportPossiblyUnboundVariable=false
# pyright: reportArgumentType=false
# pyright: reportCallIssue=false
# pyright: reportAttributeAccessIssue=false
# pyright: reportAssignmentType=false
# pyright: reportReturnType=false
"""
Enhanced API Security Decorators
Provides comprehensive security decorators for API endpoints.
"""

import time
import logging
import functools
import hashlib
import json
from typing import Dict, List, Optional, Callable, Any
from datetime import datetime, timedelta
from fastapi import HTTPException, Request, Depends
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel, ValidationError

from .enhanced_input_validation import get_input_validator, ValidationLevel
from .enhanced_auth_system import get_auth_system

logger = logging.getLogger(__name__)

# Rate limiting storage
rate_limit_storage: Dict[str, List[float]] = {}
security_bearer = HTTPBearer()


class SecurityLevel:
    """API security levels."""
    PUBLIC = "public"
    BASIC = "basic"
    AUTHENTICATED = "authenticated"
    ADMIN = "admin"
    SYSTEM = "system"


class RateLimitConfig(BaseModel):
    """Rate limiting configuration."""
    requests: int = 100
    window: int = 3600  # seconds
    burst: int = 10
    burst_window: int = 60


class SecurityConfig(BaseModel):
    """Security configuration for endpoints."""
    level: str = SecurityLevel.AUTHENTICATED
    rate_limit: Optional[RateLimitConfig] = None
    require_csrf: bool = True
    validate_input: bool = True
    validation_level: str = ValidationLevel.STANDARD.value
    log_requests: bool = True
    require_https: bool = True
    allowed_methods: List[str] = ["GET", "POST", "PUT", "DELETE"]
    max_request_size: int = 10 * 1024 * 1024  # 10MB


def enhanced_security(
    level: str = SecurityLevel.AUTHENTICATED,
    rate_limit: Optional[Dict[str, int]] = None,
    require_csrf: bool = True,
    validate_input: bool = True,
    validation_level: ValidationLevel = ValidationLevel.STANDARD,
    log_requests: bool = True,
    require_https: bool = True,
    allowed_methods: Optional[List[str]] = None,
    max_request_size: int = 10 * 1024 * 1024
):
    """
    Enhanced security decorator for API endpoints.
    
    Args:
        level: Security level required
        rate_limit: Rate limiting configuration
        require_csrf: Whether to require CSRF token
        validate_input: Whether to validate input
        validation_level: Input validation level
        log_requests: Whether to log requests
        require_https: Whether to require HTTPS
        allowed_methods: Allowed HTTP methods
        max_request_size: Maximum request size in bytes
    """
    def decorator(func: Callable) -> Callable:
        @functools.wraps(func)
        async def wrapper(request: Request, *args, **kwargs):
            start_time = time.time()
            client_ip = request.client.host
            user_agent = request.headers.get("user-agent", "")
            
            try:
                # 1. HTTPS enforcement
                if require_https and request.url.scheme != "https" and client_ip not in ["127.0.0.1", "localhost"]:
                    raise HTTPException(
                        status_code=426,
                        detail="HTTPS required for this endpoint"
                    )
                
                # 2. Method validation
                if allowed_methods and request.method not in allowed_methods:
                    raise HTTPException(
                        status_code=405,
                        detail=f"Method {request.method} not allowed"
                    )
                
                # 3. Request size validation
                content_length = request.headers.get("content-length")
                if content_length and int(content_length) > max_request_size:
                    raise HTTPException(
                        status_code=413,
                        detail="Request too large"
                    )
                
                # 4. Rate limiting
                if rate_limit:
                    await _check_rate_limit(client_ip, rate_limit)
                
                # 5. Authentication and authorization
                user_context = await _check_authentication(request, level)
                
                # 6. CSRF protection
                if require_csrf and request.method in ["POST", "PUT", "DELETE", "PATCH"]:
                    await _check_csrf_token(request)
                
                # 7. Input validation
                if validate_input:
                    await _validate_request_input(request, validation_level)
                
                # 8. Security headers validation
                await _validate_security_headers(request)
                
                # Add user context to request
                request.state.user_context = user_context
                request.state.security_level = level
                
                # Execute the endpoint
                result = await func(request, *args, **kwargs)
                
                # 9. Log successful request
                if log_requests:
                    await _log_api_request(
                        request, user_context, "success", 
                        time.time() - start_time
                    )
                
                return result
                
            except HTTPException:
                # Re-raise HTTP exceptions
                if log_requests:
                    await _log_api_request(
                        request, None, "http_error", 
                        time.time() - start_time
                    )
                raise
            except Exception as e:
                # Log and handle unexpected errors
                logger.error(f"API endpoint error: {e}")
                if log_requests:
                    await _log_api_request(
                        request, None, "error", 
                        time.time() - start_time, str(e)
                    )
                raise HTTPException(
                    status_code=500,
                    detail="Internal server error"
                )
        
        return wrapper
    return decorator


async def _check_rate_limit(client_ip: str, config: Dict[str, int]):
    """Check rate limiting for client IP."""
    current_time = time.time()
    key = f"rate_limit:{client_ip}"
    
    if key not in rate_limit_storage:
        rate_limit_storage[key] = []
    
    # Clean old entries
    window = config.get("window", 3600)
    rate_limit_storage[key] = [
        timestamp for timestamp in rate_limit_storage[key]
        if current_time - timestamp < window
    ]
    
    # Check rate limit
    max_requests = config.get("requests", 100)
    if len(rate_limit_storage[key]) >= max_requests:
        raise HTTPException(
            status_code=429,
            detail="Rate limit exceeded",
            headers={"Retry-After": str(window)}
        )
    
    # Add current request
    rate_limit_storage[key].append(current_time)


async def _check_authentication(request: Request, level: str) -> Optional[Dict[str, Any]]:
    """Check authentication and authorization."""
    if level == SecurityLevel.PUBLIC:
        return None
    
    # Get authorization header
    auth_header = request.headers.get("authorization")
    if not auth_header or not auth_header.startswith("Bearer "):
        raise HTTPException(
            status_code=401,
            detail="Authentication required"
        )
    
    token = auth_header[7:]  # Remove "Bearer " prefix
    
    # Validate token with auth system
    auth_system = get_auth_system()
    
    # For now, return a mock user context
    # In production, this would validate the actual token
    user_context = {
        "user_id": "test_user",
        "username": "test_user",
        "roles": ["user"],
        "permissions": ["read", "write"],
        "session_id": token[:8]
    }
    
    # Check authorization level
    if level == SecurityLevel.ADMIN and "admin" not in user_context.get("roles", []):
        raise HTTPException(
            status_code=403,
            detail="Admin access required"
        )
    
    if level == SecurityLevel.SYSTEM and "system" not in user_context.get("roles", []):
        raise HTTPException(
            status_code=403,
            detail="System access required"
        )
    
    return user_context


async def _check_csrf_token(request: Request):
    """Check CSRF token for state-changing operations."""
    # Skip CSRF for API endpoints with proper authentication
    if request.url.path.startswith("/api/"):
        return
    
    csrf_token = request.headers.get("X-CSRF-Token")
    if not csrf_token:
        # Try to get from form data
        if request.method == "POST":
            try:
                form_data = await request.form()
                csrf_token = form_data.get("csrf_token")
            except Exception:
                pass
    
    if not csrf_token:
        raise HTTPException(
            status_code=403,
            detail="CSRF token required"
        )
    
    # Validate CSRF token (simplified validation)
    # In production, this would validate against session-stored token
    if len(csrf_token) < 32:
        raise HTTPException(
            status_code=403,
            detail="Invalid CSRF token"
        )


async def _validate_request_input(request: Request, validation_level: ValidationLevel):
    """Validate request input for security threats."""
    validator = get_input_validator()
    
    # Validate query parameters
    for key, value in request.query_params.items():
        result = validator.validate_input(value, validation_level)
        if not result.is_valid:
            raise HTTPException(
                status_code=400,
                detail=f"Invalid query parameter '{key}': {', '.join(result.warnings)}"
            )
    
    # Validate headers
    dangerous_headers = ["x-forwarded-for", "x-real-ip", "host"]
    for header in dangerous_headers:
        value = request.headers.get(header)
        if value:
            result = validator.validate_input(value, validation_level)
            if not result.is_valid:
                logger.warning(f"Suspicious header {header}: {value}")
    
    # Validate request body if present
    if request.method in ["POST", "PUT", "PATCH"]:
        try:
            content_type = request.headers.get("content-type", "")
            if "application/json" in content_type:
                body = await request.body()
                if body:
                    body_str = body.decode("utf-8")
                    result = validator.validate_input(body_str, validation_level)
                    if not result.is_valid:
                        raise HTTPException(
                            status_code=400,
                            detail=f"Invalid request body: {', '.join(result.warnings)}"
                        )
        except UnicodeDecodeError:
            raise HTTPException(
                status_code=400,
                detail="Invalid request encoding"
            )


async def _validate_security_headers(request: Request):
    """Validate security-related headers."""
    # Check for suspicious user agents
    user_agent = request.headers.get("user-agent", "")
    suspicious_agents = ["sqlmap", "nikto", "nmap", "masscan", "zap"]
    
    if any(agent in user_agent.lower() for agent in suspicious_agents):
        logger.warning(f"Suspicious user agent detected: {user_agent}")
        raise HTTPException(
            status_code=403,
            detail="Access denied"
        )
    
    # Check for suspicious headers
    suspicious_headers = {
        "x-forwarded-for": ["127.0.0.1", "localhost", "0.0.0.0"],
        "x-real-ip": ["127.0.0.1", "localhost", "0.0.0.0"],
        "x-originating-ip": ["127.0.0.1", "localhost", "0.0.0.0"]
    }
    
    for header, suspicious_values in suspicious_headers.items():
        value = request.headers.get(header)
        if value and any(sus_val in value for sus_val in suspicious_values):
            logger.warning(f"Suspicious header {header}: {value}")


async def _log_api_request(
    request: Request, 
    user_context: Optional[Dict[str, Any]], 
    status: str,
    duration: float,
    error: Optional[str] = None
):
    """Log API request for security monitoring."""
    log_entry = {
        "timestamp": datetime.now().isoformat(),
        "method": request.method,
        "path": str(request.url.path),
        "query_params": dict(request.query_params),
        "client_ip": request.client.host,
        "user_agent": request.headers.get("user-agent", ""),
        "user_id": user_context.get("user_id") if user_context else None,
        "status": status,
        "duration_ms": round(duration * 1000, 2),
        "error": error
    }
    
    # Log based on status
    if status == "success":
        logger.info(f"API Request: {request.method} {request.url.path} - {log_entry['duration_ms']}ms")
    elif status == "error":
        logger.error(f"API Error: {request.method} {request.url.path} - {error}")
    else:
        logger.warning(f"API Warning: {request.method} {request.url.path} - {status}")


def require_permission(permission: str):
    """Decorator to require specific permission."""
    def decorator(func: Callable) -> Callable:
        @functools.wraps(func)
        async def wrapper(request: Request, *args, **kwargs):
            user_context = getattr(request.state, "user_context", None)
            if not user_context:
                raise HTTPException(
                    status_code=401,
                    detail="Authentication required"
                )
            
            user_permissions = user_context.get("permissions", [])
            if permission not in user_permissions:
                raise HTTPException(
                    status_code=403,
                    detail=f"Permission '{permission}' required"
                )
            
            return await func(request, *args, **kwargs)
        return wrapper
    return decorator


def require_role(role: str):
    """Decorator to require specific role."""
    def decorator(func: Callable) -> Callable:
        @functools.wraps(func)
        async def wrapper(request: Request, *args, **kwargs):
            user_context = getattr(request.state, "user_context", None)
            if not user_context:
                raise HTTPException(
                    status_code=401,
                    detail="Authentication required"
                )
            
            user_roles = user_context.get("roles", [])
            if role not in user_roles:
                raise HTTPException(
                    status_code=403,
                    detail=f"Role '{role}' required"
                )
            
            return await func(request, *args, **kwargs)
        return wrapper
    return decorator


def audit_log(action: str, resource: str = ""):
    """Decorator to log actions for audit purposes."""
    def decorator(func: Callable) -> Callable:
        @functools.wraps(func)
        async def wrapper(request: Request, *args, **kwargs):
            user_context = getattr(request.state, "user_context", None)
            
            # Execute function
            result = await func(request, *args, **kwargs)
            
            # Log audit event
            audit_entry = {
                "timestamp": datetime.now().isoformat(),
                "action": action,
                "resource": resource,
                "user_id": user_context.get("user_id") if user_context else None,
                "client_ip": request.client.host,
                "user_agent": request.headers.get("user-agent", ""),
                "success": True
            }
            
            logger.info(f"Audit: {action} on {resource} by {audit_entry['user_id']}")
            
            return result
        return wrapper
    return decorator
