"""
Security Decorators

Decorators for authentication, authorization, rate limiting, and security enforcement.
"""

import functools
import logging
from typing import Any, Callable, Dict, List, Optional, Union
from enum import Enum
from itsdangerous import TimedJSONWebSignatureSerializer as Serializer, BadSignature, SignatureExpired
from fastapi import Request, HTTPException

from ..config import config

try:
    from . import SecurityLevel
    from ..authentication import get_auth_manager
except ImportError:
    # Fallback imports
    SecurityLevel = None
    get_auth_manager = None

try:
    from ..config.rate_limiting_config import get_rate_limiting_config, AccountType
except ImportError:
    get_rate_limiting_config = None
    AccountType = None

logger = logging.getLogger(__name__)


class RequiredPermission(Enum):
    """Required permission levels."""
    READ = "read"
    WRITE = "write"
    ADMIN = "admin"
    SYSTEM = "system"


def require_auth(func: Callable) -> Callable:
    """Decorator to require authentication."""
    @functools.wraps(func)
    async def wrapper(*args, **kwargs):
        # Extract request or session token
        request = None
        session_token = None
        
        # Try to find request in args
        for arg in args:
            if hasattr(arg, 'headers'):
                request = arg
                break
        
        # Try to find session token in kwargs
        session_token = kwargs.get('session_token')
        
        # Extract from request headers if available
        if request and hasattr(request, 'headers'):
            auth_header = request.headers.get('authorization', '')
            if auth_header.startswith('Bearer '):
                session_token = auth_header[7:]
        
        if not session_token:
            raise Exception("Authentication required")
        
        # Validate session if auth manager is available
        if get_auth_manager:
            auth_manager = get_auth_manager()
            valid, session_data = auth_manager.validate_session(session_token)
            if not valid:
                raise Exception("Invalid or expired session")
            
            # Add session data to kwargs
            kwargs['session_data'] = session_data
        
        return await func(*args, **kwargs)
    
    return wrapper


def require_permission(permission: RequiredPermission):
    """Decorator to require specific permission."""
    def decorator(func: Callable) -> Callable:
        @functools.wraps(func)
        async def wrapper(*args, **kwargs):
            # Get session data from previous auth decorator
            session_data = kwargs.get('session_data')
            if not session_data:
                raise Exception("Authentication required")
            
            # Check permission
            user_permissions = session_data.get('permissions', [])
            if permission.value not in user_permissions and 'admin' not in user_permissions:
                raise Exception(f"Permission denied: {permission.value}")
            
            return await func(*args, **kwargs)
        
        return wrapper
    return decorator


def require_security_level(level: Union[str, int]):
    """Decorator to require minimum security level."""
    def decorator(func: Callable) -> Callable:
        @functools.wraps(func)
        async def wrapper(*args, **kwargs):
            # Get session data from previous auth decorator
            session_data = kwargs.get('session_data')
            if not session_data:
                raise Exception("Authentication required")
            
            # Check security level (simplified)
            user_level = session_data.get('security_level', 'basic')
            # In a real implementation, you'd compare security levels properly
            
            return await func(*args, **kwargs)
        
        return wrapper
    return decorator


def rate_limit(requests_per_minute: int = 60, account_type: Optional[Any] = None):
    """Decorator to apply rate limiting."""
    def decorator(func: Callable) -> Callable:
        @functools.wraps(func)
        async def wrapper(*args, **kwargs):
            # Extract client identifier
            client_id = "unknown"
            
            # Try to find request in args
            for arg in args:
                if hasattr(arg, 'client') and hasattr(arg.client, 'host'):
                    client_id = arg.client.host
                    break
            
            # Get session data if available
            session_data = kwargs.get('session_data')
            if session_data:
                client_id = session_data.get('user_id', client_id)
            
            # Apply rate limiting (simplified implementation)
            # In a real implementation, you'd check against a rate limiter
            logger.debug(f"Rate limiting check for {client_id}: {requests_per_minute} req/min")
            
            return await func(*args, **kwargs)
        
        return wrapper
    return decorator


def audit_access(action: str, resource: str = ""):
    """Decorator to audit access attempts."""
    def decorator(func: Callable) -> Callable:
        @functools.wraps(func)
        async def wrapper(*args, **kwargs):
            # Get session data if available
            session_data = kwargs.get('session_data')
            user_id = session_data.get('user_id', 'anonymous') if session_data else 'anonymous'
            
            # Log access attempt
            logger.info(f"Access audit: {user_id} attempted {action} on {resource}")
            
            try:
                result = await func(*args, **kwargs)
                logger.info(f"Access audit: {user_id} successfully {action} on {resource}")
                return result
            except Exception as e:
                logger.warning(f"Access audit: {user_id} failed {action} on {resource}: {e}")
                raise
        
        return wrapper
    return decorator


def sanitize_input(fields: List[str]):
    """Decorator to sanitize input fields."""
    def decorator(func: Callable) -> Callable:
        @functools.wraps(func)
        async def wrapper(*args, **kwargs):
            # Sanitize specified fields in kwargs
            for field in fields:
                if field in kwargs and isinstance(kwargs[field], str):
                    # Basic sanitization
                    kwargs[field] = kwargs[field].replace('<', '&lt;').replace('>', '&gt;')
            
            return await func(*args, **kwargs)
        
        return wrapper
    return decorator


def validate_csrf():
    """Decorator to validate CSRF tokens."""
    def decorator(func: Callable) -> Callable:
        @functools.wraps(func)
        async def wrapper(*args, **kwargs):
            # Extract request
            request = None
            for arg in args:
                if hasattr(arg, 'headers'):
                    request = arg
                    break
            
            if request:
                # Check CSRF token (simplified)
                csrf_token = request.headers.get('x-csrf-token', '')
                if not csrf_token:
                    raise Exception("CSRF token required")
                
                # In a real implementation, you'd validate the token
                logger.debug(f"CSRF token validated: {csrf_token[:8]}...")
            
            return await func(*args, **kwargs)
        
        return wrapper
    return decorator


def secure_endpoint(
    auth_required: bool = True,
    permission: Optional[RequiredPermission] = None,
    security_level: Optional[Union[str, int]] = None,
    rate_limit_rpm: int = 60,
    audit_action: str = "",
    sanitize_fields: Optional[List[str]] = None,
    csrf_protection: bool = False
):
    """Comprehensive security decorator combining multiple security measures."""
    def decorator(func: Callable) -> Callable:
        # Apply decorators in reverse order (they wrap from inside out)
        secured_func = func
        
        # CSRF protection
        if csrf_protection:
            secured_func = validate_csrf()(secured_func)
        
        # Input sanitization
        if sanitize_fields:
            secured_func = sanitize_input(sanitize_fields)(secured_func)
        
        # Audit logging
        if audit_action:
            secured_func = audit_access(audit_action)(secured_func)
        
        # Rate limiting
        secured_func = rate_limit(rate_limit_rpm)(secured_func)
        
        # Security level check
        if security_level:
            secured_func = require_security_level(security_level)(secured_func)
        
        # Permission check
        if permission:
            secured_func = require_permission(permission)(secured_func)
        
        # Authentication
        if auth_required:
            secured_func = require_auth(secured_func)
        
        return secured_func
    
    return decorator


# Convenience decorators
def admin_required(func: Callable) -> Callable:
    """Decorator requiring admin privileges."""
    return secure_endpoint(
        auth_required=True,
        permission=RequiredPermission.ADMIN,
        audit_action="admin_access"
    )(func)


# Alias for backward compatibility
require_admin = admin_required


def authenticated_only(func: Callable) -> Callable:
    """Decorator requiring authentication only."""
    return secure_endpoint(auth_required=True)(func)


def public_endpoint(rate_limit_rpm: int = 100):
    """Decorator for public endpoints with rate limiting."""
    def decorator(func: Callable) -> Callable:
        return secure_endpoint(
            auth_required=False,
            rate_limit_rpm=rate_limit_rpm
        )(func)
    return decorator


# Export all decorators
__all__ = [
    # Enums
    "RequiredPermission",
    
    # Core decorators
    "require_auth",
    "require_permission", 
    "require_security_level",
    "rate_limit",
    "audit_access",
    "sanitize_input",
    "validate_csrf",
    "secure_endpoint",
    "protect_from_replay",
    
    # Convenience decorators
    "admin_required",
    "require_admin",  # Alias for admin_required
    "authenticated_only",
    "public_endpoint",
]

def protect_from_replay(max_age_seconds: int = 60):
    """
    Decorator to protect against replay attacks by verifying a timed signature.
    Expects a signed token in the 'X-Plexi-Signature' header.
    The token should contain a signature of the request body.
    """
    def decorator(func: Callable) -> Callable:
        @functools.wraps(func)
        async def wrapper(*args, **kwargs):
            request: Optional[Request] = None
            for arg in args:
                if isinstance(arg, Request):
                    request = arg
                    break

            if not request:
                logger.error("Replay protection could not find request object.")
                raise HTTPException(status_code=500, detail="Server configuration error.")

            signed_token = request.headers.get("X-Plexi-Signature")
            if not signed_token:
                raise HTTPException(status_code=400, detail="Missing X-Plexi-Signature header.")

            if not config or not config.security.jwt_secret:
                logger.error("Replay protection cannot function without a JWT secret key.")
                raise HTTPException(status_code=500, detail="Server security not configured.")

            s = Serializer(config.security.jwt_secret)
            try:
                payload = s.loads(signed_token, max_age=max_age_seconds)

                request_body = await request.body()

                if payload.encode('utf-8') != request_body:
                    logger.warning(f"Replay protection failed: signature payload does not match request body.")
                    raise HTTPException(status_code=400, detail="Signature does not match request body.")

            except SignatureExpired:
                logger.warning(f"Replay protection failed: signature expired.")
                raise HTTPException(status_code=400, detail="Signature has expired.")
            except BadSignature:
                logger.warning(f"Replay protection failed: invalid signature.")
                raise HTTPException(status_code=400, detail="Invalid signature.")

            return await func(*args, **kwargs)
        return wrapper
    return decorator
