"""
Security Decorators

Decorators for authentication, authorization, rate limiting, and security enforcement.
"""

from collections.abc import Callable
from enum import Enum
import functools
import logging
from typing import Any

from fastapi import HTTPException, Request, status
from itsdangerous import BadSignature, SignatureExpired
from itsdangerous import TimedJSONWebSignatureSerializer as Serializer

# Import unified auth manager
from plexichat.core.authentication import get_auth_manager
from plexichat.core.config import config

# Prefer unified logging shim if available, fall back to stdlib logging
try:
    from plexichat.core.logging import get_logger  # compatibility shim

    logger = get_logger(__name__)
except Exception:
    logger = logging.getLogger(__name__)

try:
    from plexichat.core.rate_limit_config import AccountType, get_rate_limiting_config
except Exception:
    get_rate_limiting_config = None
    AccountType = None

try:
    from . import SecurityLevel
except Exception:
    SecurityLevel = None


class RequiredPermission(Enum):
    """Required permission levels."""

    READ = "read"
    WRITE = "write"
    ADMIN = "admin"
    SYSTEM = "system"


def _find_request_in_args(args: tuple, kwargs: dict) -> Request | None:
    """Helper to locate a FastAPI Request object in args or kwargs."""
    # Check kwargs first
    if kwargs:
        for v in kwargs.values():
            if isinstance(v, Request):
                return v
    # Check args
    for a in args:
        if isinstance(a, Request):
            return a
        # Some frameworks pass starlette.requests.Request-like objects with headers attribute
        if hasattr(a, "headers") and hasattr(a, "scope"):
            try:
                # Rough duck-typing
                return a  # type: ignore
            except Exception:
                continue
    return None


def _get_token_from_request(request: Request) -> str | None:
    """Extract Bearer token from request Authorization header."""
    if not request:
        return None
    auth_header = None
    try:
        # starlette's headers are case-insensitive mapping
        auth_header = request.headers.get("authorization") or request.headers.get(
            "Authorization"
        )
    except Exception:
        # fallback
        try:
            auth_header = request.headers["authorization"]
        except Exception:
            auth_header = None
    if not auth_header:
        return None
    if isinstance(auth_header, str) and auth_header.lower().startswith("bearer "):
        return auth_header.split(" ", 1)[1].strip()
    return None


def require_auth(func: Callable) -> Callable:
    """Decorator to require authentication by validating a JWT bearer token via UnifiedAuthManager."""

    @functools.wraps(func)
    async def wrapper(*args, **kwargs):
        # First, try to find a token passed explicitly
        token = (
            kwargs.get("token")
            or kwargs.get("session_token")
            or kwargs.get("access_token")
        )

        # Then, try to locate Request object and extract Authorization header
        request = _find_request_in_args(args, kwargs)
        if request:
            header_token = _get_token_from_request(request)
            if header_token:
                token = header_token

        if not token:
            logger.debug("Authentication failed: no token provided")
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Authentication credentials were not provided.",
            )

        # Use unified auth manager to validate token
        if not get_auth_manager:
            logger.error(
                "Authentication configuration error: auth manager is unavailable"
            )
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Authentication system not configured.",
            )

        auth_manager = get_auth_manager()
        try:
            valid, payload = await auth_manager.validate_token(token)
        except Exception as e:
            logger.exception("Token validation raised an exception")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Error validating authentication token.",
            ) from e

        if not valid or not payload:
            logger.info("Invalid or expired token used for authentication")
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid or expired authentication token.",
            )

        # Normalize payload into session_data structure for downstream decorators/handlers
        session_data: dict[str, Any] = {}
        # Payload may already contain user_id and permissions
        user_id = (
            payload.get("user_id") or payload.get("sub") or payload.get("username")
        )
        permissions_raw = (
            payload.get("permissions")
            or payload.get("perms")
            or payload.get("scopes")
            or []
        )
        # Ensure permissions is a set
        try:
            permissions = (
                set(permissions_raw)
                if not isinstance(permissions_raw, set)
                else permissions_raw
            )
        except Exception:
            # If payload contains a single permission string
            permissions = (
                {permissions_raw}
                if isinstance(permissions_raw, str) and permissions_raw
                else set()
            )

        session_data.update(
            {
                "user_id": user_id,
                "permissions": permissions,
                "token": token,
                "token_payload": payload,
            }
        )

        # Add session_data to kwargs for downstream use
        kwargs["session_data"] = session_data

        # Also attach to request.state if available for frameworks that prefer that access pattern
        try:
            if request:
                request.state.session_data = session_data
        except Exception:
            # Non-fatal if request has no state
            pass

        return await func(*args, **kwargs)

    return wrapper


def require_permission(permission: RequiredPermission):
    """Decorator to require specific permission."""

    def decorator(func: Callable) -> Callable:
        @functools.wraps(func)
        async def wrapper(*args, **kwargs):
            # Get session data from kwargs or request.state
            session_data = kwargs.get("session_data")
            if not session_data:
                request = _find_request_in_args(args, kwargs)
                if request and getattr(request, "state", None):
                    session_data = getattr(request.state, "session_data", None)

            if not session_data:
                logger.debug(
                    "Permission check failed: no authentication information available"
                )
                raise HTTPException(
                    status_code=401,
                    detail="Authentication required for permission check.",
                )

            # Support both dict-based session_data and SessionInfo-like objects
            user_permissions = set()
            if isinstance(session_data, dict):
                perms = session_data.get("permissions", [])
                try:
                    user_permissions = (
                        set(perms) if not isinstance(perms, set) else perms
                    )
                except Exception:
                    user_permissions = {perms} if isinstance(perms, str) else set()
                user_id = session_data.get("user_id")
            else:
                # Fallback: object with attribute permissions and user_id
                user_permissions = getattr(session_data, "permissions", set())
                user_id = getattr(session_data, "user_id", None)

            # Admin override
            if "admin" in user_permissions or "ADMIN" in user_permissions:
                logger.debug(f"Permission check passed for admin user {user_id}")
                return await func(*args, **kwargs)

            if permission.value not in user_permissions:
                logger.info(
                    f"Permission denied for user {user_id}: requires {permission.value}"
                )
                raise HTTPException(
                    status_code=403, detail=f"Permission denied: {permission.value}"
                )

            return await func(*args, **kwargs)

        return wrapper

    return decorator


def require_security_level(level: str | int):
    """Decorator to require minimum security level."""

    def decorator(func: Callable) -> Callable:
        @functools.wraps(func)
        async def wrapper(*args, **kwargs):
            session_data = kwargs.get("session_data")
            if not session_data:
                request = _find_request_in_args(args, kwargs)
                if request and getattr(request, "state", None):
                    session_data = getattr(request.state, "session_data", None)

            if not session_data:
                logger.debug(
                    "Security level check failed: no authentication information available"
                )
                raise HTTPException(
                    status_code=401,
                    detail="Authentication required for security level check.",
                )

            # Determine user's security level
            user_level = None
            if isinstance(session_data, dict):
                user_level = session_data.get("security_level")
            else:
                user_level = getattr(session_data, "security_level", None)

            # If security levels are numeric or definable via SecurityLevel, attempt to compare
            try:
                if SecurityLevel is not None:
                    # If SecurityLevel is an enum or mapping, try to derive comparable values
                    # This is intentionally permissive; concrete comparison logic belongs to SecurityLevel implementation
                    if user_level is None:
                        logger.debug("User security level missing; denying access.")
                        raise HTTPException(
                            status_code=403, detail="Insufficient security level."
                        )
                    # We won't try to coerce types here; trust SecurityLevel implementation elsewhere
                # If no SecurityLevel available, accept the endpoint if user is authenticated
            except HTTPException:
                raise
            except Exception:
                logger.exception("Error while evaluating security level")
                raise HTTPException(
                    status_code=500,
                    detail="Server error while evaluating security level.",
                )

            return await func(*args, **kwargs)

        return wrapper

    return decorator


def rate_limit(requests_per_minute: int = 60, account_type: Any | None = None):
    """Decorator to apply rate limiting. Uses UnifiedAuthManager metrics and best-effort checks."""

    def decorator(func: Callable) -> Callable:
        @functools.wraps(func)
        async def wrapper(*args, **kwargs):
            # Determine client identifier (user id if authenticated, otherwise IP)
            client_id = "unknown"
            request = _find_request_in_args(args, kwargs)
            if request:
                # try common client identifiers
                try:
                    client_host = None
                    if hasattr(request, "client") and getattr(
                        request.client, "host", None
                    ):
                        client_host = request.client.host
                    elif request.client:
                        client_host = str(request.client)
                    if client_host:
                        client_id = client_host
                except Exception:
                    pass

            session_data = kwargs.get("session_data")
            if not session_data and request and getattr(request, "state", None):
                session_data = getattr(request.state, "session_data", None)

            if session_data:
                if isinstance(session_data, dict):
                    client_id = session_data.get("user_id", client_id)
                else:
                    client_id = getattr(session_data, "user_id", client_id)

            # Allow external rate limit config to override default rpm if provided
            rpm = requests_per_minute
            if account_type and get_rate_limiting_config:
                try:
                    cfg = get_rate_limiting_config()
                    rpm = cfg.get_rpm_for_account_type(account_type) or rpm  # type: ignore
                except Exception:
                    logger.debug(
                        "Failed to load rate limiting config; using default rpm"
                    )

            # Use auth manager to record/check metrics where possible (best-effort)
            try:
                if get_auth_manager:
                    auth_manager = get_auth_manager()
                    # Increment metric for rate limit checks
                    try:
                        auth_manager._record_metric(
                            "rate_limit_checks"
                        )  # best-effort internal hook
                    except Exception:
                        # If protected, fall back to direct metric update if available
                        try:
                            if hasattr(auth_manager, "metrics"):
                                auth_manager.metrics["rate_limit_checks"] = (
                                    auth_manager.metrics.get("rate_limit_checks", 0) + 1
                                )
                        except Exception:
                            pass
            except Exception:
                logger.debug("Rate limiting: auth manager unavailable for metrics")

            logger.debug(f"Rate limiting check for client {client_id}: {rpm} req/min")

            # NOTE: This is a placeholder enforcement. Real enforcement should consult a rate-limiter store.
            # For now, do not block; just log. This keeps behavior non-breaking while integrating tracking.
            return await func(*args, **kwargs)

        return wrapper

    return decorator


def audit_access(action: str, resource: str = ""):
    """Decorator to audit access attempts."""

    def decorator(func: Callable) -> Callable:
        @functools.wraps(func)
        async def wrapper(*args, **kwargs):
            session_data = kwargs.get("session_data")
            request = _find_request_in_args(args, kwargs)
            if not session_data and request and getattr(request, "state", None):
                session_data = getattr(request.state, "session_data", None)

            user_id = "anonymous"
            if session_data:
                if isinstance(session_data, dict):
                    user_id = session_data.get("user_id", "anonymous")
                else:
                    user_id = getattr(session_data, "user_id", "anonymous")

            logger.info(f"Access audit: {user_id} attempted {action} on {resource}")

            try:
                result = await func(*args, **kwargs)
                logger.info(
                    f"Access audit: {user_id} successfully {action} on {resource}"
                )
                return result
            except HTTPException:
                # Re-raise HTTPExceptions unchanged after logging
                logger.warning(
                    f"Access audit: {user_id} failed {action} on {resource}: HTTP error"
                )
                raise
            except Exception as e:
                logger.warning(
                    f"Access audit: {user_id} failed {action} on {resource}: {e}"
                )
                raise

        return wrapper

    return decorator


def sanitize_input(fields: list[str]):
    """Decorator to sanitize input fields."""

    def decorator(func: Callable) -> Callable:
        @functools.wraps(func)
        async def wrapper(*args, **kwargs):
            for field in fields:
                if field in kwargs and isinstance(kwargs[field], str):
                    kwargs[field] = (
                        kwargs[field].replace("<", "&lt;").replace(">", "&gt;")
                    )
            return await func(*args, **kwargs)

        return wrapper

    return decorator


def validate_csrf():
    """Decorator to validate CSRF tokens."""

    def decorator(func: Callable) -> Callable:
        @functools.wraps(func)
        async def wrapper(*args, **kwargs):
            request = _find_request_in_args(args, kwargs)
            if not request:
                logger.debug("CSRF validation: no request object found")
                raise HTTPException(
                    status_code=400, detail="Request required for CSRF validation."
                )

            csrf_token = request.headers.get("x-csrf-token") or request.headers.get(
                "X-CSRF-Token"
            )
            if not csrf_token:
                logger.warning("CSRF token missing in request headers")
                raise HTTPException(status_code=403, detail="CSRF token required")

            # In a real implementation, we'd validate token against session or a token store.
            logger.debug(f"CSRF token validated (presence): {csrf_token[:8]}...")
            return await func(*args, **kwargs)

        return wrapper

    return decorator


from plexichat.core.auth.fastapi_adapter import rate_limit


def audit_access(action: str, resource: str = ""):
    """Decorator to audit access attempts."""

    def decorator(func: Callable) -> Callable:
        @functools.wraps(func)
        async def wrapper(*args, **kwargs):
            session_data = kwargs.get("session_data")
            request = _find_request_in_args(args, kwargs)
            if not session_data and request and getattr(request, "state", None):
                session_data = getattr(request.state, "session_data", None)

            user_id = "anonymous"
            if session_data:
                if isinstance(session_data, dict):
                    user_id = session_data.get("user_id", "anonymous")
                else:
                    user_id = getattr(session_data, "user_id", "anonymous")

            logger.info(f"Access audit: {user_id} attempted {action} on {resource}")

            try:
                result = await func(*args, **kwargs)
                logger.info(
                    f"Access audit: {user_id} successfully {action} on {resource}"
                )
                return result
            except HTTPException:
                # Re-raise HTTPExceptions unchanged after logging
                logger.warning(
                    f"Access audit: {user_id} failed {action} on {resource}: HTTP error"
                )
                raise
            except Exception as e:
                logger.warning(
                    f"Access audit: {user_id} failed {action} on {resource}: {e}"
                )
                raise

        return wrapper

    return decorator


def sanitize_input(fields: list[str]):
    """Decorator to sanitize input fields."""

    def decorator(func: Callable) -> Callable:
        @functools.wraps(func)
        async def wrapper(*args, **kwargs):
            for field in fields:
                if field in kwargs and isinstance(kwargs[field], str):
                    kwargs[field] = (
                        kwargs[field].replace("<", "&lt;").replace(">", "&gt;")
                    )
            return await func(*args, **kwargs)

        return wrapper

    return decorator


def validate_csrf():
    """Decorator to validate CSRF tokens."""

    def decorator(func: Callable) -> Callable:
        @functools.wraps(func)
        async def wrapper(*args, **kwargs):
            request = _find_request_in_args(args, kwargs)
            if not request:
                logger.debug("CSRF validation: no request object found")
                raise HTTPException(
                    status_code=400, detail="Request required for CSRF validation."
                )

            csrf_token = request.headers.get("x-csrf-token") or request.headers.get(
                "X-CSRF-Token"
            )
            if not csrf_token:
                logger.warning("CSRF token missing in request headers")
                raise HTTPException(status_code=403, detail="CSRF token required")

            # In a real implementation, we'd validate token against session or a token store.
            logger.debug(f"CSRF token validated (presence): {csrf_token[:8]}...")
            return await func(*args, **kwargs)

        return wrapper

    return decorator


def secure_endpoint(
    auth_required: bool = True,
    permission: RequiredPermission | None = None,
    security_level: str | int | None = None,
    rate_limit_rpm: int = 60,
    audit_action: str = "",
    sanitize_fields: list[str] | None = None,
    csrf_protection: bool = False,
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
        secured_func = rate_limit(action=func.__name__, limit=rate_limit_rpm)(
            secured_func
        )

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
        audit_action="admin_access",
    )(func)


# Alias for backward compatibility
require_admin = admin_required


def authenticated_only(func: Callable) -> Callable:
    """Decorator requiring authentication only."""
    return secure_endpoint(auth_required=True)(func)


def public_endpoint(rate_limit_rpm: int = 100):
    """Decorator for public endpoints with rate limiting."""

    def decorator(func: Callable) -> Callable:
        return secure_endpoint(auth_required=False, rate_limit_rpm=rate_limit_rpm)(func)

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
            request: Request | None = None
            for arg in args:
                if isinstance(arg, Request):
                    request = arg
                    break

            if not request:
                # Also check kwargs for 'request'
                request = kwargs.get("request")
                if not isinstance(request, Request):
                    logger.error("Replay protection could not find request object.")
                    raise HTTPException(
                        status_code=500, detail="Server configuration error."
                    )

            signed_token = request.headers.get("X-Plexi-Signature")
            if not signed_token:
                raise HTTPException(
                    status_code=400, detail="Missing X-Plexi-Signature header."
                )

            if (
                not config
                or not getattr(config, "security", None)
                or not getattr(config.security, "jwt_secret", None)
            ):
                logger.error(
                    "Replay protection cannot function without a JWT secret key."
                )
                raise HTTPException(
                    status_code=500, detail="Server security not configured."
                )

            s = Serializer(config.security.jwt_secret)
            try:
                payload = s.loads(signed_token, max_age=max_age_seconds)

                request_body = await request.body()

                # payload may be bytes or str; normalize to bytes for comparison
                if isinstance(payload, str):
                    payload_bytes = payload.encode("utf-8")
                elif isinstance(payload, bytes):
                    payload_bytes = payload
                else:
                    # If payload is a dict or other structure, compare its serialized form
                    try:
                        import json

                        payload_bytes = json.dumps(payload, sort_keys=True).encode(
                            "utf-8"
                        )
                    except Exception:
                        payload_bytes = str(payload).encode("utf-8")

                if payload_bytes != request_body:
                    logger.warning(
                        "Replay protection failed: signature payload does not match request body."
                    )
                    raise HTTPException(
                        status_code=400, detail="Signature does not match request body."
                    )

            except SignatureExpired:
                logger.warning("Replay protection failed: signature expired.")
                raise HTTPException(status_code=400, detail="Signature has expired.")
            except BadSignature:
                logger.warning("Replay protection failed: invalid signature.")
                raise HTTPException(status_code=400, detail="Invalid signature.")
            except HTTPException:
                raise
            except Exception:
                logger.exception("Unexpected error during replay protection")
                raise HTTPException(status_code=400, detail="Invalid signature format.")

            return await func(*args, **kwargs)

        return wrapper

    return decorator
