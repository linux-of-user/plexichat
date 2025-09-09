"""Core security module with fallback implementations."""

try:
    from plexichat.core.utils.fallbacks import (
        SecurityManager,
        authenticate_user,
        get_fallback_instance,
        get_module_version,
        validate_token,
    )
except ImportError:
    # Retain old fallbacks
    pass

__version__ = get_module_version()
__all__ = ["SecurityManager", "security_manager", "authenticate_user", "validate_token"]

security_manager = get_fallback_instance("SecurityManager")
