"""
NetLink API v1 - Authentication Module

Enhanced authentication, 2FA, and security features.
"""

try:
    from .auth_2fa import router as auth_2fa_router
except ImportError:
    auth_2fa_router = None

try:
    from .auth_advanced import router as auth_advanced_router
except ImportError:
    auth_advanced_router = None

__all__ = [
    "auth_2fa_router",
    "auth_advanced_router"
]
