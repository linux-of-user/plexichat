"""
PlexiChat API v1 - Security Module

Advanced security monitoring, threat detection, and compliance features.
"""

try:
    from .security import router as security_router
except ImportError:
    security_router = None

__all__ = [
    "security_router"
]
