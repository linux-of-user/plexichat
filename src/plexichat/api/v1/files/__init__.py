"""
NetLink API v1 - Files Module

Enhanced file management, sharing, and collaboration features.
"""

try:
    from .files_enhanced import router as files_enhanced_router
except ImportError:
    files_enhanced_router = None

__all__ = [
    "files_enhanced_router"
]
