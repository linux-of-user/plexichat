# pyright: reportArgumentType=false
# pyright: reportCallIssue=false
# pyright: reportAttributeAccessIssue=false
# pyright: reportAssignmentType=false
# pyright: reportReturnType=false
from typing import Optional

"""
PlexiChat API v1 - Users Module

Enhanced user management and profile features.
"""

try:
    from .users_enhanced import router as users_enhanced_router
except ImportError:
    users_enhanced_router = None

__all__ = [
    "users_enhanced_router"
]
