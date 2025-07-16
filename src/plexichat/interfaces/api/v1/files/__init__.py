# pyright: reportArgumentType=false
# pyright: reportCallIssue=false
# pyright: reportAttributeAccessIssue=false
# pyright: reportAssignmentType=false
# pyright: reportReturnType=false
from typing import Optional
    from .files_enhanced import router as files_enhanced_router



"""
PlexiChat API v1 - Files Module

Enhanced file management, sharing, and collaboration features.
"""

try:
except ImportError: Optional[files_enhanced_router] = None

__all__ = [
    "files_enhanced_router"
]
