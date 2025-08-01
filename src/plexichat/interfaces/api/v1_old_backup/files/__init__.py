# pyright: reportMissingImports=false
# pyright: reportGeneralTypeIssues=false
# pyright: reportPossiblyUnboundVariable=false
# pyright: reportArgumentType=false
# pyright: reportCallIssue=false
# pyright: reportAttributeAccessIssue=false
# pyright: reportAssignmentType=false
# pyright: reportReturnType=false
"""
PlexiChat API v1 - Files Module

Enhanced file management, sharing, and collaboration features.
"""

from typing import Optional

try:
    from .files_enhanced import router as files_enhanced_router  # type: ignore
except ImportError:
    files_enhanced_router = None

__all__ = [
    "files_enhanced_router"
]
