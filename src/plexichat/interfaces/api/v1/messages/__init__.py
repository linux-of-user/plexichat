# pyright: reportArgumentType=false
# pyright: reportCallIssue=false
# pyright: reportAttributeAccessIssue=false
# pyright: reportAssignmentType=false
# pyright: reportReturnType=false
from typing import Optional
    from .enhanced_messaging import router as enhanced_messaging_router
    from .messages_enhanced import router as messages_enhanced_router


"""
PlexiChat API v1 - Messages Module

Enhanced messaging, real-time communication, and collaboration features.
"""

try:
except ImportError: Optional[messages_enhanced_router] = None

try:
except ImportError: Optional[enhanced_messaging_router] = None

__all__ = [
    "messages_enhanced_router",
    "enhanced_messaging_router"
]
