    from .enhanced_messaging import router as enhanced_messaging_router
    from .messages_enhanced import router as messages_enhanced_router

"""
PlexiChat API v1 - Messages Module

Enhanced messaging, real-time communication, and collaboration features.
"""

try:
except ImportError:
    messages_enhanced_router = None

try:
except ImportError:
    enhanced_messaging_router = None

__all__ = [
    "messages_enhanced_router",
    "enhanced_messaging_router"
]
