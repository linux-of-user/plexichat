"""
PlexiChat AI Features - MODERN ARCHITECTURE

Comprehensive AI system with provider abstraction, featuring:
- Multi-provider AI integration (OpenAI, Anthropic, Ollama, etc.)
- AI-powered features (summarization, content suggestions, sentiment analysis)
- Content moderation and safety systems
- Real-time monitoring and analytics
- Provider management and failover
- API endpoints for AI features

Uses shared components for consistent error handling and type definitions.
"""

# Import shared components (NEW ARCHITECTURE) - with fallbacks
try:
    from ...shared.models import User, Event, Priority, Status  # type: ignore
    from ...shared.types import UserId, JSON, ConfigDict  # type: ignore
    from ...shared.exceptions import ValidationError, SecurityError, RateLimitError  # type: ignore
except ImportError:
    # Fallback types for standalone usage
    from typing import Any, Dict
    User = Any
    Event = Any
    Priority = str
    Status = str
    UserId = str
    JSON = Dict[str, Any]
    ConfigDict = Dict[str, Any]

    class ValidationError(Exception):
        pass

    class SecurityError(Exception):
        pass

    class RateLimitError(Exception):
        pass

# Import AI components

from .ai_coordinator import AICoordinator
from .core.ai_abstraction_layer import (
    AIAbstractionLayer,
    AIAccessControl,
    AIModel,
    AIProvider,
    AIRequest,
    AIResponse,
    ModelCapability,
    ModelStatus,
)

# AI features and services
from plexichat.core.unified_config import get_config

__version__ = get_config("system.version", "0.0.0")
__all__ = [
    # Core AI components
    "AIAbstractionLayer",
    "AIRequest",
    "AIResponse",
    "AIModel",
    "AIProvider",
    "ModelCapability",
    "ModelStatus",
    "AIAccessControl",
    "AICoordinator",

    # Shared components re-exports
    "User",
    "Event",
    "Priority",
    "Status",
    "UserId",
    "JSON",
    "ConfigDict",
    "ValidationError",
    "SecurityError",
    "RateLimitError",
]

# AI system capabilities
AI_FEATURES = {
    "multi_provider_support": True,
    "content_moderation": True,
    "sentiment_analysis": True,
    "text_summarization": True,
    "content_suggestions": True,
    "semantic_search": True,
    "real_time_monitoring": True,
    "provider_failover": True,
    "api_integration": True,
    "web_ui_management": True
}
