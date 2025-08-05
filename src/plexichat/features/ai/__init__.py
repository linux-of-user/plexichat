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

# Import shared components (NEW ARCHITECTURE)
from ...shared.models import User, Event, Priority, Status
from ...shared.types import UserId, JSON, ConfigDict
from ...shared.exceptions import ValidationError, SecurityError, RateLimitError
# Constants not available in shared.constants

# Import AI components

from .ai_coordinator_simple import AICoordinator
from .core.ai_abstraction_layer_simple import (
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
__version__ = "3.0.0"
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
